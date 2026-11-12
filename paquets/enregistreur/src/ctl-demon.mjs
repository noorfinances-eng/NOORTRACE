// `noortrace-ctl reload` (EX-15.5), `noortrace-ctl clock --accept`
// (EX-7.13) et `noortrace-ctl cle rotation-urgence` (CT-8 EX-10.14, CT-2
// EX-11.16) : commandes d'exploitation adressées au démon en marche.
//
//   noortrace-ctl reload [--configuration <fichier>] [--delai-ms <n>]
//   noortrace-ctl clock --accept [--configuration <fichier>] [--delai-ms <n>]
//   noortrace-ctl ancrage etat|metriques|retirer-qualification <id> [--configuration <fichier>] [--delai-ms <n>]
//   noortrace-ctl dossier exporter (--seq <n> | --dernier | --ticket <ticket_id>) --vers <répertoire>
//                                  [--configuration <fichier>] [--delai-ms <n>]
//
// `dossier exporter` (CT-2 révision 0.8, EX-15.9, EX-15.10) : domaines des
// options vérifiés avant tout (code 2), demande `dossier` avec son
// `request_id`, réponse reconnue à ce `request_id` dans le journal
// d'exploitation (rotation comprise), délai unique de toute la commande
// (120 000 ms par défaut) ; codes 0 `dossier_exported`, 1
// `dossier_export_refused` (message d'EX-15.12 sur la sortie d'erreur) ou,
// révision 0.9, `ctl_request_failed` de son `request_id` (EX-15.15), 2
// usage, configuration illisible ou démon ambigu, 4 aucun démon, fichier de
// demande occupé, signal impossible ou pas de réponse dans le délai.
//
// Toute demande (`cle rotation-urgence`, `ancrage`, `dossier`) est écrite
// par création exclusive (`O_CREAT | O_EXCL`, 0600) : un fichier déjà présent
// est une autre demande qui attend d'être lue ; la commande attend sa
// disparition dans son délai, puis rend le code 4. Si le signal ne part pas,
// la demande est retirée si elle est encore la sienne.
//
// `ancrage` (lot F2, CT-5 EX-5.9, EX-8.15) emploie le même canal que `cle
// rotation-urgence` : une demande écrite à côté du journal d'exploitation
// (`{ demande: "ancrage", commande, id }`) et le signal SIGURG ; le démon
// répond au journal (`anchoring_state`, `anchoring_metrics`,
// `provider_qualification_withdrawn`, `anchoring_ctl_refused`) ; révision 0.9
// de CT-2 (EX-15.15) : la demande porte un `request_id`, et une ligne
// `ctl_request_failed` de ce `request_id` arrête la commande aussitôt (code 1) ; pour
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
// le démon, ou demande en échec (`ctl_request_failed`) ; 2 usage ; 4 aucun démon, ou pas de réponse dans le délai.

import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { ecrireHorodatage } from "@noortrace/noyau";
import {
  normaliserVers, texteSeqValide, texteDelaiValide, ticketValide, DELAI_DOSSIER_DEFAUT_MS,
} from "./demandes-demon.mjs";

export const USAGE_CTL_DEMON = [
  "usage : noortrace-ctl reload [--configuration <fichier>] [--delai-ms <n>]",
  "        noortrace-ctl clock --accept [--configuration <fichier>] [--delai-ms <n>]",
  "        noortrace-ctl ancrage etat|metriques|retirer-qualification <id> [--configuration <fichier>] [--delai-ms <n>]",
  "        noortrace-ctl cle rotation-urgence [--configuration <fichier>] [--delai-ms <n>]",
  "        noortrace-ctl dossier exporter (--seq <n> | --dernier | --ticket <ticket_id>) --vers <répertoire> [--configuration <fichier>] [--delai-ms <n>]",
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
  if (action === "dossier") return principalDossier(argv.slice(1), { stdout, stderr, racineProc: io.racineProc, cwd: io.cwd });
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
  const debut = Date.now();
  for (const d of suivis) {
    if (spec.demande) {
      const fichier = fichierDemandeRotation(d.journal);
      let ecrit = null;
      // Révision 0.9 (EX-15.15) : `request_id` dans la demande, repris par `ctl_request_failed`.
      d.requestId = randomBytes(16).toString("hex");
      const r = await deposerDemande(fichier, () => {
        const demande = ancrage
          ? { demande: "ancrage", commande: ancrage.commande, id: ancrage.id, request_id: d.requestId, pid: process.pid, at: ecrireHorodatage(Date.now()) }
          : { demande: "rotation-urgence", request_id: d.requestId, pid: process.pid, at: ecrireHorodatage(Date.now()) };
        ecrit = `${JSON.stringify(demande)}\n`;
        return ecrit;
      }, debut + delai);
      if (r.occupe) {
        stderr.write(`noortrace-ctl : ${messageOccupe(fichier)}\n`);
        d.reponse = { event: "injoignable" };
        continue;
      }
      if (r.erreur) {
        stderr.write(`noortrace-ctl : fichier de demande impossible à écrire : ${fichier} (${r.erreur.code ?? r.erreur.message})\n`);
        d.reponse = { event: "injoignable" };
        continue;
      }
      try {
        process.kill(d.pid, spec.signal);
      } catch {
        retirerSiSienne(fichier, (texte) => texte === ecrit);
        d.reponse = { event: "injoignable" };
      }
      continue;
    }
    try {
      process.kill(d.pid, spec.signal);
    } catch {
      d.reponse = { event: "injoignable" };
    }
  }
  const fin = (spec.demande ? debut : Date.now()) + delai;
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
      // Erreur imprévue du démon pendant cette demande (EX-15.15) : reconnue à son request_id, sans attendre le délai.
      const echec = d.requestId ? lignesApres(d.journal, d.depuis).find((l) => l.event === "ctl_request_failed" && l.request_id === d.requestId) : null;
      if (echec) {
        d.reponse = echec;
        continue;
      }
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
    else if (d.reponse.event === "ctl_request_failed") {
      stderr.write(`noortrace-ctl : ${messageEchecDemande(d.reponse.data)}\n`);
      code = Math.max(code, 1);
    } else if (d.reponse.event === spec.refus) code = Math.max(code, 1);
    else if (ancrage?.commande === "metriques") {
      // Les séries d'EX-8.15 sont lues sur `/metrics` de la supervision du démon (CT-2 §17.2), quand elle les sert.
      const texte = await lireMetriquesAncrage(d.configuration).catch(() => null);
      if (texte !== null) stdout.write(texte);
    }
  }
  return code;
}

/**
 * Message d'une ligne `ctl_request_failed` (EX-15.15, révision 0.9) : la
 * demande n'a pas abouti, sur une erreur imprévue du démon.
 * @param {{detail?: unknown}|null|undefined} data
 */
export function messageEchecDemande(data) {
  const detail = typeof data?.detail === "string" ? data.detail : "erreur_interne";
  return `erreur imprévue du démon (${detail}) ; la demande n'a pas abouti : lire ctl_request_failed au journal d'exploitation`;
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

// ------------------------------------------------------------------ demandes par fichier (EX-15.10, pas 3 et 4)

const attendreMs = (ms) => new Promise((r) => setTimeout(r, Math.max(0, ms)));

/** Message du fichier de demande occupé (EX-15.10, pas 3). */
function messageOccupe(fichier) {
  return `fichier de demande occupé : ${fichier} ; une autre commande est en cours, ou une demande n'a pas été lue (à supprimer si aucune commande noortrace-ctl ne tourne)`;
}

/**
 * Écrit la demande par création exclusive (`O_CREAT | O_EXCL`, sans suivre
 * de lien, mode 0600 posé explicitement) ; un fichier présent est une autre
 * demande : attente de sa disparition jusqu'à `fin`. `contenu` est appelé à
 * chaque essai (`at` est l'instant de l'écriture).
 * @returns {Promise<{ok: true} | {occupe: true} | {erreur: Error}>}
 */
async function deposerDemande(fichier, contenu, fin) {
  const drapeaux = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW;
  for (;;) {
    let fd;
    try {
      fd = fs.openSync(fichier, drapeaux, 0o600);
    } catch (e) {
      if (e?.code !== "EEXIST") return { erreur: e };
      if (Date.now() >= fin) return { occupe: true };
      await attendreMs(Math.min(50, fin - Date.now()));
      continue;
    }
    try {
      fs.fchmodSync(fd, 0o600);
      const octets = Buffer.from(contenu(), "utf8");
      let n = 0;
      while (n < octets.length) n += fs.writeSync(fd, octets, n, octets.length - n);
    } catch (e) {
      fs.closeSync(fd);
      fd = null;
      try {
        fs.unlinkSync(fichier);
      } catch {
        // déjà retiré
      }
      return { erreur: e };
    } finally {
      if (fd !== null) fs.closeSync(fd);
    }
    return { ok: true };
  }
}

/** Retire le fichier de demande s'il porte encore la demande de cette commande (EX-15.10, pas 4). */
function retirerSiSienne(fichier, estSienne) {
  try {
    const texte = fs.readFileSync(fichier, "utf8");
    if (estSienne(texte)) fs.unlinkSync(fichier);
  } catch {
    // lu et supprimé par le démon entre-temps, ou illisible : rien à retirer
  }
}

// ------------------------------------------------------------------ journal d'exploitation suivi (rotation comprise)

/**
 * Suit le journal d'exploitation depuis la taille notée (EX-15.10, pas 2 et
 * 6) : les lignes complètes écrites après, dans le fichier noté (par son
 * numéro d'inode, qu'il ait été tourné en `<chemin>.<k>` ou non) et dans les
 * fichiers créés depuis ; les fichiers tournés déjà présents à la note sont
 * ignorés (EX-17.4).
 */
export class SuiviJournal {
  constructor(chemin) {
    this.chemin = chemin;
    const st = statOuNull(chemin);
    this.ino = st?.ino ?? null;
    this.taille = st?.size ?? 0;
    this.anciens = new Set(this.#tournes().map((c) => statOuNull(c)?.ino).filter((x) => x !== undefined && x !== this.ino));
    /** @type {Map<number, number>} inode → octets déjà lus */
    this.positions = new Map();
  }

  #tournes() {
    const liste = [];
    for (let k = 1; k <= 10000; k++) {
      const c = `${this.chemin}.${k}`;
      if (!fs.existsSync(c)) break;
      liste.push(c);
    }
    return liste;
  }

  /** Lignes nouvelles (objets JSON), du fichier le plus ancien au plus récent. */
  lire() {
    const lignes = [];
    for (const c of [...this.#tournes().reverse(), this.chemin]) {
      let fd;
      try {
        fd = fs.openSync(c, "r");
      } catch {
        continue;
      }
      try {
        const st = fs.fstatSync(fd);
        if (this.anciens.has(st.ino)) continue;
        const depuis = this.positions.get(st.ino) ?? (st.ino === this.ino ? this.taille : 0);
        if (st.size <= depuis) continue;
        const tampon = Buffer.alloc(st.size - depuis);
        let n = 0;
        while (n < tampon.length) {
          const k = fs.readSync(fd, tampon, n, tampon.length - n, depuis + n);
          if (k === 0) break;
          n += k;
        }
        const fin = tampon.subarray(0, n).lastIndexOf(0x0a);
        if (fin < 0) continue;
        this.positions.set(st.ino, depuis + fin + 1);
        for (const l of tampon.subarray(0, fin).toString("utf8").split("\n")) {
          if (!l) continue;
          try {
            lignes.push(JSON.parse(l));
          } catch {
            // ligne illisible : ignorée
          }
        }
      } finally {
        fs.closeSync(fd);
      }
    }
    return lignes;
  }
}

function statOuNull(c) {
  try {
    return fs.statSync(c);
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ noortrace-ctl dossier exporter

const PREFIXE_DOSSIER = "noortrace-ctl dossier exporter : ";

/** `<début>` des messages d'EX-15.12 : `period_start` en RFC 3339, à la seconde (`2026-11-05T09:00:00Z`). */
function debutRfc3339(periodStart) {
  return Number.isSafeInteger(periodStart) ? new Date(periodStart * 1000).toISOString().replace(/\.[0-9]{3}Z$/, "Z") : String(periodStart);
}

/**
 * Message de la table d'EX-15.12 pour une ligne `dossier_export_refused`,
 * construit depuis son `data`.
 * @param {object} data
 * @returns {string}
 */
export function messageRefusExport(data) {
  const d = data ?? {};
  switch (d.raison) {
    case "demande_invalide": return `demande invalide : ${d.member}`;
    case "demande_perimee": return `demande périmée, écrite à ${d.at} : lue plus de 600 s après, ou avant le démarrage du démon ; rien n'est exporté`;
    case "bail_non_detenu": return "le démon ne détient pas le bail (instance passive) : exporter depuis l'instance active";
    case "exports_indisponible": return `répertoire des exports indisponible : ${d.exports_dir}`;
    case "destination_hors_exports": return `la destination ${d.destination} n'est pas sous le répertoire des exports ${d.exports_dir}`;
    case "parent_absent": return `le répertoire parent de ${d.destination} n'existe pas`;
    case "destination_existante": return `la destination ${d.destination} existe et n'est pas un répertoire`;
    case "destination_non_vide": return `la destination ${d.destination} n'est pas vide : un dossier exporté n'est jamais remplacé`;
    case "evenement_inconnu": return `aucun événement de numéro ${d.seq} dans le journal`;
    case "aucune_periode_close": return "aucune période close dans le journal";
    case "ticket_inconnu": return `aucun événement du journal ne porte le ticket ${d.ticket}`;
    case "ticket_non_decide": return `le ticket ${d.ticket} n'est pas décidé`;
    case "ticket_sans_appel_execute": return `le ticket ${d.ticket} est décidé (${d.decision}) sans appel exécuté ; le dossier de la décision s'exporte par --seq`;
    case "periode_non_close": return `la période ${debutRfc3339(d.period_start)} de l'événement ${d.seq} n'est pas close`;
    case "approbations_introuvables": return `jeu d'approbateurs introuvable pour le ticket ${d.ticket} : aucun dossier écrit`;
    case "lecture_impossible": return `lecture du journal impossible : ${d.detail}`;
    case "ecriture_impossible":
      // révision 0.9 (EX-15.12, EX-15.13 point 2) : synchronisation du parent en échec après le renommage
      if (typeof d.detail === "string" && d.detail.startsWith("synchronisation_parent")) {
        return `écriture impossible : ${d.detail} ; le dossier est en place sous ${d.destination}, mais sa durabilité n'est pas assurée : l'exporter de nouveau vers une autre destination`;
      }
      return `écriture impossible : ${d.detail} ; la destination est inchangée`;
    default: return `refus ${String(d.raison)}`;
  }
}

/**
 * Lit la ligne de commande de `dossier exporter` (EX-15.9) : rend les options
 * ou un message d'usage. Chaque option est suivie de sa valeur comme argument
 * distinct ; `--option=valeur` n'est pas admise.
 * @param {string[]} argv arguments après `dossier`
 * @param {string} cwd
 */
export function lireOptionsDossier(argv, cwd) {
  if (argv[0] !== "exporter") return { erreur: "commande attendue : dossier exporter" };
  const o = {};
  const AVEC_VALEUR = ["--seq", "--ticket", "--vers", "--configuration", "--delai-ms"];
  for (let k = 1; k < argv.length; k++) {
    const a = argv[k];
    if (a === "--dernier") {
      if ("dernier" in o) return { erreur: "--dernier donné plus d'une fois" };
      o.dernier = true;
      continue;
    }
    if (!AVEC_VALEUR.includes(a)) return { erreur: `argument inattendu : ${a} (chaque option est suivie de sa valeur comme argument distinct)` };
    const nom = a.slice(2);
    if (nom in o) return { erreur: `${a} donné plus d'une fois` };
    if (k + 1 >= argv.length) return { erreur: `${a} : valeur attendue` };
    o[nom] = argv[++k];
  }
  const designations = ["seq", "dernier", "ticket"].filter((x) => x in o);
  if (designations.length !== 1) return { erreur: "exactement une désignation attendue : --seq, --dernier ou --ticket" };
  if (!("vers" in o)) return { erreur: "--vers attendu" };
  if ("seq" in o && !texteSeqValide(o.seq)) return { erreur: "--seq : entier décimal de 1 à 2^53 − 1, sans signe ni zéro de tête" };
  if ("ticket" in o && !ticketValide(o.ticket)) return { erreur: "--ticket : identifiant de ticket de 5 à 128 caractères, motif ^apr-[0-9a-z]+(-[0-9a-z]+)*$" };
  if ("delai-ms" in o && !texteDelaiValide(o["delai-ms"])) return { erreur: "--delai-ms : entier décimal de 0 à 86 400 000, sans signe ni zéro de tête" };
  if ("configuration" in o && o.configuration === "") return { erreur: "--configuration : fichier attendu" };
  const destination = normaliserVers(o.vers, cwd);
  if (destination === null) return { erreur: "--vers : chemin non vide, sans octet nul, dont le dernier composant n'est ni . ni .., de 4 096 octets au plus une fois rendu absolu, composants de 1 à 255 octets, aucun composant au nom réservé .noortrace-partiel-…" };
  return {
    selection: designations[0],
    seq: "seq" in o ? Number(o.seq) : null,
    ticket: "ticket" in o ? o.ticket : null,
    destination,
    configuration: o.configuration ?? null,
    delai: "delai-ms" in o ? Number(o["delai-ms"]) : DELAI_DOSSIER_DEFAUT_MS,
  };
}

/**
 * `noortrace-ctl dossier exporter` (EX-15.9, EX-15.10).
 * @param {string[]} argv arguments après `dossier`
 * @param {{stdout: NodeJS.WritableStream, stderr: NodeJS.WritableStream, racineProc?: string, cwd?: string}} io
 * @returns {Promise<number>}
 */
async function principalDossier(argv, io) {
  const { stdout, stderr } = io;
  const o = lireOptionsDossier(argv, io.cwd ?? process.cwd());
  if (o.erreur) {
    stderr.write(`${PREFIXE_DOSSIER}${o.erreur}\n${USAGE_CTL_DEMON}\n`);
    return 2;
  }
  // Pas 1 : démon visé.
  let demons;
  try {
    demons = trouverDemons({ configuration: o.configuration, racineProc: io.racineProc });
  } catch {
    stderr.write(`${PREFIXE_DOSSIER}--configuration : fichier illisible\n`);
    return 2;
  }
  if (!demons.length) {
    stderr.write(`${PREFIXE_DOSSIER}aucun démon noortrace de cet utilisateur pour cette configuration\n`);
    return 4;
  }
  if (demons.length > 1) {
    stderr.write(`${PREFIXE_DOSSIER}plusieurs démons ; désigner la configuration (--configuration)\n`);
    return 2;
  }
  const d = demons[0];
  // Pas 2 : journal de réponse, taille notée.
  let journal = null;
  try {
    journal = JSON.parse(fs.readFileSync(d.configuration, "utf8")).supervision.ops_log.path;
  } catch {
    journal = null;
  }
  if (typeof journal !== "string" || !journal) {
    stderr.write(`${PREFIXE_DOSSIER}configuration du démon ${d.pid} illisible\n`);
    return 2;
  }
  const suivi = new SuiviJournal(journal);
  const sortie = (ligne) => stdout.write(`${JSON.stringify({ pid: d.pid, configuration: d.configuration, event: ligne?.event ?? null, data: ligne?.data ?? null })}\n`);
  // Pas 3 : demande, par création exclusive ; le délai court depuis ici pour toute la commande.
  const fin = Date.now() + o.delai;
  const fichier = fichierDemandeRotation(journal);
  const request_id = randomBytes(16).toString("hex");
  const r = await deposerDemande(fichier, () => `${JSON.stringify({ demande: "dossier", selection: o.selection, seq: o.seq, ticket: o.ticket, destination: o.destination, request_id, pid: process.pid, at: ecrireHorodatage(Date.now()) })}\n`, fin);
  if (r.occupe) {
    sortie(null);
    stderr.write(`${PREFIXE_DOSSIER}${messageOccupe(fichier)}\n`);
    return 4;
  }
  if (r.erreur) {
    sortie(null);
    stderr.write(`${PREFIXE_DOSSIER}fichier de demande impossible à écrire : ${fichier} (${r.erreur.code ?? r.erreur.message})\n`);
    return 4;
  }
  // Pas 4 : signal ; s'il ne part pas, la demande est retirée si elle est encore la sienne.
  try {
    process.kill(d.pid, "SIGURG");
  } catch (e) {
    retirerSiSienne(fichier, (texte) => {
      try {
        return JSON.parse(texte).request_id === request_id;
      } catch {
        return false;
      }
    });
    sortie(null);
    stderr.write(`${PREFIXE_DOSSIER}signal impossible vers le démon ${d.pid} (${e?.code ?? e?.message}) ; demande retirée\n`);
    return 4;
  }
  // Pas 6 : première ligne de réponse qui porte ce request_id (révision 0.9 : `ctl_request_failed` compris, EX-15.15).
  for (;;) {
    const reponse = suivi.lire().find((l) => l.request_id === request_id && (l.event === "dossier_exported" || l.event === "dossier_export_refused" || l.event === "ctl_request_failed"));
    if (reponse) {
      sortie(reponse);
      if (reponse.event === "dossier_exported") return 0;
      if (reponse.event === "ctl_request_failed") {
        stderr.write(`${PREFIXE_DOSSIER}${messageEchecDemande(reponse.data)}\n`);
        return 1;
      }
      stderr.write(`${PREFIXE_DOSSIER}${messageRefusExport(reponse.data)}\n`);
      return 1;
    }
    if (Date.now() >= fin) break;
    await attendreMs(Math.min(50, fin - Date.now()));
  }
  sortie(null);
  stderr.write(`${PREFIXE_DOSSIER}pas de réponse dans le délai ; lire dossier_exported ou dossier_export_refused de request_id ${request_id} au journal d'exploitation\n`);
  return 4;
}
