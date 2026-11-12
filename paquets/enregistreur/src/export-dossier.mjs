// Export du dossier de preuve d'un événement à la demande de `noortrace-ctl
// dossier exporter` (CT-2 révision 0.8, §15.7 : EX-15.11 à EX-15.14 ; CT-7
// EX-3.16). Une demande `dossier` lue et admise par demandes-demon.mjs arrive
// ici ; `exporterDemande` applique les refus d'EX-15.12 dans leur ordre :
//
//    1 bail_non_detenu             6 destination_non_vide
//    2 exports_indisponible        7 evenement_inconnu, aucune_periode_close,
//    3 destination_hors_exports      ticket_inconnu, ticket_non_decide,
//    4 parent_absent                 ticket_sans_appel_execute
//    5 destination_existante       8 periode_non_close
//                                  9 approbations_introuvables
//                                 10 lecture_impossible
//                                 11 ecriture_impossible
//
// puis écrit le dossier de façon atomique (EX-15.13) : répertoire temporaire
// `.noortrace-partiel-<request_id>` en 0700 dans le parent de la destination,
// chemin réel du parent vérifié (et, en production, groupe du répertoire
// temporaire), fichiers écrits et synchronisés en 0640, répertoire passé en
// 0750 et synchronisé, chemin réel du parent revérifié, `rename(2)`,
// synchronisation du parent. Les écritures se font relativement aux
// descripteurs du parent et du répertoire temporaire (`/proc/self/fd/<n>`,
// Linux), en plus des deux vérifications : un parent remplacé entre-temps ne
// détourne aucune écriture. Elle rend la ligne de réponse (`dossier_exported`
// ou `dossier_export_refused`, EX-15.14), que l'appelant écrit quel que soit
// le niveau du journal d'exploitation.
//
// La lecture des segments (coût proportionnel au journal) s'exécute dans un
// fil de calcul (`Worker`), hors du fil des frontaux (EX-15.13 point 5,
// EX-3.6) ; le reste (une période, ses ancres) sur le fil du démon.
//
// `supprimerRestesExports` supprime, à l'acquisition du bail, les répertoires
// `.noortrace-partiel-<32 hex>` restés d'un export interrompu
// (`dossier_export_partial_removed`).

import fs from "node:fs";
import path from "node:path";
import { Worker, isMainThread, workerData, parentPort } from "node:worker_threads";
import { decoderHorodatage, sha256Hex } from "@noortrace/noyau";
import { listerSegments } from "./segments.mjs";
import { debutPeriode, nomsManifeste } from "./periodes.mjs";
import { assemblerBase, construireDossierNoyau, RAISON_JEU_INTROUVABLE } from "./dossier.mjs";
import { donneesRefusExport } from "./demandes-demon.mjs";
import { REPERTOIRE_EXPORTS_DEFAUT } from "./configuration.mjs";

/** Outil de la décision d'un ticket (CT-1 §6). */
const OUTIL_DECISION = "noortrace.approbation.decision";
/** Outil de l'événement de rotation de clé (CT-1 §8). */
const OUTIL_ROTATION = "noortrace.journal.rotation-cle";
/** Préfixe du répertoire temporaire d'un export (EX-15.13, point 2). */
export const PREFIXE_TEMPORAIRE = ".noortrace-partiel-";
/** Reste d'un export interrompu (EX-15.13, point 2) : 51 octets. */
export const MOTIF_RESTE = /^\.noortrace-partiel-[0-9a-f]{32}$/;
/** Longueur maximale de `detail` (EX-15.14). */
const DETAIL_MAX = 200;

/** Répertoire des exports tel que le démon l'a lu (EX-15.12) : `exports_dir`, ou son défaut. */
export function repertoireExports(config) {
  return config?.exports_dir ?? REPERTOIRE_EXPORTS_DEFAUT;
}

/**
 * Le chemin réel `reel` est-il `racine` ou un chemin sous elle ? C'est le
 * contrôle des chemins réels d'EX-15.12 (ordre 3) et d'EX-15.13 (point 2),
 * employé à chaque vérification du parent.
 * @param {string} reel
 * @param {string} racine
 * @returns {boolean}
 */
export function cheminReelSous(reel, racine) {
  return reel === racine || reel.startsWith(racine === "/" ? "/" : `${racine}/`);
}

/** Deux chemins réels égaux, ou l'un sous l'autre (ordre 2 d'EX-15.12, répertoire des exports et `storage.root`). */
function emboites(a, b) {
  const sous = (x, y) => x === y || x.startsWith(y === "/" ? "/" : `${y}/`);
  return sous(a, b) || sous(b, a);
}

/**
 * `detail` d'EX-15.14 : code d'erreur du système et fichier en cause, 200
 * caractères au plus ; sans code du système, le mot qui tient sa place
 * (révision 0.9) : `contenu_illisible` à la lecture (contenu qui n'est pas du
 * JSON), `erreur_interne` à l'écriture (erreur imprévue, EX-15.15).
 */
function detailErreur(e, fichier, sansCode = "contenu_illisible") {
  const code = typeof e?.code === "string" && e.code ? e.code : sansCode;
  return `${code} ${fichier ?? e?.path ?? ""}`.trim().slice(0, DETAIL_MAX);
}

/**
 * `detail` d'une erreur imprévue (EX-15.15) : `erreur_interne` suivi du nom de
 * l'erreur et de son code éventuel, jamais de son message, qui pourrait
 * porter une pièce ; 200 caractères au plus.
 * @param {unknown} e
 */
export function detailErreurInterne(e) {
  const nom = typeof e?.name === "string" && /^[A-Za-z0-9_]{1,64}$/.test(e.name) ? e.name : "Error";
  const code = typeof e?.code === "string" && /^[A-Za-z0-9_]{1,64}$/.test(e.code) ? ` ${e.code}` : "";
  return `erreur_interne ${nom}${code}`.slice(0, DETAIL_MAX);
}

class RefusExport extends Error {
  constructor(raison, x = {}) {
    super(raison);
    this.raison = raison;
    this.x = x;
  }
}

/** Le démon détient-il le bail et a-t-il relu le journal (ordre 1 d'EX-15.12, 13.4) ? */
function bailDetenu(coeur) {
  return coeur.bailDetenu === true && coeur.passif !== true && coeur.bail?.valide?.() !== false;
}

// ------------------------------------------------------------------ lecture du journal (fil de calcul)

/**
 * Lit les segments du journal et choisit l'événement exporté (EX-15.11) :
 * premier passage sur tous les segments (choix, décisions, clés), second
 * passage sur les seuls segments qui couvrent l'événement, ses voisins et sa
 * période. Les événements considérés sont les lignes complètes des segments,
 * jusqu'au dernier `seq` durable de l'écrivain (`borneSeq`).
 * @param {{repertoire: string, borneSeq: number|null, selection: string, seq: number|null, ticket: string|null}} p
 * @returns {Promise<{refus: {raison: string, seq?: number|null, period_start?: number, decision?: string, detail?: string}} | {lecture: object}>}
 */
export async function lireJournalPourExport(p) {
  const dirSegments = path.join(p.repertoire, "segments");
  const dirManifestes = path.join(p.repertoire, "manifestes");
  let segments;
  try {
    segments = await listerSegments(dirSegments);
  } catch (e) {
    return { refus: { raison: "lecture_impossible", detail: detailErreur(e, dirSegments) } };
  }
  // Périodes closes : manifeste et signature présents (EX-15.11).
  const closes = new Set();
  try {
    let noms = [];
    try {
      noms = fs.readdirSync(dirManifestes);
    } catch (e) {
      if (e.code !== "ENOENT") throw e;
    }
    const presents = new Set(noms);
    for (const n of noms) {
      const m = /^periode-([0-9]{10})\.json$/.exec(n);
      if (m && presents.has(`periode-${m[1]}.sig`)) closes.add(Number(m[1]));
    }
  } catch (e) {
    return { refus: { raison: "lecture_impossible", detail: detailErreur(e, dirManifestes) } };
  }
  const borne = Number.isSafeInteger(p.borneSeq) ? p.borneSeq : Infinity;

  /** Parcourt les événements complets d'une liste de segments ; `f` rend vrai pour arrêter. */
  const parcourir = (liste, f) => {
    for (const s of liste) {
      let texte;
      try {
        texte = fs.readFileSync(s.chemin, "utf8");
      } catch (e) {
        throw new RefusExport("lecture_impossible", { detail: detailErreur(e, s.chemin) });
      }
      const lignes = texte.split("\n");
      // La dernière ligne sans saut de ligne n'est pas complète (écriture en cours ou tronquée).
      lignes.pop();
      for (let k = 1; k < lignes.length; k++) {
        let e;
        try {
          e = JSON.parse(lignes[k]);
        } catch (err) {
          throw new RefusExport("lecture_impossible", { detail: detailErreur(err, s.chemin) });
        }
        if (!Number.isSafeInteger(e?.seq) || e.seq > borne) return true;
        if (f(e) === true) return true;
      }
    }
    return false;
  };

  let premier = null;
  const rotations = [];
  const decisions = new Map();
  let trouve = null;
  let dernierClos = null;
  let mentionne = false;
  let premierExecute = null;
  try {
    parcourir(segments, (e) => {
      if (premier === null) premier = e;
      const outil = e.execution?.tool;
      if (outil === OUTIL_ROTATION) rotations.push(e);
      if (outil === OUTIL_DECISION && typeof e.approval?.ticket === "string") {
        if (!decisions.has(e.approval.ticket)) decisions.set(e.approval.ticket, []);
        decisions.get(e.approval.ticket).push(e);
      }
      if (p.selection === "seq" && e.seq === p.seq) trouve = e.seq;
      if (p.selection === "dernier") {
        const t = decoderHorodatage(e.ts);
        if (t !== null && closes.has(debutPeriode(t))) dernierClos = e.seq;
      }
      if (p.selection === "ticket") {
        if (e.policy?.ticket === p.ticket || e.approval?.ticket === p.ticket) mentionne = true;
        if (
          premierExecute === null &&
          e.execution?.status === "executee" &&
          outil !== OUTIL_DECISION &&
          e.approval !== null && typeof e.approval === "object" &&
          e.approval.ticket === p.ticket &&
          e.approval.decision === "approuve"
        ) premierExecute = e.seq;
      }
      return false;
    });
  } catch (e) {
    if (e instanceof RefusExport) return { refus: { raison: e.raison, ...e.x } };
    throw e;
  }

  // Ordre 7 : événement désigné.
  let seq;
  if (p.selection === "seq") {
    if (trouve === null) return { refus: { raison: "evenement_inconnu" } };
    seq = trouve;
  } else if (p.selection === "dernier") {
    if (dernierClos === null) return { refus: { raison: "aucune_periode_close" } };
    seq = dernierClos;
  } else {
    if (!mentionne) return { refus: { raison: "ticket_inconnu" } };
    const d = decisions.get(p.ticket) ?? [];
    if (!d.length) return { refus: { raison: "ticket_non_decide" } };
    if (premierExecute === null) return { refus: { raison: "ticket_sans_appel_execute", decision: d[0].approval.decision } };
    seq = premierExecute;
  }

  // Second passage : l'événement, ses voisins, puis (période close) les hash de sa période.
  const couvrant = (de, a) => segments.filter((s, k) => s.first_seq <= a && (k + 1 >= segments.length || segments[k + 1].first_seq > de));
  const objets = new Map();
  try {
    parcourir(couvrant(seq - 1, seq + 1), (e) => {
      if (e.seq >= seq - 1 && e.seq <= seq + 1) objets.set(e.seq, e);
      return e.seq > seq + 1;
    });
  } catch (e) {
    if (e instanceof RefusExport) return { refus: { raison: e.raison, seq, ...e.x } };
    throw e;
  }
  const evenement = objets.get(seq);
  if (!evenement) return { refus: { raison: "lecture_impossible", seq, detail: `contenu_illisible ${dirSegments}`.slice(0, DETAIL_MAX) } };
  const periodStart = debutPeriode(decoderHorodatage(evenement.ts));
  // Ordre 8 : période close.
  if (!closes.has(periodStart)) return { refus: { raison: "periode_non_close", seq, period_start: periodStart } };
  const noms = nomsManifeste(periodStart);
  let manifeste;
  try {
    const octetsManifeste = new Uint8Array(fs.readFileSync(path.join(dirManifestes, noms.manifeste)));
    const octetsSignature = new Uint8Array(fs.readFileSync(path.join(dirManifestes, noms.signature)));
    let m;
    let sig;
    try {
      m = JSON.parse(Buffer.from(octetsManifeste).toString("utf8"));
      sig = JSON.parse(Buffer.from(octetsSignature).toString("utf8"));
    } catch (e) {
      throw Object.assign(e, { path: path.join(dirManifestes, noms.manifeste) });
    }
    if (!Number.isSafeInteger(m?.first_seq) || !Number.isSafeInteger(m?.last_seq)) throw Object.assign(new Error("manifeste"), { path: path.join(dirManifestes, noms.manifeste) });
    manifeste = { manifeste: m, signature: sig, octetsManifeste, octetsSignature };
  } catch (e) {
    return { refus: { raison: "lecture_impossible", seq, detail: detailErreur(e, e?.path) } };
  }
  const { first_seq: debut, last_seq: fin } = manifeste.manifeste;
  const hashes = [];
  try {
    if (fin >= debut) {
      parcourir(couvrant(debut, fin), (e) => {
        if (e.seq >= debut && e.seq <= fin) hashes.push(e.hash);
        return e.seq > fin;
      });
    }
  } catch (e) {
    if (e instanceof RefusExport) return { refus: { raison: e.raison, seq, ...e.x } };
    throw e;
  }
  if (hashes.length !== Math.max(0, fin - debut + 1)) return { refus: { raison: "lecture_impossible", seq, detail: `contenu_illisible ${dirSegments}`.slice(0, DETAIL_MAX) } };
  const ticketEvenement = evenement.approval?.ticket ?? null;
  return {
    lecture: {
      evenement,
      precedent: objets.get(seq - 1) ?? null,
      suivant: objets.get(seq + 1) ?? null,
      pourCles: premier === null ? [] : [premier, ...rotations.filter((r) => r.seq !== premier.seq)],
      decisions: ticketEvenement === null ? [] : decisions.get(ticketEvenement) ?? [],
      hashesPeriode: hashes,
      manifeste,
      periodStart,
    },
  };
}

/** Lit le journal dans un fil de calcul (EX-15.13 point 5) ; une panne du fil est une lecture impossible. */
function lireDansUnFil(p) {
  return new Promise((resoudre) => {
    let fini = false;
    const finir = (r) => {
      if (fini) return;
      fini = true;
      resoudre(r);
    };
    let w;
    try {
      w = new Worker(new URL(import.meta.url), { workerData: { lectureExportNoortrace: p } });
    } catch (e) {
      finir({ refus: { raison: "lecture_impossible", detail: detailErreur(e, "fil de lecture") } });
      return;
    }
    w.once("message", (m) => finir(m));
    w.once("error", (e) => finir({ refus: { raison: "lecture_impossible", detail: detailErreur(e, "fil de lecture") } }));
    w.once("exit", (code) => finir({ refus: { raison: "lecture_impossible", detail: `fil de lecture arrêté (${code})` } }));
  });
}

// ------------------------------------------------------------------ écriture atomique

/** Chemin d'un nom relatif au répertoire d'un descripteur (Linux) : les écritures suivent le répertoire tenu, pas un chemin. */
function sousDescripteur(fd, nom) {
  return nom === undefined ? `/proc/self/fd/${fd}` : `/proc/self/fd/${fd}/${nom}`;
}

/** Chemin réel courant du répertoire tenu par un descripteur. */
function cheminDuDescripteur(fd) {
  return fs.readlinkSync(sousDescripteur(fd));
}

/** Supprime le répertoire temporaire là où il se trouve maintenant (il a pu être déplacé avec son parent). */
function supprimerTemporaire(fdTemp, nomTemp, cheminInitial) {
  let chemin = cheminInitial;
  try {
    if (fdTemp !== null) {
      const courant = cheminDuDescripteur(fdTemp);
      if (path.basename(courant) === nomTemp) chemin = courant;
    }
  } catch {
    // descripteur illisible : le chemin initial
  }
  try {
    const st = fs.lstatSync(chemin);
    if (st.isDirectory() && path.basename(chemin) === nomTemp) fs.rmSync(chemin, { recursive: true, force: true });
  } catch {
    // déjà supprimé
  }
}

/**
 * Supprime, après une erreur imprévue sortie de `exporterDemande` (EX-15.15),
 * le répertoire temporaire `.noortrace-partiel-<request_id>` du parent de la
 * destination s'il existe : examiné sans suivre de lien, et seulement si le
 * chemin réel du parent est sous le répertoire des exports.
 * @param {object} config configuration du démon
 * @param {{destination?: unknown, request_id?: unknown}} demande
 */
export function supprimerTemporaireDeDemande(config, demande) {
  if (typeof demande?.destination !== "string" || typeof demande?.request_id !== "string" || !/^[0-9a-f]{32}$/.test(demande.request_id)) return;
  try {
    const exportsReel = fs.realpathSync(repertoireExports(config));
    const parentReel = fs.realpathSync(path.posix.dirname(demande.destination));
    if (!cheminReelSous(parentReel, exportsReel)) return;
    supprimerTemporaire(null, `${PREFIXE_TEMPORAIRE}${demande.request_id}`, path.join(parentReel, `${PREFIXE_TEMPORAIRE}${demande.request_id}`));
  } catch {
    // parent absent ou illisible : rien à supprimer
  }
}

/** Écrit un fichier neuf du répertoire temporaire, en 0640 posé explicitement, synchronisé. */
function ecrireFichier(fdTemp, nom, octets) {
  const fd = fs.openSync(sousDescripteur(fdTemp, nom), fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o640);
  try {
    fs.fchmodSync(fd, 0o640);
    let n = 0;
    while (n < octets.length) n += fs.writeSync(fd, octets, n, octets.length - n);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

// ------------------------------------------------------------------ export

/**
 * Exécute une demande `dossier` admise (EX-15.11 à EX-15.14). Ne lève pas :
 * toute erreur imprévue avant le renommage rend `ecriture_impossible` et ne
 * laisse aucun dossier partiel sous le nom demandé.
 * @param {import("./coeur.mjs").Coeur} coeur
 * @param {{selection: string, seq: number|null, ticket: string|null, destination: string, request_id: string, pid: number, at: string}} demande
 * @returns {Promise<{event: "dossier_exported"|"dossier_export_refused", component: "ancrage"|"noyau", seq: number|null, request_id: string, data: object}>}
 */
export async function exporterDemande(coeur, demande) {
  const exports_dir = repertoireExports(coeur.config);
  const production = coeur.config?.recorder?.environment === "production";
  let retenu = null;
  const refus = (raison, x = {}) => ({
    event: "dossier_export_refused",
    component: "noyau",
    seq: x.seq ?? retenu,
    request_id: demande.request_id,
    data: donneesRefusExport(raison, demande, {
      exports_dir,
      ...(x.seq !== undefined && x.seq !== null ? { seq: x.seq } : retenu !== null ? { seq: retenu } : {}),
      period_start: x.period_start ?? null,
      decision: x.decision ?? null,
      detail: x.detail ?? null,
    }),
  });

  // Ordre 1 : bail détenu, journal relu.
  if (!bailDetenu(coeur)) return refus("bail_non_detenu");

  // Ordre 2 : répertoire des exports.
  let exportsReel;
  let gidExports;
  try {
    exportsReel = fs.realpathSync(exports_dir);
    const st = fs.statSync(exportsReel);
    if (!st.isDirectory()) return refus("exports_indisponible");
    let racine;
    try {
      racine = fs.realpathSync(coeur.config.storage.root);
    } catch {
      racine = path.resolve(coeur.config.storage.root);
    }
    if (emboites(exportsReel, racine)) return refus("exports_indisponible");
    if (production) {
      const euid = typeof process.geteuid === "function" ? process.geteuid() : null;
      if (st.uid !== euid || (st.mode & 0o007) !== 0 || (st.mode & 0o020) !== 0 || (st.mode & 0o2000) === 0) return refus("exports_indisponible", { detail: "droits" });
    }
    gidExports = st.gid;
  } catch {
    return refus("exports_indisponible");
  }

  // Ordre 3 : destination sous le répertoire des exports, lexicalement puis par le chemin réel du parent.
  const destination = demande.destination;
  if (!destination.startsWith(exports_dir === "/" ? "/" : `${exports_dir}/`)) return refus("destination_hors_exports");
  const parent = path.posix.dirname(destination);
  const nomDestination = path.posix.basename(destination);
  let parentReel = null;
  try {
    parentReel = fs.realpathSync(parent);
  } catch {
    parentReel = null;
  }
  if (parentReel !== null && !cheminReelSous(parentReel, exportsReel)) return refus("destination_hors_exports");
  // Ordre 4 : parent présent, répertoire.
  try {
    if (parentReel === null || !fs.statSync(parentReel).isDirectory()) return refus("parent_absent");
  } catch {
    return refus("parent_absent");
  }
  // Ordres 5 et 6 : destination absente, ou répertoire vide (examinée sans suivre de lien).
  const cibleReelle = path.join(parentReel, nomDestination);
  let erreurDestination = null;
  try {
    const st = fs.lstatSync(cibleReelle);
    if (!st.isDirectory()) return refus("destination_existante");
    if (fs.readdirSync(cibleReelle).length > 0) return refus("destination_non_vide");
  } catch (e) {
    if (e?.code !== "ENOENT") erreurDestination = detailErreur(e, destination);
  }

  // Ordres 7 et 8 : événement désigné (fil de calcul), période close.
  const generated_at = coeur.horlogeBrute.murale();
  const lu = await lireDansUnFil({
    repertoire: coeur.repertoire,
    borneSeq: coeur.ecrivain?.durable?.lastSeq ?? null,
    selection: demande.selection,
    seq: demande.seq,
    ticket: demande.ticket,
  });
  if (lu.refus) {
    if (lu.refus.seq !== undefined && lu.refus.seq !== null) retenu = lu.refus.seq;
    return refus(lu.refus.raison, lu.refus);
  }
  const lecture = lu.lecture;
  retenu = lecture.evenement.seq;
  const periodStart = lecture.periodStart;

  // Ordre 9 : avec `ticket`, le jeu d'approbateurs de la décision (EX-12.23).
  const jeuDecision = (d) => coeur.approbations?.jeuDecision?.(d) ?? null;
  if (demande.selection === "ticket") {
    const decisions = lecture.decisions;
    if (!decisions.length || !jeuDecision(decisions[decisions.length - 1])) return refus("approbations_introuvables");
  }

  // Ordre 10 : le reste de la lecture (journal.json, série des points, clés).
  let base;
  try {
    base = await assemblerBase({
      repertoire: coeur.repertoire,
      seq: retenu,
      lecture,
      clePublique: async (id) => {
        try {
          return await coeur.signataire.clePubliqueHex(id);
        } catch (e) {
          throw Object.assign(new Error(`clé ${id}`), { code: e?.code ?? "cle_indisponible", path: `cle ${id}` });
        }
      },
      jeuDecision,
    });
  } catch (e) {
    return refus("lecture_impossible", { detail: detailErreur(e, e?.path) });
  }
  if (demande.selection === "ticket" && base.raisons.approbations === RAISON_JEU_INTROUVABLE) return refus("approbations_introuvables");

  // Ordre 11 : écriture atomique.
  if (erreurDestination !== null) return refus("ecriture_impossible", { detail: erreurDestination });
  const ancrage = typeof coeur.o?.ancrage?.exporterDossier === "function" && coeur.o.ancrage.demarre ? coeur.o.ancrage : null;
  const nomTemp = `${PREFIXE_TEMPORAIRE}${demande.request_id}`;
  let fdParent = null;
  let fdTemp = null;
  let cree = false;
  const cheminTemp = path.join(parentReel, nomTemp);
  /** Chemin réel du parent (point 2) : toujours celui que l'ordre 3 a retenu, et sous le répertoire des exports. */
  const parentInchange = () => {
    let reel;
    try {
      reel = fs.realpathSync(parent);
    } catch {
      return false;
    }
    if (reel !== parentReel || !cheminReelSous(reel, exportsReel)) return false;
    const tenu = path.dirname(cheminDuDescripteur(fdTemp));
    return tenu === parentReel && cheminReelSous(tenu, exportsReel) && cheminDuDescripteur(fdParent) === parentReel;
  };
  try {
    let produit;
    try {
      fdParent = fs.openSync(parent, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
      fs.mkdirSync(sousDescripteur(fdParent, nomTemp), { mode: 0o700 });
      cree = true;
      fdTemp = fs.openSync(sousDescripteur(fdParent, nomTemp), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      const stTemp = fs.fstatSync(fdTemp);
      // 0700 quel que soit le masque de création ; le bit setgid hérité est gardé.
      if ((stTemp.mode & 0o777) !== 0o700) fs.fchmodSync(fdTemp, 0o700 | (stTemp.mode & 0o2000));
    } catch (e) {
      throw new RefusExport("ecriture_impossible", { detail: detailErreur(e, cree ? cheminTemp : parent) });
    }
    if (!parentInchange()) throw new RefusExport("destination_hors_exports");
    if (production && fs.fstatSync(fdTemp).gid !== gidExports) throw new RefusExport("ecriture_impossible", { detail: "groupe" });

    // Contenu (EX-15.13, point 1).
    let attendus;
    try {
      if (ancrage) {
        const r = ancrage.exporterDossier(base, { destination: sousDescripteur(fdTemp), generated_at, destinationFinale: destination });
        attendus = [...r.fichiers.keys(), "dossier.json", ...(r.pieces?.entetes ? ["entetes-bitcoin.json"] : [])];
        produit = { composant: "ancrage", dossier: r.dossier, octetsIndex: r.octetsIndex, entetes: Boolean(r.pieces?.entetes), point: r.point, defauts: r.defauts?.length ?? 0 };
      } else {
        const r = construireDossierNoyau(base, generated_at);
        for (const [nom, octets] of r.fichiers) ecrireFichier(fdTemp, nom, octets);
        ecrireFichier(fdTemp, "dossier.json", r.octetsIndex);
        attendus = [...r.fichiers.keys(), "dossier.json"];
        produit = { composant: "noyau", dossier: r.dossier, octetsIndex: r.octetsIndex, entetes: false, point: r.point, defauts: 0 };
      }
      // Rien d'autre que ces fichiers ; chacun en 0640, synchronisé, du groupe des lecteurs en production.
      const presents = fs.readdirSync(sousDescripteur(fdTemp)).sort();
      if (presents.length !== attendus.length || [...attendus].sort().some((n, k) => n !== presents[k])) throw Object.assign(new Error("contenu"), { code: "EEXIST", path: cheminTemp });
      for (const nom of presents) {
        const fd = fs.openSync(sousDescripteur(fdTemp, nom), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
        try {
          const st = fs.fstatSync(fd);
          if (!st.isFile()) throw Object.assign(new Error("fichier"), { code: "EINVAL", path: path.join(cheminTemp, nom) });
          if (production && st.gid !== gidExports) throw new RefusExport("ecriture_impossible", { detail: "groupe" });
          fs.fchmodSync(fd, 0o640);
          fs.fsyncSync(fd);
        } finally {
          fs.closeSync(fd);
        }
      }
      fs.fchmodSync(fdTemp, 0o750);
      fs.fsyncSync(fdTemp);
    } catch (e) {
      if (e instanceof RefusExport) throw e;
      throw new RefusExport("ecriture_impossible", { detail: typeof e?.code === "string" && e.code ? detailErreur(e, e?.path ?? cheminTemp) : detailErreurInterne(e) });
    }

    // Point d'arrêt des essais (option du cœur, jamais posée par le démon) : avant la seconde vérification.
    if (typeof coeur.o?.pointArretExport === "function") await coeur.o.pointArretExport({ etape: "avant_renommage", request_id: demande.request_id, temporaire: cheminDuDescripteur(fdTemp) });

    if (!parentInchange()) throw new RefusExport("destination_hors_exports");
    try {
      fs.renameSync(sousDescripteur(fdParent, nomTemp), sousDescripteur(fdParent, nomDestination));
    } catch (e) {
      throw new RefusExport("ecriture_impossible", { detail: detailErreur(e, destination) });
    }
    cree = false;
    try {
      // Point d'essai (option du cœur, jamais posée par le démon) : synchronisation du parent en échec.
      if (typeof coeur.o?.essaiSynchronisationParent === "function") coeur.o.essaiSynchronisationParent({ request_id: demande.request_id, destination });
      fs.fsyncSync(fdParent);
    } catch (e) {
      // Révision 0.9 (EX-15.13, point 2) : le dossier, complet et synchronisé
      // fichier par fichier, reste en place sous son nom ; aucune ligne
      // dossier_exported ; détail `synchronisation_parent <code> <parent>`.
      const code = typeof e?.code === "string" && e.code ? e.code : "erreur_interne";
      return refus("ecriture_impossible", { detail: `synchronisation_parent ${code} ${parent}`.slice(0, DETAIL_MAX) });
    }
    const data = {
      selection: demande.selection,
      ticket: demande.ticket,
      seq: retenu,
      hash: lecture.evenement.hash,
      period_start: periodStart,
      destination,
      generated_at: produit.dossier.generated_at,
      dossier_sha256: sha256Hex(produit.octetsIndex),
      parts_present: produit.dossier.parts.filter((x) => x.present).length,
      files: attendus.length,
      bitcoin_headers: produit.entetes,
      checkpoint_rank: produit.point?.rang ?? null,
      checkpoint_tree_size: produit.point?.tree_size ?? null,
      defects: produit.defauts,
    };
    return { event: "dossier_exported", component: produit.composant, seq: retenu, request_id: demande.request_id, data };
  } catch (e) {
    if (cree) supprimerTemporaire(fdTemp, nomTemp, cheminTemp);
    if (e instanceof RefusExport) return refus(e.raison, e.x);
    // erreur imprévue pendant l'écriture (EX-15.15) : erreur_interne, sauf erreur du système
    return refus("ecriture_impossible", { detail: typeof e?.code === "string" && e.code ? detailErreur(e, cheminTemp) : detailErreurInterne(e) });
  } finally {
    if (fdTemp !== null) fs.closeSync(fdTemp);
    if (fdParent !== null) fs.closeSync(fdParent);
  }
}

/**
 * Restes d'exports interrompus (EX-15.13, point 2) : à l'acquisition du bail,
 * avant de lire aucune demande d'export, chaque répertoire
 * `.noortrace-partiel-<32 chiffres hexadécimaux minuscules>` trouvé sous le
 * répertoire des exports, sans suivre de lien symbolique, est supprimé et
 * consigné (`dossier_export_partial_removed`). Un répertoire des exports
 * absent ou illisible n'a rien à nettoyer.
 * @param {{config: object, journal: import("./journal-exploitation.mjs").JournalExploitation}} coeur
 * @returns {string[]} chemins supprimés
 */
export function supprimerRestesExports(coeur) {
  const racine = repertoireExports(coeur.config);
  const supprimes = [];
  const pile = [racine];
  while (pile.length) {
    const dir = pile.pop();
    let entrees;
    try {
      entrees = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const d of entrees) {
      if (!d.isDirectory()) continue;
      const chemin = path.join(dir, d.name);
      if (MOTIF_RESTE.test(d.name)) {
        try {
          fs.rmSync(chemin, { recursive: true, force: true });
          supprimes.push(chemin);
          coeur.journal.consigner("warning", "noyau", "dossier_export_partial_removed", { path: chemin });
        } catch {
          // supprimé ailleurs, ou droits retirés : laissé
        }
      } else {
        pile.push(chemin);
      }
    }
  }
  return supprimes;
}

// ------------------------------------------------------------------ fil de calcul

if (!isMainThread && workerData?.lectureExportNoortrace) {
  lireJournalPourExport(workerData.lectureExportNoortrace).then(
    (r) => parentPort.postMessage(r),
    (e) => parentPort.postMessage({ refus: { raison: "lecture_impossible", detail: detailErreur(e, e?.path ?? "fil de lecture") } }),
  );
}
