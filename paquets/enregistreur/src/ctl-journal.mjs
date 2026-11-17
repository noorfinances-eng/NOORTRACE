// Reprise dans un journal neuf (CT-2 EX-11.16, CT-8 §11.4 chemin C ;
// complément du 2026-11-16) : lien entre l'ancien journal, qui ne peut plus
// être continué, et le nouveau, consigné hors chaîne à deux endroits :
//   - la note d'exploitant qui accompagne la demande d'inscription du nouveau
//     journal (CT-4 §8.4, `demande_signature`) : fichier
//     `<demande sans .json>.note-exploitant.json`, lié à la demande par son
//     `digest` (la forme `demande_signature` n'a pas de membre libre, et la
//     note n'entre pas dans le condensé que signent les approbateurs) ;
//   - la ligne `journal_successor` du journal d'exploitation de l'ancien
//     démon (`old_journal_id`, `last_seq`, `last_hash`, `new_journal_id`).
// `last_seq` et `last_hash` sont lus de la fin réelle de l'ancien journal
// (segments relus : en-têtes, `first_seq`, chaînage, `hash` recalculé),
// jamais fournis par l'exploitant.
//
//   noortrace-ctl journal successeur --configuration <ancienne configuration> --demande <demande d'inscription>
//   noortrace-ctl journal verifier-successeur (--configuration <fichier> | --journal <répertoire>
//       --journal-exploitation <fichier>) --demande <demande d'inscription> [--note <fichier>]
//
// Codes : 0 fait, ou lien valide ; 1 refusé, ou lien invalide ; 2 usage.

import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { ecrireHorodatage } from "@noortrace/noyau";
import { listerSegments, relireSegmentParTranches } from "./segments.mjs";
import { JournalExploitation } from "./journal-exploitation.mjs";
import { trouverDemons } from "./ctl-demon.mjs";

export const USAGE_CTL_JOURNAL = [
  "usage : noortrace-ctl journal successeur --configuration <configuration de l'ancien démon> --demande <demande d'inscription du nouveau journal>",
  "        noortrace-ctl journal verifier-successeur (--configuration <fichier> | --journal <répertoire> --journal-exploitation <fichier>)",
  "            --demande <demande d'inscription du nouveau journal> [--note <note d'exploitant>]",
].join("\n");

/** Événement du journal d'exploitation qui porte le lien (CT-2 EX-11.16, EX-17.2). */
export const EVENEMENT_SUCCESSEUR = "journal_successor";

const HEX32 = /^0x[0-9a-f]{64}$/;
const ZERO32 = `0x${"0".repeat(64)}`;

/** Erreur de refus de la commande : code nommé, code de sortie 1. */
export class RefusSuccession extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

/** Chemin de la note d'exploitant d'une demande d'inscription. */
export function cheminNoteExploitant(demande) {
  return demande.endsWith(".json") ? `${demande.slice(0, -5)}.note-exploitant.json` : `${demande}.note-exploitant.json`;
}

/**
 * Fin réelle d'un journal (CT-2 EX-12.1) : chaque segment relu dans l'ordre,
 * en-tête égal à `journal.json`, `first_seq` continu, `prev_hash` chaîné,
 * `hash` de chaque événement recalculé. Une fin incomplète n'est admise que
 * pour le dernier segment (écriture interrompue : la fin réelle est le
 * dernier événement complet). Les signatures sont vérifiées par CT-8
 * EX-11.7 (`verifier-journal.mjs`), pas ici.
 * @param {string} rep répertoire du journal
 * @returns {Promise<{org_id: string, journal_id: string, last_seq: number, last_hash: string, tronque: boolean}>}
 */
export async function finDuJournal(rep) {
  let id;
  try {
    id = JSON.parse(await fsp.readFile(path.join(rep, "journal.json"), "utf8"));
  } catch {
    throw new RefusSuccession("journal_illisible", `journal.json illisible sous ${rep}`);
  }
  if (!HEX32.test(id?.org_id ?? "") || !HEX32.test(id?.journal_id ?? "")) throw new RefusSuccession("journal_illisible", `journal.json sans org_id ni journal_id sous ${rep}`);
  const segments = await listerSegments(path.join(rep, "segments"));
  let attendu = 1;
  let prev = ZERO32;
  let tronque = false;
  for (let k = 0; k < segments.length; k++) {
    const s = segments[k];
    const r = await relireSegmentParTranches(new Uint8Array(await fsp.readFile(s.chemin)), { verifierSignatures: false, prevHashAttendu: prev, firstSeqAttendu: attendu });
    if (!r.entete || r.entete.org_id !== id.org_id || r.entete.journal_id !== id.journal_id) throw new RefusSuccession("journal_altere", `segments/${s.nom} : en-tête absent ou d'un autre journal`);
    if (r.corruption) throw new RefusSuccession("journal_altere", `segments/${s.nom} : ${r.corruption.raison}${r.corruption.seq ? ` (seq ${r.corruption.seq})` : ""}`);
    if (r.tronque) {
      if (k !== segments.length - 1) throw new RefusSuccession("journal_altere", `segments/${s.nom} : fin incomplète d'un segment qui n'est pas le dernier`);
      tronque = true;
    }
    if (r.evenements.length) {
      attendu = r.evenements.at(-1).seq + 1;
      prev = r.evenements.at(-1).hash;
    }
  }
  if (attendu === 1) throw new RefusSuccession("journal_vide", `aucun événement sous ${rep}`);
  return { org_id: id.org_id, journal_id: id.journal_id, last_seq: attendu - 1, last_hash: prev, tronque };
}

/**
 * Contrôle la demande d'inscription du nouveau journal (CT-4 §7.7, §8.4) :
 * forme `demande_signature`, opération `inscription`, même organisation,
 * `journal_id` différent de l'ancien. Les signatures et le condensé sont
 * contrôlés au relais (OP-6 à OP-8 de CT-4), pas ici.
 * @param {object} demande
 * @param {{org_id: string, journal_id: string}} ancien
 * @returns {string[]} motifs de refus
 */
export function controlerDemande(demande, ancien) {
  const m = [];
  if (demande?.version !== 0 || demande?.operation !== "inscription") m.push("la demande n'est pas une demande_signature d'inscription (version 0)");
  const f = demande?.fields ?? {};
  if (String(f.org_id ?? "").toLowerCase() !== ancien.org_id) m.push("fields.org_id différent de l'organisation de l'ancien journal");
  const nouveau = String(f.journal_id ?? "").toLowerCase();
  if (!HEX32.test(nouveau) || nouveau === ZERO32) m.push("fields.journal_id absent ou nul");
  else if (nouveau === ancien.journal_id) m.push("fields.journal_id égal à celui de l'ancien journal : un journal neuf a un journal_id distinct (CT-2 EX-11.16)");
  if (!HEX32.test(String(demande?.digest ?? "").toLowerCase())) m.push("digest absent");
  return m;
}

/** Données du lien, dans l'ordre de la ligne `journal_successor`. */
function donneesLien(fin, nouveau) {
  return { old_journal_id: fin.journal_id, last_seq: fin.last_seq, last_hash: fin.last_hash, new_journal_id: nouveau };
}

/** Lignes `journal_successor` du journal d'exploitation et de ses fichiers tournés (`<chemin>.1` …). */
export function lignesSuccesseur(cheminOps) {
  const fichiers = [cheminOps];
  for (let k = 1; fs.existsSync(`${cheminOps}.${k}`); k++) fichiers.push(`${cheminOps}.${k}`);
  const lignes = [];
  for (const f of fichiers) {
    let texte = "";
    try {
      texte = fs.readFileSync(f, "utf8");
    } catch {
      continue;
    }
    for (const l of texte.split("\n")) {
      if (!l.includes(EVENEMENT_SUCCESSEUR)) continue;
      try {
        const o = JSON.parse(l);
        if (o?.event === EVENEMENT_SUCCESSEUR) lignes.push(o);
      } catch {
        // ligne illisible : ignorée (EX-9.7)
      }
    }
  }
  return lignes;
}

const memeLien = (a, b) => a.old_journal_id === b.old_journal_id && a.last_seq === b.last_seq && a.last_hash === b.last_hash && a.new_journal_id === b.new_journal_id;

/**
 * Vérifie le lien d'un journal neuf : la note d'exploitant et la ligne
 * `journal_successor` portent la fin réelle de l'ancien journal et le
 * `journal_id` de la demande d'inscription, et la note porte le `digest`
 * de la demande.
 * @param {{journal: string, journalExploitation: string, demande: string, note?: string}} o chemins
 * @returns {Promise<{valide: boolean, checks: {id: string, status: string, detail: string|null}[], fin: object|null, lien: object|null}>}
 */
export async function verifierSuccession(o) {
  const checks = [];
  const ajouter = (id, ok, detail = null) => checks.push({ id, status: ok ? "reussi" : "echec", detail: ok ? null : detail });
  let fin = null;
  try {
    fin = await finDuJournal(o.journal);
    ajouter("fin_ancien_journal", true);
  } catch (e) {
    ajouter("fin_ancien_journal", false, `${e.code ?? "erreur"} : ${e.message}`);
    return { valide: false, checks, fin: null, lien: null };
  }
  let demande = null;
  try {
    demande = JSON.parse(fs.readFileSync(o.demande, "utf8"));
  } catch {
    ajouter("demande", false, "demande d'inscription illisible");
    return { valide: false, checks, fin, lien: null };
  }
  const motifs = controlerDemande(demande, fin);
  ajouter("demande", motifs.length === 0, motifs.join(" ; "));
  const nouveau = String(demande?.fields?.journal_id ?? "").toLowerCase();
  const attendu = donneesLien(fin, nouveau);
  let note = null;
  try {
    note = JSON.parse(fs.readFileSync(o.note ?? cheminNoteExploitant(o.demande), "utf8"));
  } catch {
    note = null;
  }
  if (note === null) ajouter("note_exploitant", false, "note d'exploitant absente ou illisible");
  else {
    const ecarts = [];
    if (note.version !== 0 || note.kind !== EVENEMENT_SUCCESSEUR) ecarts.push("forme (version 0, kind journal_successor)");
    if (note.org_id !== fin.org_id) ecarts.push("org_id");
    for (const k of ["old_journal_id", "last_seq", "last_hash", "new_journal_id"]) if (note[k] !== attendu[k]) ecarts.push(k);
    if (String(note.registration_digest ?? "") !== String(demande?.digest ?? "").toLowerCase()) ecarts.push("registration_digest");
    ajouter("note_exploitant", ecarts.length === 0, `écart avec la fin réelle de l'ancien journal ou la demande : ${ecarts.join(", ")}`);
  }
  const lignes = lignesSuccesseur(o.journalExploitation).filter((l) => l.journal_id === fin.journal_id);
  const egales = lignes.filter((l) => memeLien(l.data ?? {}, attendu));
  const autres = lignes.filter((l) => !memeLien(l.data ?? {}, attendu));
  if (!lignes.length) ajouter("ligne_journal_exploitation", false, "aucune ligne journal_successor de l'ancien journal");
  else ajouter("ligne_journal_exploitation", egales.length > 0 && autres.length === 0, autres.length ? `ligne journal_successor différente de la fin réelle ou de la demande (${autres.length})` : "aucune ligne égale");
  return { valide: checks.every((c) => c.status === "reussi"), checks, fin, lien: attendu };
}

/** Options `--nom valeur` d'une sous-commande ; null si une option est inconnue ou répétée. */
function lireOptions(reste, admises) {
  const o = {};
  for (let k = 0; k < reste.length; k += 2) {
    const nom = reste[k];
    if (!admises.includes(nom) || k + 1 >= reste.length || nom.slice(2) in o) return null;
    o[nom.slice(2)] = reste[k + 1];
  }
  return o;
}

/** Répertoire du journal et journal d'exploitation de la configuration d'un démon. */
function cheminsDepuisConfiguration(fichier) {
  let c;
  try {
    c = JSON.parse(fs.readFileSync(fichier, "utf8"));
  } catch {
    throw new RefusSuccession("configuration_illisible", `configuration illisible : ${fichier}`);
  }
  const org = c?.recorder?.org_id;
  const jid = c?.recorder?.journal_id;
  if (!HEX32.test(org ?? "") || !HEX32.test(jid ?? "") || typeof c?.storage?.root !== "string" || typeof c?.supervision?.ops_log?.path !== "string") {
    throw new RefusSuccession("configuration_illisible", "configuration sans recorder.org_id, recorder.journal_id, storage.root ou supervision.ops_log.path");
  }
  return {
    journal: path.join(c.storage.root, org.slice(2), jid.slice(2)),
    journalExploitation: c.supervision.ops_log.path,
    ops: c.supervision.ops_log,
  };
}

/**
 * `noortrace-ctl journal successeur` : écrit la note d'exploitant à côté de
 * la demande et la ligne `journal_successor` dans le journal d'exploitation
 * de l'ancien démon, arrêté. Rejouée sur le même lien, elle n'écrit rien de
 * plus (`deja_fait`) ; un lien différent déjà écrit est refusé.
 */
async function successeur(o, io) {
  const ch = cheminsDepuisConfiguration(o.configuration);
  if (trouverDemons({ configuration: o.configuration, racineProc: io.racineProc }).length) {
    throw new RefusSuccession("demon_en_marche", "un démon tourne avec cette configuration : l'ancien démon est arrêté avant la reprise dans un journal neuf (CT-8 §11.4, chemin C)");
  }
  const fin = await finDuJournal(ch.journal);
  let demande;
  try {
    demande = JSON.parse(fs.readFileSync(o.demande, "utf8"));
  } catch {
    throw new RefusSuccession("demande_illisible", `demande d'inscription illisible : ${o.demande}`);
  }
  const motifs = controlerDemande(demande, fin);
  if (motifs.length) throw new RefusSuccession("demande_invalide", motifs.join(" ; "));
  const lien = donneesLien(fin, String(demande.fields.journal_id).toLowerCase());
  const note = { version: 0, kind: EVENEMENT_SUCCESSEUR, org_id: fin.org_id, ...lien, registration_digest: String(demande.digest).toLowerCase(), written_at: ecrireHorodatage(Date.now()) };
  const cheminNote = cheminNoteExploitant(o.demande);
  let noteEcrite = false;
  if (fs.existsSync(cheminNote)) {
    let n = null;
    try {
      n = JSON.parse(fs.readFileSync(cheminNote, "utf8"));
    } catch {
      n = null;
    }
    if (!n || !memeLien(n, lien) || n.registration_digest !== note.registration_digest || n.org_id !== note.org_id) {
      throw new RefusSuccession("note_existante", `${cheminNote} existe avec un autre lien : rien n'est remplacé`);
    }
  } else {
    const tmp = `${cheminNote}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, `${JSON.stringify(note, null, 2)}\n`, { flag: "wx" });
    fs.renameSync(tmp, cheminNote);
    noteEcrite = true;
  }
  const lignes = lignesSuccesseur(ch.journalExploitation).filter((l) => l.journal_id === fin.journal_id);
  if (lignes.some((l) => !memeLien(l.data ?? {}, lien))) {
    throw new RefusSuccession("successeur_existant", "le journal d'exploitation de l'ancien démon porte déjà une ligne journal_successor différente");
  }
  let ligneEcrite = false;
  if (!lignes.length) {
    const j = new JournalExploitation({ chemin: ch.journalExploitation, niveau: "debug", rotation: ch.ops.rotate_max_bytes, conserver: ch.ops.keep_files, org_id: fin.org_id, journal_id: fin.journal_id });
    j.consigner("info", "noyau", EVENEMENT_SUCCESSEUR, lien);
    if (!lignesSuccesseur(ch.journalExploitation).some((l) => l.journal_id === fin.journal_id && memeLien(l.data ?? {}, lien))) {
      throw new RefusSuccession("journal_exploitation_inaccessible", `ligne journal_successor non écrite dans ${ch.journalExploitation}`);
    }
    ligneEcrite = true;
  }
  return { result: noteEcrite || ligneEcrite ? "fait" : "deja_fait", note: cheminNote, journal_exploitation: ch.journalExploitation, link: lien, truncated_end: fin.tronque };
}

/**
 * Point d'entrée de `noortrace-ctl journal …`.
 * @param {string[]} argv arguments après `journal`
 * @param {{stdout?: NodeJS.WritableStream, stderr?: NodeJS.WritableStream, racineProc?: string}} [io]
 * @returns {Promise<number>}
 */
export async function principalCtlJournal(argv, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  const [sous, ...reste] = argv;
  const usage = () => {
    stderr.write(`${USAGE_CTL_JOURNAL}\n`);
    return 2;
  };
  try {
    if (sous === "successeur") {
      const o = lireOptions(reste, ["--configuration", "--demande"]);
      if (!o || !o.configuration || !o.demande) return usage();
      const r = await successeur(o, io);
      stdout.write(`${JSON.stringify({ version: 0, command: "journal successeur", ...r })}\n`);
      return 0;
    }
    if (sous === "verifier-successeur") {
      const o = lireOptions(reste, ["--configuration", "--journal", "--journal-exploitation", "--demande", "--note"]);
      if (!o || !o.demande || (o.configuration ? o.journal || o["journal-exploitation"] : !o.journal || !o["journal-exploitation"])) return usage();
      const ch = o.configuration ? cheminsDepuisConfiguration(o.configuration) : { journal: o.journal, journalExploitation: o["journal-exploitation"] };
      const v = await verifierSuccession({ journal: ch.journal, journalExploitation: ch.journalExploitation, demande: o.demande, note: o.note });
      stdout.write(`${JSON.stringify({ version: 0, command: "journal verifier-successeur", result: v.valide ? "lien_valide" : "lien_invalide", link: v.lien, checks: v.checks })}\n`);
      return v.valide ? 0 : 1;
    }
    return usage();
  } catch (e) {
    if (e instanceof RefusSuccession) {
      stderr.write(`noortrace-ctl journal : ${e.code} : ${e.message}\n`);
      stdout.write(`${JSON.stringify({ version: 0, command: `journal ${sous}`, result: "refuse", error: { code: e.code, message: e.message } })}\n`);
      return 1;
    }
    throw e;
  }
}
