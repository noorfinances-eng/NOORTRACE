// Reprise après arrêt (CT-2 §12.4, §12.5, EX-9.8). Au démarrage, avant
// d'écrire : (1) relecture du journal, validation complète du dernier
// segment et troncature d'une fin incomplète (EX-12.10) ; (2) événements de
// reprise des intentions restées ouvertes, dans l'ordre du journal
// d'intention (EX-12.14) ; puis, par le cœur, (3) événements en attente et
// (4) événement de politique.

import fs from "node:fs/promises";
import path from "node:path";
import { ZERO32, decoderHorodatage, hexVersOctets, NOMS_RESERVES } from "@noortrace/noyau";
import { listerSegments, lireSegmentFerme, relireSegment } from "./segments.mjs";
import { tronquer } from "./fichiers.mjs";
import { IndexChaine } from "./index-chaine.mjs";
import { dernierManifeste, debutPeriode } from "./periodes.mjs";
import { etatSerie, nomSerie, relireSerie } from "./points.mjs";
import { effetParDefaut } from "./effets.mjs";
import { redactionDe } from "./capture.mjs";

/** Anomalie de relecture qui bloque l'écriture jusqu'à intervention. */
export class ErreurRelecture extends Error {
  /** @param {string} evenement code du journal d'exploitation @param {object} donnees */
  constructor(evenement, donnees) {
    super(`${evenement} : ${JSON.stringify(donnees)}`);
    this.name = "ErreurRelecture";
    this.evenement = evenement;
    this.donnees = donnees;
  }
}

/**
 * Relit un journal (EX-12.10 pas 1 à 4) et dérive l'état de l'écrivain et
 * les index de la chaîne. Le dernier segment est validé ligne à ligne, et
 * tronqué à sa dernière ligne valide s'il finit par une écriture tronquée.
 * @param {string} repertoire répertoire du journal
 * @param {{clePublique: (keyId: string) => Promise<Uint8Array|null>, journal?: object, intervalle?: number}} options
 * @returns {Promise<object>} état relu
 */
export async function relireJournal(repertoire, options) {
  const dirSegments = path.join(repertoire, "segments");
  const segments = await listerSegments(dirSegments);
  const index = new IndexChaine();
  const evenements = [];
  let lastSeq = 0;
  let lastHash = ZERO32;
  let epoqueMax = null;
  let cleCourante = null;
  const clesConnues = new Map();
  for (let k = 0; k < segments.length; k++) {
    const s = segments[k];
    if (epoqueMax !== null && s.epoch < epoqueMax) throw new ErreurRelecture("segment_order", { segment: s.nom });
    epoqueMax = s.epoch;
    if (s.first_seq !== lastSeq + 1) throw new ErreurRelecture("segment_gap", { segment: s.nom, attendu: lastSeq + 1 });
    const octets = new Uint8Array(await fs.readFile(s.chemin));
    let entete;
    let liste;
    if (k < segments.length - 1) {
      ({ entete, evenements: liste } = lireSegmentFerme(octets));
    } else {
      const publiques = new Map(clesConnues);
      const enteteBrute = lireEnteteSimple(octets);
      const cleEntete = enteteBrute?.recorder_key_id ?? null;
      if (cleEntete && !publiques.has(cleEntete)) {
        let p = null;
        try {
          p = await options.clePublique(cleEntete);
        } catch {
          p = null;
        }
        if (p) publiques.set(cleEntete, p);
      }
      const r = relireSegment(octets, {
        verifierSignatures: true,
        clePublique: (id) => publiques.get(id) ?? null,
        prevHashAttendu: lastHash,
        firstSeqAttendu: s.first_seq,
      });
      if (r.corruption) {
        options.journal?.consigner("error", "stockage", "segment_corrupted", { segment: s.nom, ...r.corruption });
        throw new ErreurRelecture("segment_corrupted", { segment: s.nom, ...r.corruption });
      }
      if (r.tronque || r.entete === null) {
        if (r.entete === null) {
          // Segment réduit à un en-tête incomplet : rien de durable.
          await fs.rm(s.chemin);
          options.journal?.consigner("warning", "stockage", "segment_truncated", { segment: s.nom, removed_bytes: octets.length, expected_seq: lastSeq + 1 });
          break;
        }
        await tronquer(s.chemin, r.finValide);
        options.journal?.consigner("warning", "stockage", "segment_truncated", {
          segment: s.nom,
          removed_bytes: octets.length - r.finValide,
          expected_seq: (r.evenements[r.evenements.length - 1]?.seq ?? lastSeq) + 1,
        });
      }
      entete = r.entete;
      liste = r.evenements;
    }
    if (cleCourante === null) cleCourante = entete.recorder_key_id;
    for (const e of liste) {
      evenements.push(e);
      index.ajouter(e);
      if (e.execution.tool === NOMS_RESERVES.ROTATION) {
        const a = e.execution.arguments.value;
        clesConnues.set(a.new_key_id, hexVersOctets(a.new_public_key, 32));
        cleCourante = a.new_key_id;
      }
      lastSeq = e.seq;
      lastHash = e.hash;
    }
  }
  const dernier = evenements[evenements.length - 1] ?? null;
  const lastTs = dernier ? decoderHorodatage(dernier.ts) : null;

  // Période courante : celle qui suit le dernier manifeste, sinon celle du
  // premier événement.
  const dm = await dernierManifeste(path.join(repertoire, "manifestes"));
  let periode = null;
  let prevPeriodHash = ZERO32;
  let plancherTs = null;
  if (dm) {
    const m = dm.manifeste;
    prevPeriodHash = dm.periodHash;
    plancherTs = m.period_end * 1000;
    const hashAvant = m.last_seq === 0 ? ZERO32 : (evenements.find((e) => e.seq === m.last_seq)?.hash ?? ZERO32);
    periode = { start: m.period_end, firstSeq: m.last_seq + 1, hashAvant, evenements: [] };
  } else if (evenements.length) {
    periode = { start: debutPeriode(decoderHorodatage(evenements[0].ts)), firstSeq: 1, hashAvant: ZERO32, evenements: [] };
  }
  if (periode) {
    for (const e of evenements) if (e.seq >= periode.firstSeq) periode.evenements.push({ seq: e.seq, ts: decoderHorodatage(e.ts), hash: e.hash });
  }
  const intervalle = options.intervalle ?? 60;
  const serie = periode
    ? etatSerie(await relireSerie(path.join(repertoire, "points", nomSerie(periode.start))), periode.start * 1000, intervalle)
    : null;
  return {
    lastSeq,
    lastHash,
    lastTs,
    cleCourante,
    epoqueMax,
    index,
    evenements,
    periode,
    prevPeriodHash,
    plancherTs,
    serie,
    dernierSegment: segments.length ? segments[segments.length - 1].nom : null,
  };
}

function lireEnteteSimple(octets) {
  const fin = octets.indexOf(0x0a);
  if (fin < 0) return null;
  try {
    return JSON.parse(new TextDecoder().decode(octets.subarray(0, fin)));
  } catch {
    return null;
  }
}

/**
 * Plan de reprise des intentions sans levée (EX-12.14), dans l'ordre du
 * fichier : levée implicite par un candidat de la chaîne, ou événement de
 * reprise à construire.
 * @param {object[]} intentions entrées de `relireIntentions`
 * @param {Map<string, number>} levees intent_id → seq
 * @param {object[]} evenements événements durables du journal
 * @returns {{intentId: string, entree: object, candidat: object|null}[]}
 */
export function planifierReprise(intentions, levees, evenements) {
  const designes = new Set(levees.values());
  const apparies = new Set();
  const plan = [];
  for (const entree of intentions) {
    const i = entree.intention;
    if (levees.has(i.intent_id)) continue;
    const ecrite = decoderHorodatage(i.written_at);
    let candidat = null;
    for (const e of evenements) {
      if (e.execution.status !== "executee") continue;
      if (designes.has(e.seq) || apparies.has(e.seq)) continue;
      if (decoderHorodatage(e.ts) < ecrite) continue;
      if (e.execution.tool !== i.tool || e.execution.arguments?.sha256 !== i.arguments.sha256) continue;
      if ((e.policy?.ticket ?? null) !== (i.ticket ?? null)) continue;
      candidat = e;
      break;
    }
    if (candidat) apparies.add(candidat.seq);
    plan.push({ intentId: i.intent_id, entree, candidat });
  }
  return plan;
}

/**
 * Événement partiel de reprise (EX-12.14 pas 2, EX-12.13) : depuis la ligne
 * contexte, ou, sans elle, depuis la ligne intention et la chaîne.
 * @param {object} entree `{ intention, sha256, contexte }`
 * @param {{index: object, hote: (id: string) => object|null, classe: (tool: string) => "lecture"|"ecriture",
 *   origine: (tool: string) => {alias: string, nom: string}, nomRedaction: string|null, recorder: string,
 *   resultat: object}} ctx `resultat` : référence de la pièce de reprise
 * @returns {{partiel: object|null, note: string|null}}
 */
export function partielReprise(entree, ctx) {
  const i = entree.intention;
  let base = entree.contexte;
  let note = null;
  if (!base) {
    note = "intention_sans_contexte";
    const hote = ctx.hote(i.host);
    let policy = { rule: null, decision: "autorise", ticket: null };
    let approval = null;
    if (i.ticket) {
      const retenue = ctx.index.retenues.get(i.ticket)?.[0] ?? null;
      const decision = ctx.index.decisions.get(i.ticket) ?? null;
      if (!retenue || !decision) return { partiel: null, note: "intention_irreconstructible" };
      policy = { rule: retenue.policy.rule, decision: retenue.policy.decision, ticket: retenue.policy.ticket };
      approval = decision.approval;
    }
    if (!hote) return { partiel: null, note: "intention_irreconstructible" };
    const version = ctx.index.versionA(decoderHorodatage(i.written_at));
    base = {
      delegation: { launched_by: hote.launched_by, on_behalf_of: hote.on_behalf_of ?? null, scope: hote.scope, run_id: null },
      code: { model: null, prompt_version: null, policy_version: version, recorder: ctx.recorder },
      intent: null,
      policy,
      approval,
      execution: { tool: i.tool, arguments: i.arguments },
      effects: [],
      context: [],
    };
  }
  const classe = ctx.classe(i.tool);
  const o = ctx.origine(i.tool);
  const effets = base.effects?.length ? base.effects : classe === "ecriture" ? [effetParDefaut(o.alias, o.nom)] : [];
  const partiel = {
    delegation: base.delegation,
    code: base.code,
    intent: base.intent,
    policy: { rule: base.policy.rule, decision: base.policy.decision, ticket: base.policy.ticket, redaction: null },
    approval: base.approval,
    execution: {
      tool: base.execution.tool,
      arguments: base.execution.arguments,
      status: "executee",
      result: ctx.resultat,
      duration_ms: 0,
      is_error: true,
    },
    effects: effets,
    context: base.context,
  };
  partiel.policy.redaction = redactionDe(partiel, ctx.nomRedaction);
  return { partiel, note };
}
