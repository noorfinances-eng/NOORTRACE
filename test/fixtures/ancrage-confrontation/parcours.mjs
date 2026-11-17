// Confrontation de la référence (scripts/lib/ancrage.mjs) et du composant
// d'ancrage (paquets/ancrage) sur des parcours tirés d'une graine (CT-5 A.4,
// confrontation aléatoire ; complément du 2026-11-16).
//
// Un parcours part d'une file vide, reçoit des entrées tirées au hasard
// (points K1 à K4 et leurs réponses, clôture de la période 1 de référence,
// réponses des calendriers, réponses RFC 3161, événements du registre, tics)
// et s'arrête et redémarre plusieurs fois : chaque segment, d'un démarrage à
// un arrêt, est rejoué par la référence puis par le composant, avec les mêmes
// gigues et les nonces des vecteurs (A.2) ; la file relue au redémarrage
// suivant est celle d'avant le segment plus les lignes que la référence a
// écrites pendant le segment (EX-8.5 : la dernière ligne d'un id fait foi).
//
// Modes, combinables :
//   rfc     réponses RFC 3161 de toute forme au jeton de clôture et à des
//           demandes inconnues ou d'une autre sorte, échecs du registre ;
//   points  points K1 à K4 (chacun admis ou non), leurs ancres et leurs jetons ;
//   coupe   arrêt brutal pendant l'écriture : seules les premières lignes du
//           segment ont atteint le disque (EX-8.5, règle 1 : la ligne précède
//           l'action ; une file coupée relit des demandes a_envoyer, envoyee…) ;
//   journaux un second journal dans la même file (CT-5 EX-9.4, complément du
//           2026-11-16 : une transaction en vol par clé de chaîne, c'est-à-dire
//           par journal ; deux journaux ne s'attendent pas) : journal-sinistres
//           de la même organisation, ou journal-principal d'une autre
//           organisation, qui clôt sa période précédente pendant les points du
//           premier ; son ancre, son jeton et sa soumission vivent à côté de
//           ceux du premier ; toujours avec les points ;
//   points2 (avec journaux ; complément du 2026-11-16, EX-8.16) le second
//           journal produit aussi les points de la période 1, aux mêmes
//           instants que le premier, et sa période 1 reste ouverte : leurs
//           échéances et leurs cadences tombent aux mêmes instants, dans
//           l'ordre où elles ont été armées ;
//   reprises (avec points ; complément du 2026-11-16, EX-9.5, EX-9.4) : les
//           quatre points sont ancrés (registry.checkpoints = tous), l'attente
//           de reprise est tirée courte (5 s) ou longue (10 min) ; juste avant
//           l'admission d'un point, le registre signale parfois l'échec de
//           l'ancre du point précédent (noeud_injoignable, nonce_incoherent,
//           transaction_refusee ou recu_absent), si bien que le point suivant
//           est admis pendant la reprise de cette ancre ;
//   sans mode : soumissions et réponses OpenTimestamps, tics.
//
// Invariants (CT-5 EX-9.4, compléments du 2026-11-16), rendus comme une
// divergence sur chaque segment où les deux implémentations concordent (`ou` :
// « invariant EX-9.4 ») : aucune ancre de période ne part (ligne `envoyee`
// écrite depuis un autre état) tant qu'une ancre de point de sa période et de
// son journal n'a ni son reçu ni un autre état final ; aucune ancre de point ne
// part tant qu'une ancre d'un point antérieur de sa période et de son journal
// (`checkpoint_ts` plus petit, puis l'ordre de la file) n'a ni son reçu ni un
// autre état final.
//
// Ne dépend que des deux implémentations et des vecteurs publiés
// (spec/vecteurs/ct-5 : constantes et configuration de la trace de référence).
// Déterministe : un générateur xorshift32 par graine ; aucune horloge lue.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

export const MODES = Object.freeze({
  ots: {},
  rfc: { rfc: true },
  points: { points: true },
  "points+rfc": { points: true, rfc: true },
  coupe: { coupe: true },
  "coupe+rfc": { coupe: true, rfc: true },
  "coupe+points": { coupe: true, points: true },
  "coupe+points+rfc": { coupe: true, points: true, rfc: true },
  journaux: { points: true, journaux: true },
  "journaux+rfc": { points: true, rfc: true, journaux: true },
  "coupe+journaux+rfc": { coupe: true, points: true, rfc: true, journaux: true },
  "journaux+points2": { points: true, journaux: true, points2: true },
  "journaux+points2+rfc": { points: true, rfc: true, journaux: true, points2: true },
  "coupe+journaux+points2+rfc": { coupe: true, points: true, rfc: true, journaux: true, points2: true },
  reprises: { points: true, reprises: true },
  "coupe+reprises+rfc": { coupe: true, points: true, rfc: true, reprises: true },
});

const sha = (s) => "0x" + crypto.createHash("sha256").update(s).digest("hex");
const T9 = ["T-1", "T-2", "T-3", "T-4", "T-5", "T-6", "T-7", "T-8", "T-9"];

/** xorshift32 : suite déterministe de flottants dans [0, 1). */
export function prng(graine) {
  let x = graine >>> 0 || 1;
  return () => {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    return x / 4294967296;
  };
}

/**
 * Contexte de confrontation : modules de la référence (`A`, scripts/lib/ancrage.mjs), du planificateur du composant
 * (`P`) et de ses traces (`T`), constantes et configuration lues dans les vecteurs publiés (`vecteurs` : spec/vecteurs/ct-5).
 */
export function contexte({ A, P, T, vecteurs }) {
  const constantes = JSON.parse(fs.readFileSync(path.join(vecteurs, "constantes.json"), "utf8"));
  const reference = JSON.parse(fs.readFileSync(path.join(vecteurs, "planification", "heure-nominale-reference.json"), "utf8"));
  const j = constantes.reference_journal;
  const p1 = j.periods.find((p) => p.index === 1);
  const points = ["K1", "K2", "K3", "K4"].map((nom) => ({ nom, ...j.checkpoints[nom] }));
  // Second journal du mode journaux : journal-sinistres des vecteurs (même organisation), ou journal-principal d'une
  // organisation inventée pour l'essai ; l'empreinte de sa période est tirée de son nom (aucune n'est publiée).
  const seconds = [
    { nom: constantes.vectors_journal.name, org_id: j.org_id, journal_id: constantes.vectors_journal.journal_id },
    { nom: j.name, org_id: sha("noortrace/essai/confrontation/organisation-b"), journal_id: j.journal_id },
  ];
  return { A, P, T, journal: j.name, org_id: j.org_id, journal_id: j.journal_id, p1, points, seconds, config: reference.config };
}

const ETATS_FINAUX = new Set(["obtenue", "complete", "sans_objet", "refusee", "remplacee"]);

/**
 * Invariant d'EX-9.4 (complément du 2026-11-16 : « l'ancre de la période ne part qu'après le reçu de l'ancre du point de
 * clôture de la même clé », et, dans une période, ses points d'abord) : rend les départs d'une ancre de période (ligne
 * `envoyee` écrite depuis un autre état) alors qu'une ancre de point de la même période et du même journal n'avait ni
 * son reçu ni un autre état final. `queueBefore` et `fileFinale` donnent les sujets ; `actions` est la suite rejouée
 * (`expected`). Ne lit que la trace : aucune implémentation n'est appelée.
 */
export function violationsAncrePeriode(queueBefore, actions, fileFinale) {
  const sujets = new Map();
  for (const d of [...queueBefore, ...fileFinale]) sujets.set(d.id, d.subject);
  const etats = new Map(queueBefore.map((d) => [d.id, d.state]));
  const violations = [];
  for (const [indice, a] of actions.entries()) {
    if (a.action !== "ecrire_file" || typeof a.request_id !== "string") continue;
    const avant = etats.get(a.request_id);
    etats.set(a.request_id, a.detail.state);
    if (!a.request_id.startsWith("ancre_registre_periode:") || a.detail.state !== "envoyee" || avant === "envoyee") continue;
    const sp = sujets.get(a.request_id);
    if (!sp) throw new Error(`invariant EX-9.4 : sujet inconnu pour ${a.request_id}`);
    for (const [id, etat] of etats) {
      if (!id.startsWith("ancre_registre_point:") || ETATS_FINAUX.has(etat)) continue;
      const s = sujets.get(id);
      if (!s) throw new Error(`invariant EX-9.4 : sujet inconnu pour ${id}`);
      if (s.org_id === sp.org_id && s.journal_id === sp.journal_id && s.period_start === sp.period_start) violations.push({ indice, t: a.t, periode: a.request_id, point: id, etat });
    }
  }
  return violations;
}

/** Rang d'une ancre de point dans sa série (EX-9.4) : `checkpoint_ts`, puis l'ordre de la file (8.5 : `created_at`, puis `id`). */
const avantDansLaSerie = (a, b) => a.subject.declared_at < b.subject.declared_at || (a.subject.declared_at === b.subject.declared_at && (a.created_at < b.created_at || (a.created_at === b.created_at && a.id < b.id)));

/**
 * Invariant d'EX-9.4 (complément du 2026-11-16, l'ordre des ancres des points d'une période) : rend les départs d'une
 * ancre de point (ligne `envoyee` écrite depuis un autre état) alors qu'une ancre d'un point antérieur de la même
 * période et du même journal (`checkpoint_ts` plus petit, puis l'ordre de la file) n'avait ni son reçu ni un autre état
 * final : incluses dans cet ordre, les deux ancres renverseraient l'ordre des blocs de la série (`hors_ordre`, EX-10.7).
 * `queueBefore` et `fileFinale` donnent les demandes ; ne lit que la trace.
 */
export function violationsOrdrePoints(queueBefore, actions, fileFinale) {
  const demandes = new Map();
  for (const d of [...queueBefore, ...fileFinale]) demandes.set(d.id, d);
  const etats = new Map(queueBefore.map((d) => [d.id, d.state]));
  const violations = [];
  for (const [indice, a] of actions.entries()) {
    if (a.action !== "ecrire_file" || typeof a.request_id !== "string") continue;
    const avant = etats.get(a.request_id);
    etats.set(a.request_id, a.detail.state);
    if (!a.request_id.startsWith("ancre_registre_point:") || a.detail.state !== "envoyee" || avant === "envoyee") continue;
    const d = demandes.get(a.request_id);
    if (!d) throw new Error(`invariant EX-9.4 : demande inconnue ${a.request_id}`);
    for (const [id, etat] of etats) {
      if (id === a.request_id || !id.startsWith("ancre_registre_point:") || ETATS_FINAUX.has(etat)) continue;
      const e = demandes.get(id);
      if (!e) throw new Error(`invariant EX-9.4 : demande inconnue ${id}`);
      if (e.subject.org_id === d.subject.org_id && e.subject.journal_id === d.subject.journal_id && e.subject.period_start === d.subject.period_start && avantDansLaSerie(e, d)) violations.push({ indice, t: a.t, point: a.request_id, anterieur: id, etat });
    }
  }
  return violations;
}

/** Rejoue un segment des deux côtés ; rend `{ ref }` s'ils concordent, sinon la première divergence. */
function confronterSegment(ctx, trace) {
  const { A, P, T } = ctx;
  const ref = A.creerPlanificateur(trace.config, { aleatoire: A.aleatoireVecteurs({ gigues: trace.jitter_ms }) });
  const comp = new P.Planificateur(trace.config, { gigues: [...trace.jitter_ms], nonces: T.noncesVecteurs(), fileInitiale: trace.queue_before });
  ref.charger(trace.queue_before);
  const actionsRef = [];
  const actionsComp = [];
  const origine = [];
  for (const [k, e] of trace.inputs.entries()) {
    let r;
    try {
      r = ref.recevoir(e);
    } catch (err) {
      return { entree: k, ou: "exception de la référence", indice: actionsRef.length, reference: err.message, composant: null };
    }
    actionsRef.push(...r);
    for (let i = 0; i < r.length; i++) origine.push(k);
    let c;
    try {
      c = comp.traiter(e);
    } catch (err) {
      return { entree: k, ou: "exception du composant", indice: actionsComp.length, reference: null, composant: err.message };
    }
    actionsComp.push(...c);
    const ecart = T.comparer(actionsRef, actionsComp, "expected")[0];
    if (ecart) return { entree: origine[ecart.indice] ?? k, ou: "expected", indice: ecart.indice, reference: ecart.attendu, composant: ecart.obtenu };
  }
  const ecart = T.comparer(ref.file(), comp.file(), "queue_after")[0];
  if (ecart) return { entree: trace.inputs.length - 1, ou: "queue_after", indice: ecart.indice, reference: ecart.attendu, composant: ecart.obtenu };
  // Invariant d'EX-9.4 sur la suite commune des deux implémentations.
  const v = violationsAncrePeriode(trace.queue_before, actionsRef, ref.file())[0] ?? violationsOrdrePoints(trace.queue_before, actionsRef, ref.file())[0];
  if (v) return { entree: origine[v.indice] ?? trace.inputs.length - 1, ou: "invariant EX-9.4", indice: v.indice, reference: v, composant: null };
  return { ref };
}

/**
 * Tire le parcours de `graine` dans `mode` (clé de MODES) et le confronte segment par segment. Rend `null` quand les
 * deux implémentations concordent sur tous les segments, sinon la première divergence : graine, mode, segment, entrée
 * (instant et type) et action (ou ligne de file) des deux côtés.
 */
export function confronterParcours(ctx, graine, mode) {
  const { A } = ctx;
  const m = MODES[mode];
  if (!m) throw new Error(`mode inconnu : ${mode}`);
  const r = prng(graine);
  const choix = (l) => l[Math.floor(r() * l.length)];
  const nonceTsa = (sorte, hash, n, journal = ctx.journal) => A.hexNonce(A.nonceDepuisEtiquette(A.ETIQUETTES.nonceTsa({ journal, sorte, hash, n })));
  const PH = ctx.p1.period_hash;
  const OP1 = `ots_periode:${PH}`;
  const AP1 = `ancre_registre_periode:${PH}`;
  const JP1 = `jeton_periode:${PH}`;
  const cloture = { org_id: ctx.org_id, journal_id: ctx.journal_id, period_start: ctx.p1.period_start, period_hash: PH, generated_at: ctx.p1.generated_at };
  // Mode journaux : le second journal et sa période précédente (close dans l'heure de la période 1 du premier, sans
  // point dans la file : aucune échéance ni cadence ne s'arme pour elle).
  // Une graine sur deux : journal-sinistres de la même organisation, ou journal-principal d'une autre (le premier tirage
  // de xorshift32 varie trop peu d'une graine à la suivante pour choisir).
  const J2 = m.journaux ? ctx.seconds[graine % 2] : null;
  const PH2 = J2 ? sha(`${J2.org_id}|${J2.journal_id}|periode-0`) : null;
  const vus = [];
  // Mode points2 : points du second journal dans la période 1 (empreintes tirées de son nom et du nom du point).
  const vus2 = [];
  const point2 = (p) => ({ ...p, checkpoint_hash: sha(`${J2.org_id}|${J2.journal_id}|${p.nom}`) });
  /** Demandes de période du journal tiré : le second avec la probabilité 1/2 en mode journaux (un tirage de plus), le premier sinon. */
  const periode = () => (J2 && r() < 0.5 ? { PH: PH2, OP: `ots_periode:${PH2}`, AP: `ancre_registre_periode:${PH2}`, JP: `jeton_periode:${PH2}`, journal: J2.nom, vus: [] } : { PH, OP: OP1, AP: AP1, JP: JP1, journal: ctx.journal, vus });
  const config = structuredClone(ctx.config);
  config.opentimestamps.min_responses = choix([2, 2, 2, 1]);
  // Mode reprises : tous les points ancrés ; attente de reprise courte ou longue (un tirage de plus).
  if (m.reprises) {
    config.registry.checkpoints = "tous";
    config.rfc3161.retry = { ...config.rfc3161.retry, initial_ms: choix([5000, 600000]), max_ms: 3600000 };
  }
  let t = A.ms("2026-11-03T13:59:00.000Z");
  let segment = 0;
  let trace = { version: 0, id: `confrontation-${graine}`, description: "parcours tiré", config, jitter_ms: Array.from({ length: 200 }, () => Math.floor(r() * 251)), queue_before: [], inputs: [], expected: [], queue_after: [] };
  const entree = (type, data = {}) => trace.inputs.push({ t: A.iso(t), type, data });
  const divergence = (d) => {
    const e = trace.inputs[d.entree];
    return { graine, mode, segment, entree: e ? `${e.t} ${e.type}` : null, ou: d.ou, indice: d.indice, reference: d.reference, composant: d.composant };
  };
  if (m.points) {
    t = A.ms("2026-11-03T13:40:00.000Z");
    entree("demarrage");
    // Mode journaux : clôture de la période précédente du second journal, avant l'un des points du premier.
    const avant = J2 ? choix(ctx.points) : null;
    for (const p of ctx.points) {
      if (p === avant) {
        t += choix([0, 1000, 30000]);
        entree("periode_close", { org_id: J2.org_id, journal_id: J2.journal_id, period_start: ctx.p1.period_start - 3600, period_hash: PH2, generated_at: A.iso(t) });
      }
      const fin = A.ms(p.checkpoint_ts);
      while (r() < 0.6 && vus.length) {
        const pas = Math.floor(r() * 240000);
        if (t + pas >= fin) break;
        t += pas;
        // Mode points2 : les réponses visent aussi les points du second journal (un tirage de plus).
        const deJ2 = m.points2 && vus2.length > 0 && r() < 0.5;
        const q = deJ2 ? choix(vus2) : choix(vus);
        const journalQ = deJ2 ? J2.nom : ctx.journal;
        const c2 = r();
        if (c2 < 0.3) entree("inclusion_registre", { request_id: `ancre_registre_point:${q.checkpoint_hash}`, block_number: 20000 + vus.length, capture_sha256: sha(`capture ${q.checkpoint_hash}`) });
        else if (c2 < 0.7) {
          const n = choix([1, 1, 2, 3]);
          if (r() < 0.6) entree("reponse_rfc3161", { request_id: `jeton_point:${q.checkpoint_hash}`, attempt: n, transport: "reponse", http_status: 200, pki_status: 0, failure_info: null, retry_after_s: null, nonce_in_response: nonceTsa("point", q.checkpoint_hash, n, journalQ), imprint_matches: true, checks_passed: [...T9], gen_time: A.iso(t - 1000).replace(/\.\d{3}Z$/, "Z"), accuracy_s: 1, token_sha256: sha(`jp${graine}-${t}`), token_size: 2104 });
          else entree("reponse_rfc3161", { request_id: `jeton_point:${q.checkpoint_hash}`, attempt: n, transport: "reponse", http_status: choix([503, 500, 408]), pki_status: null, failure_info: null, retry_after_s: null, nonce_in_response: null, imprint_matches: null, checks_passed: [], gen_time: null, accuracy_s: null, token_sha256: null, token_size: null });
        } else entree("tic");
      }
      // Mode reprises : le registre signale l'échec de l'ancre du dernier point admis juste avant ce point (s'il ne l'a
      // pas déjà fait), qui est ainsi admis pendant la reprise de cette ancre (EX-9.5, EX-9.4).
      if (m.reprises && vus.length && r() < 0.6 && t < fin - 1000) {
        t = fin - 1000;
        entree("echec_registre", { request_id: `ancre_registre_point:${vus.at(-1).checkpoint_hash}`, code: choix(["noeud_injoignable", "nonce_incoherent", "transaction_refusee", "recu_absent", "recu_absent"]) });
      }
      t = Math.max(t, fin);
      // Un point peut manquer (EX-4.1) : ses échéances restent ouvertes, ou sont servies par le suivant.
      if (r() < 0.8) {
        entree("point_produit", { org_id: ctx.org_id, journal_id: ctx.journal_id, period_start: ctx.p1.period_start, tree_size: p.tree_size, checkpoint_hash: p.checkpoint_hash, checkpoint_ts: p.checkpoint_ts });
        vus.push(p);
      }
      // Mode points2 : le point de même nom du second journal, au même instant (il peut manquer aussi).
      if (m.points2 && r() < 0.8) {
        const p2 = point2(p);
        entree("point_produit", { org_id: J2.org_id, journal_id: J2.journal_id, period_start: ctx.p1.period_start, tree_size: p2.tree_size, checkpoint_hash: p2.checkpoint_hash, checkpoint_ts: p2.checkpoint_ts });
        vus2.push(p2);
      }
    }
  } else entree("demarrage");
  t = Math.max(t, A.ms(ctx.p1.generated_at));
  entree("periode_close", cloture);
  let ancienne = false;
  const pas = 6 + Math.floor(r() * 20);
  for (let k = 0; k < pas; k++) {
    const c = r();
    t += choix([1000, 1000, 5000, 6000, 30000, 1800000, 21600000, 21601000]);
    const x = periode();
    if (c < 0.45) {
      const attestation = choix(["aucune", "en_attente", "en_attente", "complete"]);
      const preuve = r() < 0.75;
      entree("reponse_ots", { request_id: choix([x.OP, x.OP, x.OP, x.OP, x.OP, "ots_point:0x" + "ab".repeat(32)]), calendars_answered: choix([0, 1, 2, 2, 3]), attestation, proof_sha256: preuve ? sha(`p${graine}-${k}`) : null, proof_size: preuve ? 233 : null });
    } else if (c < 0.57 && m.rfc) {
      const n = choix([1, 1, 2, 3, 5, 99]);
      const id = choix([x.JP, x.JP, x.JP, x.OP, x.AP, "jeton_point:0x" + "cd".repeat(32)]);
      const v = r();
      if (v < 0.15) entree("reponse_rfc3161", { request_id: id, attempt: n, transport: choix(["delai", "erreur_transport"]), http_status: null, pki_status: null, failure_info: null, retry_after_s: null, nonce_in_response: null, imprint_matches: null, checks_passed: [], gen_time: null, accuracy_s: null, token_sha256: null, token_size: null });
      else if (v < 0.25) entree("reponse_rfc3161", { request_id: id, attempt: n, transport: "reponse", http_status: 200, pki_status: 2, failure_info: "unacceptedPolicy", retry_after_s: null, nonce_in_response: null, imprint_matches: null, checks_passed: [], gen_time: null, accuracy_s: null, token_sha256: null, token_size: null });
      else if (v < 0.6) entree("reponse_rfc3161", { request_id: id, attempt: n, transport: "reponse", http_status: 200, pki_status: 0, failure_info: null, retry_after_s: null, nonce_in_response: r() < 0.2 ? "0x0123456789abcdef" : nonceTsa("periode", x.PH, n, x.journal), imprint_matches: true, checks_passed: [...T9], gen_time: A.iso(t - 1000).replace(/\.\d{3}Z$/, "Z"), accuracy_s: 1, token_sha256: sha(`j${graine}-${k}`), token_size: 3082 });
      else entree("reponse_rfc3161", { request_id: id, attempt: n, transport: "reponse", http_status: 503, pki_status: null, failure_info: null, retry_after_s: null, nonce_in_response: null, imprint_matches: null, checks_passed: [], gen_time: null, accuracy_s: null, token_sha256: null, token_size: null });
    } else if (c < 0.61 && m.rfc) {
      entree("echec_registre", { request_id: choix([x.AP, x.AP, "ancre_registre_point:0x" + "ef".repeat(32)]), code: choix(["noeud_injoignable", "refus_gaz", "recu_absent"]) });
    } else if (c < 0.61) {
      entree("tic");
    } else if (c < 0.72) {
      // Reçu de l'ancre de la période, ou d'une ancre de point encore en vol (qui retient celle de la période, EX-9.4).
      const id = x.vus.length && r() < 0.4 ? `ancre_registre_point:${choix(x.vus).checkpoint_hash}` : x.AP;
      entree("inclusion_registre", { request_id: id, block_number: 21087, capture_sha256: sha(`capture ${id}`) });
    } else if (c < 0.82) {
      // Redémarrage : le segment est confronté ; la file relue est celle d'avant le segment plus ses lignes.
      entree("arret");
      const d = confronterSegment(ctx, trace);
      if (!d.ref) return divergence(d);
      let lignes = d.ref.lignes;
      if (m.coupe && r() < 0.6) lignes = lignes.slice(0, lignes.length - Math.floor(r() * Math.min(lignes.length + 1, 10)));
      const lus = A.lireFile([...trace.queue_before.map((x) => JSON.stringify(x)), ...lignes].map((l) => l + "\n").join(""));
      let q = lus.demandes;
      // Ligne d'une version antérieure du composant : a_reprendre portant encore une tentative en_cours (EX-8.12).
      if (!ancienne && r() < 0.3) {
        q = q.map((x) => {
          if (x.id !== OP1 || x.state !== "envoyee") return x;
          ancienne = true;
          return { ...x, state: "a_reprendre", due_at: A.iso(t) };
        });
      }
      segment += 1;
      trace = { ...trace, id: `confrontation-${graine}-${segment}`, queue_before: q, inputs: [], jitter_ms: Array.from({ length: 200 }, () => Math.floor(r() * 251)) };
      t += choix([1000, 30000, 600000]);
      entree("demarrage");
    } else {
      entree("tic");
    }
  }
  entree("arret");
  const d = confronterSegment(ctx, trace);
  return d.ref ? null : divergence(d);
}

/** Texte d'une divergence : graine, mode, segment, entrée, puis l'action (ou la ligne) des deux côtés. */
export function decrire(d) {
  const court = (x) => (x === null || x === undefined ? "rien" : typeof x === "string" ? x : JSON.stringify(x).slice(0, 400));
  return `graine ${d.graine} (mode ${d.mode}), segment ${d.segment}, entrée ${d.entree} : première divergence (${d.ou}, indice ${d.indice}) ; référence ${court(d.reference)} ; composant ${court(d.composant)}`;
}
