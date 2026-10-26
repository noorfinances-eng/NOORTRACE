#!/usr/bin/env node
// Générateur des vecteurs de CT-5 (spec/CT-5-ancrage.md, annexe A) :
// spec/vecteurs/ct-5/.
//
//   node scripts/vecteurs/generer-ct5.mjs [--sortie <répertoire ct-5>]
//   npm run vecteurs:ct5
//
// Familles (A.3, A.4) :
//
//   constantes.json   les constantes d'A.2 (identifiants, empreintes, étiquettes) ;
//   requetes/         TimeStampReq DER construites octet pour octet (EX-5.1), et
//                     les constructions refusées (AN-5, AN-6) ;
//   reponses/         TimeStampResp de l'autorité de test de CT-6 et réponses
//                     HTTP représentées, classées selon EX-5.10 à EX-5.12 ;
//   ots/              fichiers .ots en attente (EX-6.4), paire de mise à niveau
//                     (EX-6.6) sur les preuves de CT-6 ;
//   planification/    les douze traces normatives de §8.10, rejouées par
//                     scripts/lib/ancrage.mjs (rejouerTrace) ;
//   reprise/          files NDJSON avant et après le redémarrage de deux traces ;
//   cout/             les onze cas de la formule de coût (§12.3) ;
//   INDEX.md          chaque cas et son attendu.
//
// Tout est déterministe (EX-A.1) : aucune horloge ni valeur aléatoire ; les
// nonces, gigues et instants sont dérivés d'étiquettes ou fixés. Entrées lues
// et jamais réécrites (EX-A.2) : l'exemple de référence de CT-1 (lu dans
// spec/CT-1-evenements-et-formats.md), les manifestes de spec/vecteurs/ct-1,
// les clés et certificats de l'autorité de test de CT-6
// (spec/vecteurs/ct-6/rfc3161/cles) et les preuves
// spec/vecteurs/ct-6/ots/preuves/{o7-en-attente,periode-1}.ots. Le générateur
// n'efface et ne réécrit que ses propres entrées de premier niveau, jamais
// verificateur-independant/ ni confrontation/ ; il refuse, sans rien effacer,
// un répertoire de sortie qui porte une autre entrée.
//
// Chaque trace est validée contre spec/schemas/planificateur-ancrage-v0 et
// rejouée ; la trace de référence doit être identique, forme canonique pour
// forme canonique, à l'exemple de CT-5 §8.10. Les attendus de reponses/ sont
// ceux d'evaluerReponse, confrontés à la conception de chaque cas : un écart
// arrête la génération.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import * as A from "../lib/ancrage.mjs";
import * as H from "../lib/horodatage.mjs";
import * as J from "../lib/journal.mjs";
import * as O from "../lib/ots.mjs";
import { DOC_TYPE_PERIODE, anchorFingerprint, journalIdOf } from "../lib/noortrace.mjs";
import * as G from "./ct6/rfc3161.mjs";

const PROJECT_ROOT = fileURLToPath(new URL("../../", import.meta.url));
export const REPERTOIRE_CT5 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-5");
const REPERTOIRE_CT6 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-6");
const REPERTOIRE_CT1 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-1");
const SPEC_CT1 = path.join(PROJECT_ROOT, "spec", "CT-1-evenements-et-formats.md");
const SPEC_CT5 = path.join(PROJECT_ROOT, "spec", "CT-5-ancrage.md");
const SCHEMA_PLANIFICATEUR = path.join(PROJECT_ROOT, "spec", "schemas", "planificateur-ancrage-v0.schema.json");

/** Entrées de premier niveau jamais touchées (A.1). */
const CONSERVEES = new Set(["verificateur-independant", "confrontation"]);
/** Entrées que le générateur écrit : seules elles sont effacées avant une génération. */
const ENTREES_GENEREES = ["INDEX.md", "constantes.json", "requetes", "reponses", "ots", "planification", "reprise", "cout", "completude"];

const texteJSON = (v) => JSON.stringify(v, null, 2) + "\n";
const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
const sha256Hex = (b) => "0x" + sha256(b).toString("hex");
const exiger = (condition, message) => {
  if (!condition) throw new Error(`generer-ct5 : ${message}`);
};
const JOURNAL = "journal-principal";

// ---------------------------------------------------------------------------
// Constantes (A.2) : l'exemple de référence de CT-1
// ---------------------------------------------------------------------------

export const ORG_ID = "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab";
export const JOURNAL_ID = journalIdOf(JOURNAL);
export const PERIOD_START_1 = 1793710800;
export const PERIOD_START_2 = 1793714400;
export const PERIOD_HASH_1 = "0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1";
export const GENERATED_AT_1 = "2026-11-03T14:00:00.250Z";
export const GENERATED_AT_2 = "2026-11-03T15:00:00.112Z";
/** Points K1 à K6 de CT-1 §10.8 : checkpointHash, tree_size, checkpoint_ts, période. */
export const POINTS = {
  K1: { hash: "0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4", tree_size: 2, ts: "2026-11-03T13:42:00.000Z", periode: 1 },
  K2: { hash: "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff", tree_size: 4, ts: "2026-11-03T13:53:00.000Z", periode: 1 },
  K3: { hash: "0x3feb86ac4d6d8c054bef224f131f0276d2f1c9c9db2a6ce06adec173378d8867", tree_size: 4, ts: "2026-11-03T13:54:00.000Z", periode: 1 },
  K4: { hash: "0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107", tree_size: 5, ts: "2026-11-03T14:00:00.250Z", periode: 1 },
  K5: { hash: "0x3c4bd86148138e52a1ef6912c7ab4fa98ffdaf90879900887833e726b5a9e153", tree_size: 0, ts: "2026-11-03T14:01:00.000Z", periode: 2 },
  K6: { hash: "0xd6e22871885b68962dadee69f9fa2ff3a76949d23550d1682d3564bcc705474d", tree_size: 0, ts: "2026-11-03T15:00:00.112Z", periode: 2 },
};
/** Empreintes d'ancre des points K1 à K4 (A.2). */
const EMPREINTES_A2 = {
  K1: "0xd0cd916d070ecb8c2af3a3b62b933ccd6e61fd481ea2b70312ab988fabac8540",
  K2: "0x7f721a4526c614882ff41ac33792c6d05fa7fb6dd98bc1c369d0e277029f4e44",
  K3: "0xa1aeb874daa988a4833c394476c4ea740096a3496ed081ae6f8592fb4912a837",
  K4: "0xa7f0a30f11f724f5ae4bd7ba952079fa513dfe0ed70c051bdfc5bbe9c67b3792",
};
const ETIQUETTE_NONCE_CT1 = "noortrace/vecteurs/v0/ct-1/nonce-tsa/point-de-controle/exemple";
const NONCE_CT1 = "0x74a6f4979421411e";
// Unités symboliques de la formule de coût (A.2) : p_q, p_s, F, Q ; jamais un prix (AN-60). Les clés des cas de
// `cout/` sont celles du schéma ($defs/cas_cout) ; constantes.json les porte sous leurs noms de la section 12.
const PRIX_SYMBOLIQUES = { unit_price_qualified: 1, unit_price_second_rank: 0.2, subscription_fee: 10000, subscription_quota: 10000 };

/** Les blocs JSON annotés `<!-- schema: … -->` d'une spécification. */
function blocsSpec(fichier, marque) {
  const md = fs.readFileSync(fichier, "utf8");
  const re = new RegExp(`<!-- schema: ${marque} -->\\n\`\`\`json\\n([\\s\\S]*?)\\n\`\`\``, "g");
  const out = [];
  let m;
  while ((m = re.exec(md))) out.push(J.analyserJSONStrict(m[1]));
  return out;
}

/** L'exemple de référence de CT-1 : manifestes des périodes 1 et 2, points K2 et K5 annotés ; contrôle des constantes. */
function exempleCT1() {
  const manifestes = blocsSpec(SPEC_CT1, "manifeste");
  exiger(manifestes.length === 2, "deux manifestes annotés attendus dans CT-1");
  const [m1, m2] = manifestes;
  exiger(m1.period_start === PERIOD_START_1 && m2.period_start === PERIOD_START_2, "périodes de l'exemple de CT-1");
  exiger(J.hachageManifeste(m1) === PERIOD_HASH_1, "periodHash de la période 1 de l'exemple de CT-1 (A.2)");
  const periodHash2 = J.hachageManifeste(m2);
  exiger(m1.generated_at === GENERATED_AT_1 && m2.generated_at === GENERATED_AT_2, "generated_at de l'exemple de CT-1");
  exiger(m1.org_id === ORG_ID && m1.journal_id === JOURNAL_ID, "identifiants du journal de référence");
  const points = blocsSpec(SPEC_CT1, "point-de-controle");
  for (const p of points) {
    const h = J.hachagePointDeControle(p);
    const nom = Object.keys(POINTS).find((k) => POINTS[k].hash === h);
    exiger(nom && POINTS[nom].tree_size === p.tree_size && POINTS[nom].ts === p.checkpoint_ts, `point annoté de CT-1 (${p.checkpoint_ts}) absent de la table K1 à K6`);
  }
  for (const [nom, e] of Object.entries(EMPREINTES_A2)) exiger(J.empreinteAncrePoint(ORG_ID, JOURNAL_ID, POINTS[nom].hash) === e, `empreinte d'ancre de ${nom} (A.2)`);
  exiger(A.hexNonce(A.nonceDepuisEtiquette(ETIQUETTE_NONCE_CT1)) === NONCE_CT1, "nonce de CT-1 §13");
  return { manifestes: { 1: m1, 2: m2 }, periodHash: { 1: PERIOD_HASH_1, 2: periodHash2 }, generatedAt: { 1: GENERATED_AT_1, 2: GENERATED_AT_2 } };
}

// ---------------------------------------------------------------------------
// Configurations des traces (projection d'EX-8.2)
// ---------------------------------------------------------------------------

const PRESTATAIRES = {
  principal: { id: "qtsa-principal", role: "principal", policy_oid: null, qualified: true, min_interval_ms: 0, request_timeout_ms: 10000 },
  secours: { id: "qtsa-secours", role: "secours", policy_oid: null, qualified: true, min_interval_ms: 0, request_timeout_ms: 10000 },
  interne: { id: "tsa-interne", role: "interne", policy_oid: A.POLITIQUE_TEST, qualified: false, min_interval_ms: 0, request_timeout_ms: 5000 },
  second_rang: { id: "tsa-second-rang", role: "second_rang", policy_oid: null, qualified: false, min_interval_ms: 0, request_timeout_ms: 10000 },
};

/** La configuration de la trace de référence, avec des variations. */
export function configuration({ prestataires = ["principal", "secours", "interne"], provider_role = "interne", countersign_idle = false, min_interval = {}, retry = {}, registry = {}, opentimestamps = {}, upgrade = {}, queue = {} } = {}) {
  return {
    checkpoint_interval_s: 60,
    rfc3161: {
      providers: prestataires.map((r) => ({ ...PRESTATAIRES[r], min_interval_ms: min_interval[r] ?? PRESTATAIRES[r].min_interval_ms })),
      manifest: { fallback_after_s: 300 },
      checkpoints: { interval_s: 300, provider_role, fallback_after_s: 120, countersign_idle },
      freshness: { max_response_delay_s: 60, clock_tolerance_s: 120 },
      retry: { initial_ms: 5000, factor: 2, max_ms: 300000, jitter_ms: 250, ...retry },
    },
    registry: { checkpoints: "nouveaux_evenements", squat_wait_s: 5, inclusion_alert_s: 60, ...registry },
    opentimestamps: { enabled: true, calendars: [...A.CALENDRIERS_VECTEURS], min_responses: 2, timeout_ms: 5000, checkpoint: "aucun", ...opentimestamps, upgrade: { first_after_s: 21600, interval_s: 1800, give_up_after_s: 1209600, ...upgrade } },
    queue: { max_pending: 100000, anchor_pending_alert_s: 7200, ...queue },
  };
}

// ---------------------------------------------------------------------------
// Traces (§8.10) : scénarios dont le planificateur de référence calcule l'attendu
// ---------------------------------------------------------------------------

const T9 = ["T-1", "T-2", "T-3", "T-4", "T-5", "T-6", "T-7", "T-8", "T-9"];
const plusMs = (t, ms) => A.iso(A.ms(t) + ms);
const sansFraction = (t) => t.replace(/\.000Z$/, "Z");
const shaTexte = (texte) => sha256Hex(Buffer.from(texte, "utf8"));
const nonceDe = (sorte, hash, n) => A.hexNonce(A.nonceDepuisEtiquette(A.ETIQUETTES.nonceTsa({ journal: JOURNAL, sorte, hash, n })));
const sujetPeriode = (ex, n) => ({ org_id: ORG_ID, journal_id: JOURNAL_ID, period_start: n === 1 ? PERIOD_START_1 : PERIOD_START_2, period_hash: ex.periodHash[n], generated_at: ex.generatedAt[n] });

/**
 * Séries de points du journal des vecteurs (journal-sinistres, CT-1 §13) : lues
 * dans spec/vecteurs/ct-1/points-de-controle/periode-<n>.json (EX-A.2), un point
 * par minute aligné sur period_start et le point de clôture ; checkpointHash
 * recalculé (CT-1 §10.6).
 */
export function serieSinistres(n) {
  const points = J.analyserJSONStrict(fs.readFileSync(path.join(REPERTOIRE_CT1, "points-de-controle", `periode-${n}.json`)));
  return points.map((p) => ({ org_id: p.org_id, journal_id: p.journal_id, period_start: p.period_start, tree_size: p.tree_size, checkpoint_hash: J.hachagePointDeControle(p), checkpoint_ts: p.checkpoint_ts, point: p }));
}
/** Le manifeste de la période n du journal des vecteurs (spec/vecteurs/ct-1/manifestes/periode-<n>.json), en données de periode_close. */
export function clotureSinistres(n) {
  const m = J.analyserJSONStrict(fs.readFileSync(path.join(REPERTOIRE_CT1, "manifestes", `periode-${n}.json`)));
  return { org_id: m.org_id, journal_id: m.journal_id, period_start: m.period_start, period_hash: J.hachageManifeste(m), generated_at: m.generated_at };
}
const donneesPoint = (p) => ({ org_id: p.org_id, journal_id: p.journal_id, period_start: p.period_start, tree_size: p.tree_size, checkpoint_hash: p.checkpoint_hash, checkpoint_ts: p.checkpoint_ts });
const minute = (p) => p.checkpoint_ts.slice(11, 16);

class Scenario {
  constructor(id, description, config, { jitter = [], queue_before = [] } = {}) {
    this.trace = { version: 0, id, description, config, jitter_ms: jitter, queue_before, inputs: [], expected: [], queue_after: [] };
  }
  entree(t, type, data = {}) {
    this.trace.inputs.push({ t, type, data });
    return this;
  }
  demarrage(t) {
    return this.entree(t, "demarrage");
  }
  tic(t) {
    return this.entree(t, "tic");
  }
  arret(t) {
    return this.entree(t, "arret");
  }
  point(nom, { t = null } = {}) {
    const p = POINTS[nom];
    return this.entree(t ?? p.ts, "point_produit", { org_id: ORG_ID, journal_id: JOURNAL_ID, period_start: p.periode === 1 ? PERIOD_START_1 : PERIOD_START_2, tree_size: p.tree_size, checkpoint_hash: p.hash, checkpoint_ts: p.ts });
  }
  cloture(ex, n) {
    return this.entree(ex.generatedAt[n], "periode_close", sujetPeriode(ex, n));
  }
  /** Point d'une série du journal des vecteurs (serieSinistres), admis à son checkpoint_ts. */
  pointSerie(p, { t = null } = {}) {
    return this.entree(t ?? p.checkpoint_ts, "point_produit", donneesPoint(p));
  }
  /** Clôture d'une période du journal des vecteurs (clotureSinistres). */
  clotureSerie(c) {
    return this.entree(c.generated_at, "periode_close", c);
  }
  /** Objets durables sans ancre obtenue relus dans le stockage (EX-8.12). */
  stockage(t, { periods = [], checkpoints = [] }) {
    return this.entree(t, "stockage_relu", { periods, checkpoints: checkpoints.map(donneesPoint) });
  }
  inclusion(t, request_id, bloc) {
    return this.entree(t, "inclusion_registre", { request_id, block_number: bloc, capture_sha256: shaTexte(`capture ${request_id} ${bloc}`) });
  }
  echecRegistre(t, request_id, code) {
    return this.entree(t, "echec_registre", { request_id, code });
  }
  /** Réponse granted d'un prestataire : jeton représenté par SHA-256("jeton <nom>"). */
  granted(t, request_id, attempt, { gen_time, nom, accuracy_s = 1, size = 2104, nonce = null, pki_status = 0, journal = JOURNAL, extra = {} }) {
    const [kind, hash] = [request_id.split(":")[0], request_id.split(":")[1]];
    return this.entree(t, "reponse_rfc3161", {
      request_id,
      attempt,
      transport: "reponse",
      http_status: 200,
      pki_status,
      failure_info: null,
      retry_after_s: null,
      nonce_in_response: nonce ?? A.hexNonce(A.nonceDepuisEtiquette(A.ETIQUETTES.nonceTsa({ journal, sorte: kind === "jeton_point" ? "point" : "periode", hash, n: attempt }))),
      imprint_matches: true,
      checks_passed: [...T9],
      gen_time: sansFraction(gen_time),
      accuracy_s,
      token_sha256: shaTexte(`jeton ${nom}`),
      token_size: size,
      ...extra,
    });
  }
  /** Réponse en échec : transport, HTTP ou PKIStatus. */
  echec(t, request_id, attempt, { transport = "reponse", http_status = null, pki_status = null, failure_info = null, retry_after_s = null, extra = {} }) {
    return this.entree(t, "reponse_rfc3161", { request_id, attempt, transport, http_status: transport === "reponse" ? http_status ?? 200 : null, pki_status, failure_info, retry_after_s, nonce_in_response: null, imprint_matches: null, checks_passed: [], gen_time: null, accuracy_s: null, token_sha256: null, token_size: null, ...extra });
  }
  ots(t, request_id, { attestation = "en_attente", calendars_answered = 2, nom = null, size = 233 }) {
    return this.entree(t, "reponse_ots", { request_id, calendars_answered, attestation, proof_sha256: nom ? shaTexte(`preuve ${nom}`) : null, proof_size: nom ? size : null });
  }
  construire() {
    const r = A.rejouerTrace(this.trace);
    this.trace.expected = r.actions;
    this.trace.queue_after = r.file;
    this.lignes = r.lignes;
    return this.trace;
  }
}

const ID = (kind, hash) => `${kind}:${hash}`;
const ANCRE = (nom) => ID("ancre_registre_point", POINTS[nom].hash);
const JETON = (nom) => ID("jeton_point", POINTS[nom].hash);

/** Une demande de file, dans l'ordre des clés du schéma ($defs/demande). */
function demande({ kind, sujet, deadlines = [], state, created_at, due_at = null, attempts = [], result = null, replaced_by = null }) {
  return { version: 0, id: ID(kind, sujet.hash), kind, subject: sujet, deadlines, state, created_at, due_at, attempts, result, replaced_by };
}
const sujetPoint = (nom) => ({ kind: "point", org_id: ORG_ID, journal_id: JOURNAL_ID, period_start: POINTS[nom].periode === 1 ? PERIOD_START_1 : PERIOD_START_2, hash: POINTS[nom].hash, tree_size: POINTS[nom].tree_size, declared_at: POINTS[nom].ts });
const tentative = ({ n, provider = null, started_at, nonce = null, kind, hash, outcome = "en_cours", error_code = null, http_status = null, pki_status = null, failure_info = null, retry_after_s = null, next_at = null, detail }) => ({ n, provider, started_at, nonce, correlation_id: A.identifiantCorrelation(kind, hash, n), outcome, error_code, http_status, pki_status, failure_info, retry_after_s, next_at, detail });

/** Les douze traces normatives (A.3), dans l'ordre d'A.3. */
export function traces(ex) {
  const liste = [];
  const ajouter = (s, controles) => {
    const trace = s.construire();
    let resultats;
    try {
      resultats = controles(trace);
    } catch (e) {
      resultats = [[`contrôles inévaluables (${e.message})`, false]];
    }
    for (const [description, ok] of resultats) {
      if (!ok && process.env.GENERER_CT5_DEBUG) fs.writeFileSync(path.join(process.env.GENERER_CT5_DEBUG, `${trace.id}.debug.json`), texteJSON(trace));
      exiger(ok, `trace ${trace.id} : ${description}`);
    }
    liste.push({ trace, lignes: s.lignes });
  };
  const actions = (trace, action, pred = () => true) => trace.expected.filter((a) => a.action === action && pred(a));
  const dem = (trace, id) => trace.queue_after.find((d) => d.id === id);
  const PH1 = ID("jeton_periode", ex.periodHash[1]);
  const AP1 = ID("ancre_registre_periode", ex.periodHash[1]);
  const OP1 = ID("ots_periode", ex.periodHash[1]);
  const PH2 = ID("jeton_periode", ex.periodHash[2]);
  const AP2 = ID("ancre_registre_periode", ex.periodHash[2]);
  const OP2 = ID("ots_periode", ex.periodHash[2]);

  // 1. heure-nominale-reference : la trace de CT-5 §8.10, reconstruite depuis ses entrées.
  {
    const s = new Scenario(
      "heure-nominale-reference",
      "Période 1 de l'exemple de référence de CT-1 (annexe A de CT-1) : points K1 à K4 de CT-1 §10.8, clôture à 14:00:00.250Z ; échéances D_1 à D_11 toutes les 300 s, la clôture tenant lieu de D_12 (EX-4.2, EX-4.3) ; registre, prestataire principal, serveur interne pour les points et calendriers tous joignables ; aucune reprise. Les réponses des prestataires sont des entrées de la trace (jetons représentés par leur SHA-256) ; l'horloge est injectée.",
      configuration(),
    );
    s.demarrage("2026-11-03T13:40:00.000Z").point("K1").inclusion("2026-11-03T13:42:03.000Z", ANCRE("K1"), 20001).granted("2026-11-03T13:42:05.000Z", JETON("K1"), 1, { gen_time: "2026-11-03T13:42:04Z", nom: "K1" });
    s.tic("2026-11-03T13:45:00.000Z").tic("2026-11-03T13:50:00.000Z").point("K2").inclusion("2026-11-03T13:53:02.000Z", ANCRE("K2"), 20660).granted("2026-11-03T13:53:04.000Z", JETON("K2"), 1, { gen_time: "2026-11-03T13:53:03Z", nom: "K2" });
    s.point("K3").tic("2026-11-03T13:55:00.000Z").point("K4").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" });
    s.inclusion("2026-11-03T14:00:02.000Z", ANCRE("K4"), 21085).granted("2026-11-03T14:00:03.000Z", JETON("K4"), 1, { gen_time: "2026-11-03T14:00:02Z", nom: "K4" });
    s.inclusion("2026-11-03T14:00:04.000Z", AP1, 21087).granted("2026-11-03T14:00:05.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:05Z", nom: "periode 1", size: 3082 }).arret("2026-11-03T14:01:00.000Z");
    ajouter(s, (t) => [
      ["88 actions et 9 demandes", t.expected.length === 88 && t.queue_after.length === 9],
      ["écriture de la ligne envoyee avant chaque envoi (EX-8.5, règle 1)", t.expected.every((a, i) => !["envoyer_rfc3161", "envoyer_registre", "soumettre_ots"].includes(a.action) || (t.expected[i - 1]?.action === "ecrire_file" && t.expected[i - 1].request_id === a.request_id && t.expected[i - 1].detail.state === "envoyee"))],
      ["point_manquant à 13:44 et 13:56 (série volontairement creuse, EX-8.15)", JSON.stringify(actions(t, "alerter", (a) => a.detail.code === "point_manquant").map((a) => a.t)) === JSON.stringify(["2026-11-03T13:44:00.000Z", "2026-11-03T13:56:00.000Z"])],
      ["K1 satisfait D_1 à D_8", JSON.stringify(dem(t, JETON("K1")).deadlines) === "[1,2,3,4,5,6,7,8]" && dem(t, JETON("K1")).state === "obtenue"],
      ["K3 ni ancré ni contresigné", actions(t, "journaliser", (a) => a.detail.event === "checkpoint_not_anchored").length === 1 && !dem(t, JETON("K3"))],
      ["tailles des requêtes 82, 81, 82, 70", JSON.stringify(actions(t, "envoyer_rfc3161").map((a) => a.detail.request_size)) === "[82,81,82,70]"],
    ]);
  }

  // 2. principal-injoignable : erreurs de transport, 503 avec Retry-After, 408 immédiat, attentes, relève, jeton du secours, réponse tardive conservée.
  {
    const s = new Scenario(
      "principal-injoignable",
      "Clôture de la période 1 de référence ; le prestataire principal ne répond pas : erreur de transport, 503 avec Retry-After 30 s, 408 rejoué immédiatement une fois, délai d'attente, 503 sans Retry-After ; attentes d'EX-8.9 (5 s + 100 ms de gigue, Retry-After 30 s, 0 s, 40 s + 200 ms, 80 s + 50 ms) ; relève par le secours 300 s après la première tentative (manifest.fallback_after_s, EX-8.8), jeton promu du secours ; la réponse tardive du principal à la tentative 6 est conservée sans être promue (EX-5.8, EX-8.5).",
      configuration(),
      { jitter: [100, 200, 50] },
    );
    s.demarrage("2026-11-03T13:59:00.000Z").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" }).inclusion("2026-11-03T14:00:02.000Z", AP1, 21087);
    s.echec("2026-11-03T14:00:12.000Z", PH1, 1, { transport: "erreur_transport" });
    s.echec("2026-11-03T14:00:17.600Z", PH1, 2, { http_status: 503, retry_after_s: 30 });
    s.echec("2026-11-03T14:00:48.000Z", PH1, 3, { http_status: 408 });
    s.echec("2026-11-03T14:00:58.000Z", PH1, 4, { transport: "delai" });
    s.echec("2026-11-03T14:01:39.000Z", PH1, 5, { http_status: 503 });
    s.granted("2026-11-03T14:05:04.000Z", PH1, 7, { gen_time: "2026-11-03T14:05:03Z", nom: "periode 1 secours", size: 3082 });
    s.granted("2026-11-03T14:05:40.000Z", PH1, 6, { gen_time: "2026-11-03T14:05:39Z", nom: "periode 1 tardif principal", size: 3082 });
    s.arret("2026-11-03T14:06:00.000Z");
    ajouter(s, (t) => [
      ["raisons des attentes : backoff, retry_after, immediat, backoff, backoff", JSON.stringify(actions(t, "programmer", (a) => a.request_id === PH1 && ["backoff", "retry_after", "immediat"].includes(a.detail.reason)).map((a) => a.detail.reason)) === JSON.stringify(["backoff", "retry_after", "immediat", "backoff", "backoff"])],
      ["instants des reprises", JSON.stringify(actions(t, "envoyer_rfc3161", (a) => a.request_id === PH1).map((a) => a.t)) === JSON.stringify(["2026-11-03T14:00:02.000Z", "2026-11-03T14:00:17.100Z", "2026-11-03T14:00:47.600Z", "2026-11-03T14:00:48.000Z", "2026-11-03T14:01:38.200Z", "2026-11-03T14:02:59.050Z", "2026-11-03T14:05:02.000Z"])],
      ["relève par le secours à 14:05:02", actions(t, "releve").length === 1 && actions(t, "releve")[0].t === "2026-11-03T14:05:02.000Z" && actions(t, "releve")[0].detail.provider === "qtsa-secours"],
      ["jeton promu du secours", dem(t, PH1).state === "obtenue" && dem(t, PH1).result.provider === "qtsa-secours"],
      ["réponse tardive du principal conservée, non promue", actions(t, "stocker", (a) => a.t === "2026-11-03T14:05:40.000Z").length === 1 && dem(t, PH1).result.sha256 === shaTexte("jeton periode 1 secours")],
    ]);
  }

  // 3. refus-permanent-releve : unacceptedPolicy du principal (relève immédiate), unacceptedPolicy du second rang (refus du point, aucune relève).
  {
    const s = new Scenario(
      "refus-permanent-releve",
      "Points contresignés par un prestataire de second rang : K1 reçoit PKIStatus 2 unacceptedPolicy, erreur permanente sans relève pour ce rôle (EX-5.7, EX-8.8) : demande refusee, alerte prestataires_epuises ; la demande refusée ne compte plus comme contresignée et rend la main à ses échéances D_1 à D_8 (EX-4.3, EX-8.4 règle 1) : K4, premier point qui suit, est contresigné pour D_1 à D_11 en une requête. À la clôture, le principal répond unacceptedPolicy : relève immédiate par le secours (la demande repasse a_envoyer, EX-8.3), aucune réexpédition de la requête refusée (EX-5.12).",
      configuration({ prestataires: ["principal", "secours", "second_rang"], provider_role: "second_rang" }),
    );
    s.demarrage("2026-11-03T13:40:00.000Z").point("K1").inclusion("2026-11-03T13:42:03.000Z", ANCRE("K1"), 20001);
    s.echec("2026-11-03T13:42:05.000Z", JETON("K1"), 1, { pki_status: 2, failure_info: "unacceptedPolicy" });
    s.tic("2026-11-03T13:45:00.000Z").tic("2026-11-03T13:50:00.000Z").tic("2026-11-03T13:55:00.000Z").point("K4").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" });
    s.inclusion("2026-11-03T14:00:02.000Z", ANCRE("K4"), 21085).granted("2026-11-03T14:00:03.000Z", JETON("K4"), 1, { gen_time: "2026-11-03T14:00:02Z", nom: "K4 second rang" });
    s.inclusion("2026-11-03T14:00:04.000Z", AP1, 21087).echec("2026-11-03T14:00:05.000Z", PH1, 1, { pki_status: 2, failure_info: "unacceptedPolicy" });
    s.granted("2026-11-03T14:00:06.000Z", PH1, 2, { gen_time: "2026-11-03T14:00:06Z", nom: "periode 1 secours", size: 3082 }).arret("2026-11-03T14:01:00.000Z");
    ajouter(s, (t) => [
      ["K1 refusé sans relève", dem(t, JETON("K1")).state === "refusee" && actions(t, "alerter", (a) => a.detail.code === "prestataires_epuises").length === 1 && actions(t, "releve").length === 1],
      ["K1 refusé rend ses échéances : K4 sert D_1 à D_11, aucune échéance remplacée", JSON.stringify(dem(t, JETON("K4")).deadlines) === "[1,2,3,4,5,6,7,8,9,10,11]" && actions(t, "echeance", (a) => a.detail.state === "remplacee").length === 0],
      ["relève immédiate par le secours à 14:00:05", actions(t, "releve")[0].t === "2026-11-03T14:00:05.000Z" && actions(t, "envoyer_rfc3161", (a) => a.request_id === PH1 && a.detail.provider === "qtsa-principal").length === 1],
      ["jeton de clôture du secours", dem(t, PH1).state === "obtenue" && dem(t, PH1).result.provider === "qtsa-secours"],
    ]);
  }

  // 4. reponse-tardive : période 2 (preuve de vie sans contresignature), deux réponses tardives puis la troisième promue avec avertissement.
  {
    const s = new Scenario(
      "reponse-tardive",
      "Période 2 de l'exemple de référence (points K5 et K6 sans nouvel événement, tree_size 0) : aucun point ancré ni contresigné, les onze échéances sont closes sans_objet au point de clôture (EX-4.3, countersign_idle faux). Le jeton de clôture arrive trois fois plus de max_response_delay_s (60 s) après l'envoi : les deux premières réponses sont conservées sans être promues et rejouées avec un nouveau nonce, la troisième est promue avec l'avertissement reponse_tardive (EX-5.11).",
      configuration(),
      { jitter: [0, 0] },
    );
    s.demarrage("2026-11-03T14:00:30.000Z").point("K5");
    for (let k = 1; k <= 11; k++) s.tic(A.iso((PERIOD_START_2 + 300 * k) * 1000));
    s.point("K6").cloture(ex, 2).ots("2026-11-03T15:00:01.000Z", OP2, { nom: "en attente periode 2" }).inclusion("2026-11-03T15:00:02.000Z", AP2, 24700);
    s.granted("2026-11-03T15:01:03.000Z", PH2, 1, { gen_time: "2026-11-03T15:01:02Z", nom: "periode 2 tardif 1", size: 3082 });
    s.granted("2026-11-03T15:02:09.000Z", PH2, 2, { gen_time: "2026-11-03T15:02:08Z", nom: "periode 2 tardif 2", size: 3082 });
    s.granted("2026-11-03T15:03:20.000Z", PH2, 3, { gen_time: "2026-11-03T15:03:19Z", nom: "periode 2 tardif 3", size: 3082 }).arret("2026-11-03T15:04:00.000Z");
    ajouter(s, (t) => [
      ["onze échéances sans_objet", actions(t, "echeance", (a) => a.detail.state === "sans_objet").length === 11],
      ["deux rejets reponse_tardive", actions(t, "rejeter_reponse", (a) => a.detail.error_code === "reponse_tardive").length === 2],
      ["troisième réponse promue avec avertissement", dem(t, PH2).state === "obtenue" && actions(t, "journaliser", (a) => a.detail.event === "period_timestamped")[0].detail.warnings?.[0] === "reponse_tardive"],
      ["aucun point ancré", actions(t, "envoyer_registre").length === 1],
    ]);
  }

  // 5. horloge-suspecte : genTime à plus de clock_tolerance_s de l'envoi, jeton promu avec avertissement et alerte.
  {
    const s = new Scenario(
      "horloge-suspecte",
      "Comme la trace de référence, sans K2 ni K3 : le serveur interne répond pour K1 avec un genTime de 13:45:10 alors que la requête est partie à 13:42:03, soit 187 s d'écart, au-delà de clock_tolerance_s (120 s) : le jeton est promu, marqué horloge_suspecte, et l'alerte est levée (EX-5.11) ; d_jeton se lit sur la borne du jeton. K4 satisfait D_9 à D_11.",
      configuration(),
    );
    s.demarrage("2026-11-03T13:40:00.000Z").point("K1").inclusion("2026-11-03T13:42:03.000Z", ANCRE("K1"), 20001).granted("2026-11-03T13:42:05.000Z", JETON("K1"), 1, { gen_time: "2026-11-03T13:45:10Z", nom: "K1 horloge" });
    s.tic("2026-11-03T13:45:00.000Z").tic("2026-11-03T13:50:00.000Z").tic("2026-11-03T13:55:00.000Z").point("K4").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" });
    s.inclusion("2026-11-03T14:00:02.000Z", ANCRE("K4"), 21085).granted("2026-11-03T14:00:03.000Z", JETON("K4"), 1, { gen_time: "2026-11-03T14:00:02Z", nom: "K4" });
    s.inclusion("2026-11-03T14:00:04.000Z", AP1, 21087).granted("2026-11-03T14:00:05.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:05Z", nom: "periode 1", size: 3082 }).arret("2026-11-03T14:01:00.000Z");
    ajouter(s, (t) => [
      ["avertissement et alerte horloge_suspecte", actions(t, "alerter", (a) => a.detail.code === "horloge_suspecte").length === 1 && actions(t, "journaliser", (a) => a.detail.event === "checkpoint_countersigned" && a.detail.warnings?.[0] === "horloge_suspecte").length === 1],
      ["jeton promu, d_jeton 311 s", dem(t, JETON("K1")).state === "obtenue" && actions(t, "journaliser", (a) => a.detail.event === "checkpoint_countersigned")[0].detail.d_jeton_s === 311],
      ["K4 pour D_9 à D_11", JSON.stringify(dem(t, JETON("K4")).deadlines) === "[9,10,11]"],
    ]);
  }

  // 6. echeance-remplacee : serveur interne injoignable, aucun rattrapage, fenêtre observée.
  {
    const s = new Scenario(
      "echeance-remplacee",
      "Le serveur interne ne répond pas à la requête de K1 (délai d'attente à chaque tentative ; retry.initial_ms porté à 60 s pour raccourcir la trace : attentes 60, 120, 240 puis 300 s plafonnées, gigue nulle) ; K2 est contresigné pour D_9 et D_10 : la demande de K1 et ses échéances D_1 à D_8 passent remplacee, la ligne checkpoint_anchor_late porte la fenêtre observée (borne du jeton de K2 moins D_1) et l'alerte est mineure pour le serveur interne (EX-4.4, EX-8.4). Aucun rattrapage des points ; la clôture est servie normalement.",
      configuration({ retry: { initial_ms: 60000 } }),
      { jitter: [0, 0, 0, 0] },
    );
    s.demarrage("2026-11-03T13:40:00.000Z").point("K1").inclusion("2026-11-03T13:42:03.000Z", ANCRE("K1"), 20001);
    s.echec("2026-11-03T13:42:08.000Z", JETON("K1"), 1, { transport: "delai" });
    s.echec("2026-11-03T13:43:13.000Z", JETON("K1"), 2, { transport: "delai" });
    s.tic("2026-11-03T13:45:00.000Z");
    s.echec("2026-11-03T13:45:18.000Z", JETON("K1"), 3, { transport: "delai" });
    s.echec("2026-11-03T13:49:23.000Z", JETON("K1"), 4, { transport: "delai" });
    s.tic("2026-11-03T13:50:00.000Z").point("K2").inclusion("2026-11-03T13:53:02.000Z", ANCRE("K2"), 20660).granted("2026-11-03T13:53:04.000Z", JETON("K2"), 1, { gen_time: "2026-11-03T13:53:03Z", nom: "K2" });
    s.point("K3").tic("2026-11-03T13:55:00.000Z").point("K4").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" });
    s.inclusion("2026-11-03T14:00:02.000Z", ANCRE("K4"), 21085).granted("2026-11-03T14:00:03.000Z", JETON("K4"), 1, { gen_time: "2026-11-03T14:00:02Z", nom: "K4" });
    s.inclusion("2026-11-03T14:00:04.000Z", AP1, 21087).granted("2026-11-03T14:00:05.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:05Z", nom: "periode 1", size: 3082 }).arret("2026-11-03T14:01:00.000Z");
    ajouter(s, (t) => [
      ["quatre tentatives pour K1 puis plus aucune", actions(t, "envoyer_rfc3161", (a) => a.request_id === JETON("K1")).length === 4],
      ["attentes 60, 120, 240, 300 s", JSON.stringify(actions(t, "programmer", (a) => a.request_id === JETON("K1") && a.detail.reason === "backoff").map((a) => A.ms(a.detail.next_at) - A.ms(a.t))) === "[60000,120000,240000,300000]"],
      ["K1 remplacée par K2, fenêtre 2884 s, alerte mineure", dem(t, JETON("K1")).state === "remplacee" && dem(t, JETON("K1")).replaced_by === JETON("K2") && actions(t, "journaliser", (a) => a.detail.event === "checkpoint_anchor_late")[0].detail.window_s === 2884 && actions(t, "alerter", (a) => a.detail.code === "checkpoint_anchor_late")[0].detail.severity === "mineure"],
      ["huit échéances remplacées", actions(t, "echeance", (a) => a.detail.state === "remplacee").length === 8],
    ]);
  }

  // 7. registre-indisponible : redémarrage avec une ancre de point sans reçu (squat_wait_s puis ordre_ancres_non_respecte, renvois, empreinte squattée), ancre de période sans reçu (registry_pending, inclusion_late, anchor_pending).
  {
    const fileAvant = [
      demande({ kind: "ancre_registre_point", sujet: sujetPoint("K1"), state: "envoyee", created_at: POINTS.K1.ts, attempts: [tentative({ n: 1, started_at: POINTS.K1.ts, kind: "ancre_registre_point", hash: POINTS.K1.hash, detail: "transaction envoyee" })] }),
      demande({ kind: "jeton_point", sujet: sujetPoint("K1"), deadlines: [1, 2, 3, 4, 5, 6, 7, 8], state: "attente_registre", created_at: POINTS.K1.ts, due_at: "2026-11-03T13:42:05.000Z" }),
    ];
    const s = new Scenario(
      "registre-indisponible",
      "Redémarrage à 13:42:01 avec, dans la file, l'ancre de K1 envoyee sans reçu et sa demande de jeton en attente du registre (EX-8.12 : renvoi des mêmes octets, interrogation de l'inclusion). L'inclusion n'est pas constatée dans squat_wait_s (5 s) : la requête part avec la ligne ordre_ancres_non_respecte (EX-4.7, EX-9.6) ; l'ancre est renvoyée puis remplacée au même nonce à chaque inclusion_alert_s (300 s) avec l'alerte inclusion_late, puis le registre répond empreinte_squattee : demande refusee, alerte critique, aucun nouvel essai (EX-9.7). À la clôture, l'ancre de la période reste sans reçu : jeton_periode en attente_registre, registry_pending à chaque inclusion_alert_s, anchor_pending à queue.anchor_pending_alert_s (900 s), puis inclusion tardive et jeton de clôture (EX-4.5, EX-8.4).",
      configuration({ registry: { inclusion_alert_s: 300 }, queue: { anchor_pending_alert_s: 900 } }),
      { queue_before: fileAvant },
    );
    s.demarrage("2026-11-03T13:42:01.000Z").granted("2026-11-03T13:42:07.000Z", JETON("K1"), 1, { gen_time: "2026-11-03T13:42:06Z", nom: "K1" });
    s.tic("2026-11-03T13:45:00.000Z").tic("2026-11-03T13:50:00.000Z").point("K2").echecRegistre("2026-11-03T13:53:03.000Z", ANCRE("K1"), "empreinte_squattee");
    s.inclusion("2026-11-03T13:53:04.000Z", ANCRE("K2"), 20660).granted("2026-11-03T13:53:06.000Z", JETON("K2"), 1, { gen_time: "2026-11-03T13:53:05Z", nom: "K2" });
    s.point("K3").tic("2026-11-03T13:55:00.000Z").point("K4").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" });
    s.inclusion("2026-11-03T14:00:02.000Z", ANCRE("K4"), 21085).granted("2026-11-03T14:00:03.000Z", JETON("K4"), 1, { gen_time: "2026-11-03T14:00:02Z", nom: "K4" });
    s.inclusion("2026-11-03T14:16:00.000Z", AP1, 21999).granted("2026-11-03T14:16:02.000Z", PH1, 1, { gen_time: "2026-11-03T14:16:01Z", nom: "periode 1", size: 3082 }).arret("2026-11-03T14:17:00.000Z");
    ajouter(s, (t) => [
      ["ordre des ancres non respecté à 13:42:05 puis requête", actions(t, "journaliser", (a) => a.detail.event === "ordre_ancres_non_respecte").length === 1 && actions(t, "envoyer_rfc3161", (a) => a.request_id === JETON("K1"))[0].t === "2026-11-03T13:42:05.000Z"],
      ["renvoi puis remplacement de l'ancre de K1, puis empreinte squattée", actions(t, "envoyer_registre", (a) => a.request_id === ANCRE("K1")).length === 3 && dem(t, ANCRE("K1")).state === "refusee" && actions(t, "alerter", (a) => a.detail.code === "empreinte_squattee").length === 1],
      ["K2 ancrée dès que la clé est libre (13:53:03)", actions(t, "envoyer_registre", (a) => a.request_id === ANCRE("K2"))[0].t === "2026-11-03T13:53:03.000Z"],
      ["registry_pending puis anchor_pending", actions(t, "alerter", (a) => a.detail.code === "registry_pending").length === 1 && actions(t, "alerter", (a) => a.detail.code === "anchor_pending").length === 1 && actions(t, "journaliser", (a) => a.detail.event === "registry_pending").length === 3],
      ["inclusion_late mineure puis majeure sur l'ancre de la période", JSON.stringify(actions(t, "alerter", (a) => a.request_id === AP1 && a.detail.code === "inclusion_late").map((a) => a.detail.severity)) === JSON.stringify(["mineure", "majeure", "majeure"])],
      ["jeton de clôture obtenu après l'inclusion tardive", dem(t, PH1).state === "obtenue" && actions(t, "journaliser", (a) => a.detail.event === "period_timestamped")[0].detail.d_jeton_s === 962],
    ]);
  }

  // 8. redemarrage-reprise : file non vide avec envoyee, attente_registre, en_attente (transitions d'EX-8.12).
  {
    const ref = liste[0].trace.queue_after;
    const copie = (id) => JSON.parse(JSON.stringify(ref.find((d) => d.id === id)));
    const k4 = copie(JETON("K4"));
    k4.state = "envoyee";
    k4.result = null;
    Object.assign(k4.attempts[0], { outcome: "en_cours", http_status: null, pki_status: null, detail: "requete envoyee" });
    const ap = copie(AP1);
    ap.state = "envoyee";
    ap.result = null;
    ap.attempts[0].outcome = "en_cours";
    ap.attempts[0].detail = "transaction envoyee";
    const jp = copie(PH1);
    jp.state = "attente_registre";
    jp.due_at = "2026-11-03T14:01:00.250Z";
    jp.attempts = [];
    jp.result = null;
    const fileAvant = [copie(ANCRE("K1")), copie(JETON("K1")), copie(ANCRE("K2")), copie(JETON("K2")), ap, copie(ANCRE("K4")), jp, k4, copie(OP1)];
    const s = new Scenario(
      "redemarrage-reprise",
      "La trace de référence interrompue à 14:00:02.500 et redémarrée : la file porte le jeton de K4 envoyee (réponse non reçue), l'ancre de la période envoyee sans reçu, le jeton de clôture en attente_registre et la preuve OpenTimestamps en_attente. Transitions d'EX-8.12 : envoyee devient a_reprendre et repart aussitôt avec un nouveau nonce (tentative 2) ; l'ancre est renvoyée ; l'inclusion est interrogée ; la mise à niveau est reprogrammée à max(due_at, now). La réponse à la tentative 1 de K4, arrivée après le redémarrage, est conservée sans changer l'état (EX-8.5).",
      configuration(),
      { queue_before: fileAvant },
    );
    s.demarrage("2026-11-03T14:00:02.500Z").granted("2026-11-03T14:00:03.000Z", JETON("K4"), 1, { gen_time: "2026-11-03T14:00:02Z", nom: "K4" });
    s.granted("2026-11-03T14:00:03.500Z", JETON("K4"), 2, { gen_time: "2026-11-03T14:00:03Z", nom: "K4 tentative 2" });
    s.inclusion("2026-11-03T14:00:04.000Z", AP1, 21087).granted("2026-11-03T14:00:05.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:05Z", nom: "periode 1", size: 3082 }).arret("2026-11-03T14:01:00.000Z");
    ajouter(s, (t) => [
      ["9 demandes relues", t.expected[0].detail.queue_entries === 9],
      ["K4 : a_reprendre immédiat puis tentative 2 au nouveau nonce", actions(t, "envoyer_rfc3161", (a) => a.request_id === JETON("K4")).length === 1 && actions(t, "envoyer_rfc3161", (a) => a.request_id === JETON("K4"))[0].detail.attempt === 2 && dem(t, JETON("K4")).state === "obtenue" && dem(t, JETON("K4")).result.sha256 === shaTexte("jeton K4 tentative 2")],
      ["réponse à la tentative 1 conservée sans promotion", actions(t, "journaliser", (a) => a.detail.event === "anchor_response_rejected" && a.detail.error_code === "tentative_close").length === 1],
      ["ancre de la période renvoyée puis incluse", actions(t, "journaliser", (a) => a.detail.event === "anchor_retry").length === 1 && dem(t, AP1).state === "obtenue"],
      ["mise à niveau reprogrammée à 20:00:01", actions(t, "programmer", (a) => a.detail.reason === "mise_a_niveau")[0].detail.next_at === "2026-11-03T20:00:01.000Z"],
      ["jeton de clôture obtenu", dem(t, PH1).state === "obtenue"],
    ]);
  }

  // 9. ots-mise-a-niveau : soumission, 404 en attente, puis attestation Bitcoin : complete, réexport ; preuve de point à l'échéance médiane.
  {
    const OK1 = ID("ots_point", POINTS.K1.hash);
    const s = new Scenario(
      "ots-mise-a-niveau",
      "Option mi_periode : K1, sélectionné par l'échéance médiane D_6, reçoit une preuve OpenTimestamps en plus de son ancre et de son jeton (EX-6.1) ; cadence de mise à niveau raccourcie (first_after_s et interval_s à 60 s). Soumission, attestation en attente, première mise à niveau sans attestation (404 : en_attente, nouvelle tentative interval_s plus tard), seconde mise à niveau avec attestation Bitcoin : preuve complète, réexport demandé (EX-6.6, EX-6.7, EX-8.11). La preuve de la clôture est soumise puis mise à niveau une fois sans attestation avant l'arrêt.",
      configuration({ opentimestamps: { checkpoint: "mi_periode" }, upgrade: { first_after_s: 60, interval_s: 60 } }),
    );
    s.demarrage("2026-11-03T13:40:00.000Z").point("K1").ots("2026-11-03T13:42:01.000Z", OK1, { nom: "en attente point K1" }).inclusion("2026-11-03T13:42:03.000Z", ANCRE("K1"), 20001).granted("2026-11-03T13:42:05.000Z", JETON("K1"), 1, { gen_time: "2026-11-03T13:42:04Z", nom: "K1" });
    s.ots("2026-11-03T13:43:02.000Z", OK1, { attestation: "en_attente", calendars_answered: 1 });
    s.ots("2026-11-03T13:44:03.000Z", OK1, { attestation: "complete", calendars_answered: 1, nom: "complete point K1", size: 316 });
    s.tic("2026-11-03T13:45:00.000Z").tic("2026-11-03T13:50:00.000Z").point("K2").inclusion("2026-11-03T13:53:02.000Z", ANCRE("K2"), 20660).granted("2026-11-03T13:53:04.000Z", JETON("K2"), 1, { gen_time: "2026-11-03T13:53:03Z", nom: "K2" });
    s.point("K3").tic("2026-11-03T13:55:00.000Z").point("K4").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" });
    s.inclusion("2026-11-03T14:00:02.000Z", ANCRE("K4"), 21085).granted("2026-11-03T14:00:03.000Z", JETON("K4"), 1, { gen_time: "2026-11-03T14:00:02Z", nom: "K4" });
    s.inclusion("2026-11-03T14:00:04.000Z", AP1, 21087).granted("2026-11-03T14:00:05.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:05Z", nom: "periode 1", size: 3082 });
    s.ots("2026-11-03T14:01:02.000Z", OP1, { attestation: "en_attente", calendars_answered: 1 }).arret("2026-11-03T14:01:30.000Z");
    ajouter(s, (t) => [
      ["preuve du point soumise à l'admission de K1", actions(t, "soumettre_ots", (a) => a.request_id === OK1)[0].t === POINTS.K1.ts],
      ["mises à niveau à 13:43:01 et 13:44:02", JSON.stringify(actions(t, "mettre_a_niveau_ots", (a) => a.request_id === OK1).map((a) => a.t)) === JSON.stringify(["2026-11-03T13:43:01.000Z", "2026-11-03T13:44:02.000Z"])],
      ["preuve du point complète, réexport", dem(t, OK1).state === "complete" && actions(t, "journaliser", (a) => a.detail.event === "ots_complete" && a.request_id === OK1).length === 1],
      ["preuve de la clôture en attente, prochaine mise à niveau à 14:02:02", dem(t, OP1).state === "en_attente" && dem(t, OP1).due_at === "2026-11-03T14:02:02.000Z"],
      ["aucune preuve de point pour K2 et K4", !dem(t, ID("ots_point", POINTS.K2.hash)) && !dem(t, ID("ots_point", POINTS.K4.hash))],
    ]);
  }

  // 10. preuve-de-vie : countersign_idle vrai, période 2 sans nouvel événement.
  {
    const s = new Scenario(
      "preuve-de-vie",
      "Période 2 de l'exemple de référence avec countersign_idle vrai : K5 et K6 n'engagent aucun nouvel événement (tree_size 0) et ne sont pas ancrés au registre (EX-4.6), mais le point de clôture K6, premier point de checkpoint_ts >= D_1 à D_11, est contresigné pour ces onze échéances en une requête, qui part aussitôt faute d'ancre à attendre (EX-4.3, EX-8.4 règle 3) ; puis la clôture est servie.",
      configuration({ countersign_idle: true }),
    );
    s.demarrage("2026-11-03T14:00:30.000Z").point("K5");
    for (let k = 1; k <= 11; k++) s.tic(A.iso((PERIOD_START_2 + 300 * k) * 1000));
    s.point("K6").cloture(ex, 2).ots("2026-11-03T15:00:01.000Z", OP2, { nom: "en attente periode 2" });
    s.granted("2026-11-03T15:00:02.000Z", JETON("K6"), 1, { gen_time: "2026-11-03T15:00:01Z", nom: "K6" });
    s.inclusion("2026-11-03T15:00:03.000Z", AP2, 24700).granted("2026-11-03T15:00:04.000Z", PH2, 1, { gen_time: "2026-11-03T15:00:04Z", nom: "periode 2", size: 3082 }).arret("2026-11-03T15:01:00.000Z");
    ajouter(s, (t) => [
      ["K6 contresigné pour D_1 à D_11", dem(t, JETON("K6"))?.state === "obtenue" && dem(t, JETON("K6")).deadlines.length === 11],
      ["requête partie à l'admission de K6, sans attente du registre", actions(t, "envoyer_rfc3161", (a) => a.request_id === JETON("K6"))[0].t === POINTS.K6.ts && actions(t, "programmer", (a) => a.request_id === JETON("K6")).length === 0],
      ["aucun point ancré", !dem(t, ANCRE("K5")) && !dem(t, ANCRE("K6")) && actions(t, "journaliser", (a) => a.detail.event === "checkpoint_not_anchored").length === 2],
      ["aucune échéance sans_objet", actions(t, "echeance", (a) => a.detail.state === "sans_objet").length === 0],
    ]);
  }

  // 11. file-pleine : max_pending atteint par des clôtures en souffrance ; points non ancrés, clôture toujours servie.
  {
    const fileAvant = [];
    for (let i = 100; i >= 1; i--) {
      const period_start = PERIOD_START_1 - 3600 * i;
      const hash = shaTexte(`noortrace/vecteurs/v0/ct-5/file-pleine/periode/${period_start}`);
      const created_at = A.iso((period_start + 3600) * 1000);
      const sujet = { kind: "periode", org_id: ORG_ID, journal_id: JOURNAL_ID, period_start, hash, tree_size: null, declared_at: created_at };
      fileAvant.push(demande({ kind: "jeton_periode", sujet, state: "a_reprendre", created_at, due_at: "2026-11-03T14:30:00.000Z", attempts: [tentative({ n: 1, provider: "qtsa-principal", started_at: plusMs(created_at, 2000), nonce: nonceDe("periode", hash, 1), kind: "jeton_periode", hash, outcome: "echec_transitoire", error_code: "http_503", http_status: 503, next_at: "2026-11-03T14:30:00.000Z", detail: "http 503" })] }));
    }
    const s = new Scenario(
      "file-pleine",
      "queue.max_pending abaissé à 100 et une file qui porte déjà cent jetons de clôture en a_reprendre (cent heures de panne du prestataire, représentées ; prochaine tentative après la fin de la trace) : les points K1, K2 et K4 ne sont plus ancrés (anchor_queue_full, alerte file_pleine critique) mais la clôture crée toujours ses trois demandes et le jeton de clôture est obtenu (EX-8.5, règle 4). Les échéances de points restées ouvertes sont closes remplacee par la clôture (EX-4.4).",
      configuration({ queue: { max_pending: 100 } }),
      { queue_before: fileAvant },
    );
    s.demarrage("2026-11-03T13:40:00.000Z").point("K1").tic("2026-11-03T13:45:00.000Z").tic("2026-11-03T13:50:00.000Z").point("K2").tic("2026-11-03T13:55:00.000Z").point("K4").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" });
    s.inclusion("2026-11-03T14:00:02.000Z", AP1, 21087).granted("2026-11-03T14:00:03.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:03Z", nom: "periode 1", size: 3082 }).arret("2026-11-03T14:01:00.000Z");
    ajouter(s, (t) => [
      ["cent demandes relues, trois refus de point", t.expected[0].detail.queue_entries === 100 && actions(t, "alerter", (a) => a.detail.code === "file_pleine").length === 3 && !dem(t, ANCRE("K1")) && !dem(t, JETON("K4"))],
      ["la clôture crée ses trois demandes et obtient son jeton", dem(t, AP1).state === "obtenue" && dem(t, PH1).state === "obtenue" && dem(t, OP1).state === "en_attente"],
      ["onze échéances remplacées par la clôture", actions(t, "echeance", (a) => a.detail.state === "remplacee").length === 11],
      ["103 demandes à l'arrêt", t.queue_after.length === 103],
    ]);
  }

  // 12. prestataire-min-interval : min_interval_ms respecté toutes demandes confondues ; jeton_periode servi d'abord à égalité.
  {
    const s = new Scenario(
      "prestataire-min-interval",
      "Points contresignés par le prestataire principal dont min_interval_ms vaut 480 000 (huit minutes) : la requête de K2 (13:53:02) rend le prestataire indisponible jusqu'à 14:01:02 ; à la clôture, le jeton de K4 et le jeton de clôture attendent tous deux ; à 14:01:02 le jeton_periode part d'abord (EX-8.7) et le jeton de K4 est reprogrammé huit minutes plus tard ; la clôture obtenue avant lui clôt remplacee la demande de K4 et son échéance D_11 (EX-4.4), avec l'alerte majeure d'un prestataire extérieur.",
      configuration({ provider_role: "principal", min_interval: { principal: 480000 } }),
    );
    s.demarrage("2026-11-03T13:40:00.000Z").point("K1").inclusion("2026-11-03T13:42:03.000Z", ANCRE("K1"), 20001).granted("2026-11-03T13:42:05.000Z", JETON("K1"), 1, { gen_time: "2026-11-03T13:42:04Z", nom: "K1 qualifie", size: 3082 });
    s.tic("2026-11-03T13:45:00.000Z").tic("2026-11-03T13:50:00.000Z").point("K2").inclusion("2026-11-03T13:53:02.000Z", ANCRE("K2"), 20660).granted("2026-11-03T13:53:04.000Z", JETON("K2"), 1, { gen_time: "2026-11-03T13:53:03Z", nom: "K2 qualifie", size: 3082 });
    s.point("K3").tic("2026-11-03T13:55:00.000Z").point("K4").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" });
    s.inclusion("2026-11-03T14:00:02.000Z", ANCRE("K4"), 21085).inclusion("2026-11-03T14:00:04.000Z", AP1, 21087);
    s.granted("2026-11-03T14:01:03.000Z", PH1, 1, { gen_time: "2026-11-03T14:01:03Z", nom: "periode 1", size: 3082 }).arret("2026-11-03T14:02:00.000Z");
    ajouter(s, (t) => [
      ["jeton de clôture envoyé à 14:01:02, avant le jeton de K4", actions(t, "envoyer_rfc3161", (a) => a.request_id === PH1)[0].t === "2026-11-03T14:01:02.000Z" && actions(t, "envoyer_rfc3161", (a) => a.request_id === JETON("K4")).length === 0],
      ["K4 reprogrammé à 14:01:02 puis 14:09:02", JSON.stringify(actions(t, "programmer", (a) => a.request_id === JETON("K4") && a.detail.reason === "backoff").map((a) => a.detail.next_at)) === JSON.stringify(["2026-11-03T14:01:02.000Z", "2026-11-03T14:09:02.000Z"])],
      ["K4 remplacée par la clôture, alerte majeure", dem(t, JETON("K4")).state === "remplacee" && dem(t, JETON("K4")).replaced_by === PH1 && actions(t, "alerter", (a) => a.detail.code === "checkpoint_anchor_late")[0].detail.severity === "majeure"],
    ]);
  }

  // Traces sur le journal des vecteurs (journal-sinistres de CT-1 §13) : séries de
  // spec/vecteurs/ct-1/points-de-controle, un point par minute aligné sur period_start.
  const S1 = serieSinistres(1);
  const S2 = serieSinistres(2);
  const C1 = clotureSinistres(1);
  const pt = (serie, hhmm) => {
    const x = serie.find((p) => p.checkpoint_ts.slice(11, 16) === hhmm && p.checkpoint_ts.endsWith(":00.000Z"));
    exiger(x, `point de ${hhmm} absent de la série`);
    return x;
  };
  const clotureS1 = S1[S1.length - 1];
  const SIN = "journal-sinistres";
  const JS = (p) => ID("jeton_point", p.checkpoint_hash);
  const AS = (p) => ID("ancre_registre_point", p.checkpoint_hash);
  const PHS1 = ID("jeton_periode", C1.period_hash);
  const APS1 = ID("ancre_registre_periode", C1.period_hash);
  const OPS1 = ID("ots_periode", C1.period_hash);
  const jour = (hhmmss) => `2026-11-05T${hhmmss}.000Z`;
  const avant = (serie, hhmm) => serie.filter((p) => p.checkpoint_ts.slice(11, 16) <= hhmm && p.checkpoint_ts.endsWith(":00.000Z"));

  // 13. refus-puis-preuve-de-vie (EX-4.3, EX-8.4 règle 1) : un jeton de point refusé ne compte pas comme contresigné.
  const scenarioRefus = (id, description) => new Scenario(id, description, configuration({ prestataires: ["principal", "secours", "second_rang"], provider_role: "second_rang" }));
  const debutRefus = (s) => {
    s.demarrage(jour("08:59:30"));
    for (const p of avant(S1, "09:15")) {
      s.pointSerie(p);
      if (minute(p) === "09:13") s.inclusion(jour("09:13:02"), AS(p), 30013);
    }
    s.echec(jour("09:15:02"), JS(pt(S1, "09:15")), 1, { pki_status: 2, failure_info: "unacceptedPolicy" });
    return s;
  };
  const finRefus = (s, depuis) => {
    for (const p of S1.filter((p) => p.checkpoint_ts >= jour(depuis) && p.checkpoint_ts <= jour("09:25:00"))) {
      s.pointSerie(p);
      if (minute(p) === "09:16") s.granted(jour("09:16:02"), JS(p), 1, { gen_time: "2026-11-05T09:16:01Z", nom: "sinistres point 09:16", journal: SIN });
    }
    s.arret(jour("09:26:00"));
    return s;
  };
  {
    const s = finRefus(debutRefus(scenarioRefus("refus-puis-preuve-de-vie", "Journal des vecteurs, période 1, points contresignés par un prestataire de second rang : le jeton du point de 09:15 (tree_size 5, D_3) est refusé (unacceptedPolicy, sans relève pour ce rôle) ; la demande refusée ne compte pas comme contresignée et rend D_3 (EX-4.3, EX-8.4 règle 1) : le point suivant, à 09:16, de même tree_size (preuve de vie), est contresigné pour D_3 au lieu d'être clos sans_objet ; D_4 et D_5 sont ensuite closes sans_objet (même tree_size qu'un point dont le jeton est obtenu).")), "09:16:00");
    ajouter(s, (t) => [
      ["jeton de 09:15 refusé", dem(t, JS(pt(S1, "09:15"))).state === "refusee"],
      ["le point de 09:16 (même tree_size) est contresigné pour D_3", JSON.stringify(dem(t, JS(pt(S1, "09:16"))).deadlines) === "[3]" && dem(t, JS(pt(S1, "09:16"))).state === "obtenue"],
      ["D_4 et D_5 closes sans_objet après le jeton de 09:16", actions(t, "echeance", (a) => a.detail.state === "sans_objet" && (a.detail.k === 4 || a.detail.k === 5)).length === 2],
    ]);
  }
  // 14. refus-puis-preuve-de-vie-redemarrage : même scénario, redémarrage entre le refus et le point suivant.
  {
    const a = debutRefus(scenarioRefus("refus-puis-preuve-de-vie-avant", "x")).arret(jour("09:15:10")).construire();
    const s = new Scenario(
      "refus-puis-preuve-de-vie-redemarrage",
      "Le scénario refus-puis-preuve-de-vie interrompu après le refus du jeton de 09:15 et redémarré à 09:15:30 sur sa file : la demande refusée ne tient aucune échéance au démarrage (EX-8.12) et le point de 09:16 est contresigné au même instant et auprès du même prestataire que sans redémarrage. Les échéances closes sans_objet ne sont pas dans la file : D_1 et D_2, rouvertes au démarrage, sont servies par le même jeton (sans requête de plus).",
      configuration({ prestataires: ["principal", "secours", "second_rang"], provider_role: "second_rang" }),
      { queue_before: a.queue_after },
    );
    s.demarrage(jour("09:15:30"));
    finRefus(s, "09:16:00");
    ajouter(s, (t) => [
      ["le point de 09:16 est contresigné après le redémarrage, pour D_1 à D_3", JSON.stringify(dem(t, JS(pt(S1, "09:16"))).deadlines) === "[1,2,3]" && dem(t, JS(pt(S1, "09:16"))).state === "obtenue"],
      ["même requête qu'en continu (09:16:00, tentative 1, second rang)", actions(t, "envoyer_rfc3161", (x) => x.request_id === JS(pt(S1, "09:16"))).length === 1 && actions(t, "envoyer_rfc3161", (x) => x.request_id === JS(pt(S1, "09:16")))[0].t === jour("09:16:00") && actions(t, "envoyer_rfc3161", (x) => x.request_id === JS(pt(S1, "09:16")))[0].detail.provider === "tsa-second-rang"],
    ]);
  }

  // 15. file-perdue (EX-8.12) : file absente au démarrage, reconstruction depuis le stockage.
  {
    const s = new Scenario(
      "file-perdue",
      "Période 1 de l'exemple de référence : la file est perdue et le composant redémarre à 13:56 avec une file vide ; l'enregistreur relève dans son stockage les points K1 à K3 sans ancre obtenue (stockage_relu) : le dernier point de la période ouverte, K3, est traité comme admis (ancre au registre, jeton pour D_1 à D_10), anchoring_queue_rebuilt porte le nombre de demandes recréées et l'alerte file_perdue est levée (EX-8.12). La suite de l'heure est servie normalement.",
      configuration(),
    );
    s.demarrage("2026-11-03T13:56:00.000Z").entree("2026-11-03T13:56:00.000Z", "stockage_relu", { periods: [], checkpoints: ["K1", "K2", "K3"].map((n) => ({ org_id: ORG_ID, journal_id: JOURNAL_ID, period_start: PERIOD_START_1, tree_size: POINTS[n].tree_size, checkpoint_hash: POINTS[n].hash, checkpoint_ts: POINTS[n].ts })) });
    s.inclusion("2026-11-03T13:56:02.000Z", ANCRE("K3"), 20730).granted("2026-11-03T13:56:04.000Z", JETON("K3"), 1, { gen_time: "2026-11-03T13:56:03Z", nom: "K3" });
    s.point("K4").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" });
    s.inclusion("2026-11-03T14:00:02.000Z", ANCRE("K4"), 21085).granted("2026-11-03T14:00:03.000Z", JETON("K4"), 1, { gen_time: "2026-11-03T14:00:02Z", nom: "K4" });
    s.inclusion("2026-11-03T14:00:04.000Z", AP1, 21087).granted("2026-11-03T14:00:05.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:05Z", nom: "periode 1", size: 3082 }).arret("2026-11-03T14:01:00.000Z");
    ajouter(s, (t) => [
      ["anchoring_queue_rebuilt : deux demandes recréées (ancre et jeton de K3)", actions(t, "journaliser", (a) => a.detail.event === "anchoring_queue_rebuilt")[0]?.detail.recreated === 2 && actions(t, "alerter", (a) => a.detail.code === "file_perdue").length === 1],
      ["K3 contresigné pour D_1 à D_10", JSON.stringify(dem(t, JETON("K3")).deadlines) === "[1,2,3,4,5,6,7,8,9,10]" && dem(t, JETON("K3")).state === "obtenue"],
      ["K1 et K2 non recréés (seul le dernier point de la période ouverte)", !dem(t, JETON("K1")) && !dem(t, ANCRE("K2"))],
    ]);
  }

  // 16 et 17. bascule-epoque (EX-8.5, EX-8.12) : deux fichiers de file d'époques successives.
  const ecrivainA = () => {
    const s = new Scenario("bascule-ecrivain-a", "x", configuration());
    const p58 = pt(S1, "09:58");
    s.demarrage(jour("09:57:30")).pointSerie(p58).inclusion(jour("09:58:02"), AS(p58), 30098).granted(jour("09:58:04"), JS(p58), 1, { gen_time: "2026-11-05T09:58:03Z", nom: "sinistres point 09:58", journal: SIN });
    s.pointSerie(pt(S1, "09:59")).pointSerie(clotureS1).clotureSerie(C1).inclusion(jour("10:00:01"), AS(clotureS1), 30100).ots("2026-11-05T10:00:01.500Z", OPS1, { nom: "en attente sinistres periode 1" });
    s.construire();
    return s;
  };
  const ecrivainB = () => {
    const s = new Scenario("bascule-ecrivain-b", "x", configuration());
    s.demarrage(jour("10:00:30"));
    for (const p of S2.filter((p) => p.checkpoint_ts >= jour("10:01:00") && p.checkpoint_ts <= jour("10:05:00"))) s.pointSerie(p);
    const p5 = pt(S2, "10:05");
    s.inclusion(jour("10:05:02"), AS(p5), 30401).granted(jour("10:05:04"), JS(p5), 1, { gen_time: "2026-11-05T10:05:03Z", nom: "sinistres point 10:05", journal: SIN });
    s.construire();
    return s;
  };
  const fichiersBascule = () => {
    const a = ecrivainA();
    const b = ecrivainB();
    return [
      { nom: "file-1.ndjson", texte: a.lignes.map((l) => l + "\n").join("") },
      { nom: "file-2.ndjson", texte: b.lignes.map((l) => l + "\n").join("") },
    ];
  };
  const suiteBascule = (s) => {
    s.inclusion(jour("10:06:03"), APS1, 30460).granted(jour("10:06:05"), PHS1, 1, { gen_time: "2026-11-05T10:06:04Z", nom: "sinistres periode 1", size: 3082, journal: SIN }).arret(jour("10:07:00"));
    return s;
  };
  const stockageBascule = { periods: [C1], checkpoints: S2.filter((p) => p.checkpoint_ts <= jour("10:05:00")) };
  {
    const fichiers = fichiersBascule();
    const lus = A.lireFiles(fichiers);
    exiger(lus.truncated.length === 0 && lus.errors.length === 0, "bascule-epoque : relecture des deux fichiers");
    const s = new Scenario(
      "bascule-epoque",
      "Bascule d'écrivain (CT-2 §13) sur le journal des vecteurs : l'écrivain d'époque 1 a clos la période 1 (ancre de la période envoyee sans reçu, jeton de clôture en attente_registre, preuve OpenTimestamps en attente) puis s'est arrêté ; l'écrivain d'époque 2 a servi les premiers points de la période 2 dans file-2.ndjson. Au redémarrage à 10:06, le composant relit tous les fichiers de file (file-1.ndjson puis file-2.ndjson, EX-8.12 ; reprise/bascule-epoque.epoque-*.ndjson) : la demande de jeton de clôture de l'époque 1 n'est pas oubliée ; la confrontation au stockage (stockage_relu) ne recrée aucune demande. L'ancre de la période est renvoyée, incluse, et le jeton qualifié obtenu (EX-4.5).",
      configuration(),
      { queue_before: lus.demandes },
    );
    s.demarrage(jour("10:06:00")).stockage(jour("10:06:00"), stockageBascule);
    suiteBascule(s);
    ajouter(s, (t) => [
      ["aucune demande recréée", actions(t, "journaliser", (a) => a.detail.event === "anchoring_queue_rebuilt")[0]?.detail.recreated === 0 && actions(t, "alerter", (a) => a.detail.code === "file_perdue").length === 0],
      ["jeton de clôture de l'époque 1 obtenu", dem(t, PHS1).state === "obtenue"],
    ]);
    liste[liste.length - 1].fichiers = fichiers;
  }
  {
    const fichiers = fichiersBascule();
    const lus = A.lireFiles([fichiers[1]]);
    const s = new Scenario(
      "bascule-epoque-fichier-perdu",
      "Même bascule, file-1.ndjson perdu : seul file-2.ndjson est relu ; la confrontation au stockage (stockage_relu : manifeste de la période 1 sans ancre obtenue, points de la période 2) recrée les trois demandes de la clôture de la période 1 (EX-8.12 : le déclenchement ne dépend pas d'une file vide) ; anchoring_queue_rebuilt et alerte file_perdue ; le jeton de clôture est obtenu.",
      configuration(),
      { queue_before: lus.demandes },
    );
    s.demarrage(jour("10:06:00")).stockage(jour("10:06:00"), stockageBascule);
    s.ots(jour("10:06:01"), OPS1, { nom: "en attente sinistres periode 1" });
    suiteBascule(s);
    ajouter(s, (t) => [
      ["trois demandes de la clôture recréées", actions(t, "journaliser", (a) => a.detail.event === "anchoring_queue_rebuilt")[0]?.detail.recreated === 3 && actions(t, "alerter", (a) => a.detail.code === "file_perdue").length === 1],
      ["jeton de clôture obtenu", dem(t, PHS1).state === "obtenue"],
    ]);
  }

  // 18. registre-indisponible-cloture (EX-4.2, EX-8.4 règle 2, EX-9.5) : repli sur le point de clôture, rattrapage des ancres de points.
  {
    const s = new Scenario(
      "registre-indisponible-cloture",
      "Journal des vecteurs, période 1 (un point par minute) ; le registre n'inclut plus rien à partir de l'ancre du point de 09:13 (inclusion_alert_s porté à 1800 s pour raccourcir la trace). L'ancre du point de 09:32 attend la clé (a_envoyer) puis est remplacée par celle du point de clôture (EX-9.5, rattrapage). À la clôture, le jeton de la période attend l'inclusion de son ancre ; squat_wait_s après la clôture, le point de clôture (tree_size 9, aucune échéance ne l'a sélectionné) reçoit un jeton_point de repli auprès du prestataire des points (EX-4.2, EX-8.4 règle 2), envoyé squat_wait_s plus tard avec ordre_ancres_non_respecte, ce qui borne la date du dernier intervalle. Le registre revient à 10:20 : ancre de la période, jeton qualifié de la clôture, puis ancre du point de clôture.",
      configuration({ registry: { inclusion_alert_s: 1800 } }),
    );
    s.demarrage(jour("08:59:30"));
    for (const p of S1) {
      s.pointSerie(p);
      if (minute(p) === "09:15") s.granted(jour("09:15:02"), JS(p), 1, { gen_time: "2026-11-05T09:15:01Z", nom: "sinistres point 09:15", journal: SIN });
      if (minute(p) === "09:35") s.granted(jour("09:35:02"), JS(p), 1, { gen_time: "2026-11-05T09:35:01Z", nom: "sinistres point 09:35", journal: SIN });
    }
    s.clotureSerie(C1).ots(jour("10:00:01"), OPS1, { nom: "en attente sinistres periode 1" });
    s.granted(jour("10:00:12"), JS(clotureS1), 1, { gen_time: "2026-11-05T10:00:11Z", nom: "sinistres point de cloture", journal: SIN });
    s.inclusion(jour("10:20:00"), AS(pt(S1, "09:13")), 30013).inclusion(jour("10:20:02"), APS1, 31201).granted(jour("10:20:04"), PHS1, 1, { gen_time: "2026-11-05T10:20:03Z", nom: "sinistres periode 1", size: 3082, journal: SIN });
    s.inclusion(jour("10:20:06"), AS(clotureS1), 31203).arret(jour("10:21:00"));
    ajouter(s, (t) => [
      ["ancre du point de 09:32 remplacée par celle du point de clôture (EX-9.5)", dem(t, AS(pt(S1, "09:32"))).state === "remplacee" && dem(t, AS(pt(S1, "09:32"))).replaced_by === AS(clotureS1) && actions(t, "envoyer_registre", (a) => a.request_id === AS(pt(S1, "09:32"))).length === 0],
      ["repli : jeton_point du point de clôture sans échéance, créé squat_wait_s après la clôture", actions(t, "journaliser", (a) => a.detail.event === "checkpoint_closing_fallback").length === 1 && JSON.stringify(dem(t, JS(clotureS1)).deadlines) === "[]" && dem(t, JS(clotureS1)).state === "obtenue"],
      ["jeton de repli envoyé avec ordre_ancres_non_respecte", actions(t, "journaliser", (a) => a.request_id === JS(clotureS1) && a.detail.event === "ordre_ancres_non_respecte").length === 1],
      ["contresignature du repli marquée closing_fallback", actions(t, "journaliser", (a) => a.request_id === JS(clotureS1) && a.detail.event === "checkpoint_countersigned")[0]?.detail.closing_fallback === true],
      ["jeton de clôture obtenu après le retour du registre", dem(t, PHS1).state === "obtenue"],
    ]);
  }

  // 19. mi-periode-impair (EX-6.1) : c_T = 720, n_T = 5, k_m = ⌈5 / 2⌉ = 3.
  {
    const s = new Scenario(
      "mi-periode-impair",
      "Option mi_periode avec c_T = 720 s (n_T = 5, nombre impair) sur le journal des vecteurs : l'échéance médiane est k_m = 3 (D_3 = 09:36) et le point qu'elle sélectionne reçoit une preuve OpenTimestamps en plus de son jeton (EX-6.1) ; aucune preuve pour les autres points.",
      { ...configuration({ opentimestamps: { checkpoint: "mi_periode" } }), rfc3161: { ...configuration().rfc3161, checkpoints: { interval_s: 720, provider_role: "interne", fallback_after_s: 120, countersign_idle: false } } },
    );
    s.demarrage(jour("08:59:30"));
    for (const p of avant(S1, "09:50")) {
      s.pointSerie(p);
      if (minute(p) === "09:13") s.inclusion(jour("09:13:02"), AS(p), 30013);
      if (minute(p) === "09:32") s.inclusion(jour("09:32:02"), AS(p), 30032);
      if (minute(p) === "09:24") s.granted(jour("09:24:02"), JS(p), 1, { gen_time: "2026-11-05T09:24:01Z", nom: "sinistres point 09:24", journal: SIN });
      if (minute(p) === "09:36") {
        s.ots(jour("09:36:01"), ID("ots_point", p.checkpoint_hash), { nom: "en attente sinistres point 09:36" });
        s.granted(jour("09:36:02"), JS(p), 1, { gen_time: "2026-11-05T09:36:01Z", nom: "sinistres point 09:36", journal: SIN });
      }
    }
    s.arret(jour("09:51:00"));
    ajouter(s, (t) => [
      ["une seule preuve de point, pour le point de 09:36 (D_3)", t.queue_after.filter((d) => d.kind === "ots_point").length === 1 && dem(t, ID("ots_point", pt(S1, "09:36").checkpoint_hash))?.state === "en_attente" && JSON.stringify(dem(t, JS(pt(S1, "09:36"))).deadlines) === "[3]"],
    ]);
  }

  // 20. reponse-hors-profil (EX-5.10, étapes 1 et 5) : Content-Type, taille et politique portés par l'entrée.
  {
    const s = new Scenario(
      "reponse-hors-profil",
      "Clôture de la période 1 de référence : le principal répond 200 avec un Content-Type text/html (type_contenu, erreur permanente : relève immédiate) ; le secours répond un jeton dont la politique est hors de accepted_policies (politique_refusee, permanente) : les deux prestataires sont épuisés, alerte prestataires_epuises, reprise au pas retry.max_ms en alternant (EX-8.8) ; le principal répond alors un corps de 200 000 octets (taille, permanente), puis le secours un jeton conforme, promu (EX-5.10, étapes 1 et 5 ; EX-8.6).",
      configuration(),
    );
    s.demarrage("2026-11-03T13:59:00.000Z").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" }).inclusion("2026-11-03T14:00:02.000Z", AP1, 21087);
    s.echec("2026-11-03T14:00:03.000Z", PH1, 1, { http_status: 200, extra: { content_type: "text/html" } });
    s.granted("2026-11-03T14:00:04.000Z", PH1, 2, { gen_time: "2026-11-03T14:00:04Z", nom: "periode 1 politique hors liste", size: 3082, extra: { policy_check: "politique_refusee" } });
    s.echec("2026-11-03T14:05:05.000Z", PH1, 3, { http_status: 200, extra: { content_type: "application/timestamp-reply", body_size: 200000 } });
    s.granted("2026-11-03T14:10:06.000Z", PH1, 4, { gen_time: "2026-11-03T14:10:06Z", nom: "periode 1 secours conforme", size: 3082, extra: { policy_check: "conforme" } });
    s.arret("2026-11-03T14:11:00.000Z");
    ajouter(s, (t) => [
      ["codes type_contenu, politique_refusee, taille", JSON.stringify(actions(t, "rejeter_reponse", (a) => a.request_id === PH1).map((a) => a.detail.error_code)) === JSON.stringify(["type_contenu", "politique_refusee", "taille"])],
      ["jeton du secours promu à la quatrième tentative", dem(t, PH1).state === "obtenue" && dem(t, PH1).result.provider === "qtsa-secours" && dem(t, PH1).attempts.length === 4],
    ]);
  }

  // 21. point-manquant (EX-8.15, AN-2) : série creuse du journal des vecteurs.
  {
    const s = new Scenario(
      "point-manquant",
      "Journal des vecteurs, période 1, dont l'enregistreur n'a produit que trois points (09:00, 09:59 et la clôture) : 2 x c_K après le point de 09:00 sans autre point, la ligne point_manquant et l'alerte majeure sont émises (EX-8.15) ; le point de 09:59 est sélectionné par D_1 à D_11 et contresigné en une requête (EX-4.3).",
      configuration(),
    );
    s.demarrage(jour("08:59:30")).pointSerie(pt(S1, "09:00")).tic(jour("09:30:00")).pointSerie(pt(S1, "09:59"));
    s.inclusion(jour("09:59:02"), AS(pt(S1, "09:59")), 30359).granted(jour("09:59:04"), JS(pt(S1, "09:59")), 1, { gen_time: "2026-11-05T09:59:03Z", nom: "sinistres point 09:59", journal: SIN });
    s.pointSerie(clotureS1).clotureSerie(C1).ots(jour("10:00:01"), OPS1, { nom: "en attente sinistres periode 1" });
    s.inclusion(jour("10:00:02"), AS(clotureS1), 30360).inclusion(jour("10:00:03"), APS1, 30361).granted(jour("10:00:04"), PHS1, 1, { gen_time: "2026-11-05T10:00:04Z", nom: "sinistres periode 1", size: 3082, journal: SIN }).arret(jour("10:01:00"));
    ajouter(s, (t) => [
      ["point_manquant à 09:02, une seule fois", JSON.stringify(actions(t, "alerter", (a) => a.detail.code === "point_manquant").map((a) => a.t)) === JSON.stringify([jour("09:02:00")])],
      ["le point de 09:59 sert D_1 à D_11", JSON.stringify(dem(t, JS(pt(S1, "09:59"))).deadlines) === "[1,2,3,4,5,6,7,8,9,10,11]"],
    ]);
  }

  exiger(liste.length === 21, "vingt et une traces attendues");
  return liste;
}

// ---------------------------------------------------------------------------
// Famille requetes (EX-5.1, A.4)
// ---------------------------------------------------------------------------

export function familleRequetes() {
  const cas = (id, description, digest, nonce_label, policy_oid, file) => {
    const nonce = A.nonceDepuisEtiquette(nonce_label);
    const der = A.construireRequete({ digest, nonce, policy_oid });
    const relu = A.lireRequete(der);
    exiger(relu.nonce === nonce && relu.digest === digest && relu.policy_oid === policy_oid, `requête ${id} : relecture`);
    return { id, description, input: { digest, nonce_label, policy_oid, cert_req: true }, expected: { nonce: A.hexNonce(nonce), der: "0x" + der.toString("hex"), size: der.length, sha256: sha256Hex(der), file } };
  };
  const K2 = POINTS.K2.hash;
  const etiq = (sorte, hash, n, journal = JOURNAL) => A.ETIQUETTES.nonceTsa({ journal, sorte, hash, n });
  const cases = [
    cas("requete-point-k2", "La requête d'EX-5.1 : checkpointHash du point K2 de CT-1 §10.5, nonce de CT-1 §13 (0x74a6f4979421411e), à laquelle le jeton de CT-1 §11.2 répond.", K2, ETIQUETTE_NONCE_CT1, null, "requete-point-k2.tsq"),
    cas("point-k2-exemple", "Point K2 de l'exemple de référence de CT-1 (checkpointHash), première tentative, sans politique.", K2, etiq("point", K2, 1), null, "point-k2-exemple.tsq"),
    cas("point-k2-exemple-politique-interne", "Même empreinte, politique du serveur interne de test 1.3.6.1.4.1.99999.1.1.", K2, etiq("point", K2, 1), A.POLITIQUE_TEST, "point-k2-exemple-politique-interne.tsq"),
    cas("periode-1-reference", "periodHash de la période 1 de l'exemple de référence de CT-1, première tentative (nonce à bit haut : 70 octets).", PERIOD_HASH_1, etiq("periode", PERIOD_HASH_1, 1), null, "periode-1-reference.tsq"),
    cas("periode-1-reference-tentative-2", "Même empreinte, deuxième tentative : nonce frais.", PERIOD_HASH_1, etiq("periode", PERIOD_HASH_1, 2), null, "periode-1-reference-tentative-2.tsq"),
    cas("periode-1-vecteurs", "periodHash de la période 1 des vecteurs CT-1 (journal-sinistres), première tentative.", G.PERIOD_HASHES[0], etiq("periode", G.PERIOD_HASHES[0], 1, "journal-sinistres"), null, "periode-1-vecteurs.tsq"),
  ];
  const attendus = { "requete-point-k2": [69, NONCE_CT1], "point-k2-exemple": [69, "0x018032ff0d74cfda", "0x6f69038e3ba10962a7b6af72d5366e4b04946a9cf06aa2bb17d818bbc6ef736a"], "point-k2-exemple-politique-interne": [81, "0x018032ff0d74cfda"], "periode-1-reference": [70, "0xf144cca6ec50dcdb"], "periode-1-reference-tentative-2": [70, "0xe514f7e31f6ba99e"], "periode-1-vecteurs": [69, "0x29ccc3c9db80e87b"] };
  for (const c of cases) {
    const [taille, nonce, sha] = attendus[c.id];
    exiger(c.expected.size === taille && c.expected.nonce === nonce && (!sha || c.expected.sha256 === sha), `requête ${c.id} : taille, nonce ou SHA-256 différents d'A.4`);
  }
  const refus = (id, description, entree, regle) => {
    let message = null;
    try {
      A.construireRequete(entree);
    } catch (e) {
      exiger(e instanceof A.ErreurAncrage && e.regle === regle, `cas refusé ${id} : règle ${regle} attendue`);
      message = e.message;
    }
    exiger(message !== null, `cas refusé ${id} : la construction aurait dû être refusée`);
    return { id, description, input: { digest: typeof entree.digest === "string" ? entree.digest : "0x" + Buffer.from(entree.digest).toString("hex"), nonce: typeof entree.nonce === "bigint" ? "0x" + entree.nonce.toString(16) : String(entree.nonce), policy_oid: entree.policy_oid ?? null, cert_req: entree.cert_req ?? true }, expected: { refused: true, rule: regle, message } };
  };
  const refusees = [
    refus("condense-31-octets", "Empreinte de 31 octets : messageImprint SHA-256 exige 32 octets (EX-5.1, EX-5.2).", { digest: Buffer.alloc(31, 0xab), nonce: 1n }, "AN-5"),
    refus("nonce-nul", "Nonce 0 : l'entier est dans [1, 2^64 − 1] (EX-5.3).", { digest: K2, nonce: 0n }, "AN-6"),
    refus("nonce-hors-64-bits", "Nonce 2^64 : hors de [1, 2^64 − 1] (EX-5.3).", { digest: K2, nonce: 1n << 64n }, "AN-6"),
    refus("certreq-faux", "certReq FALSE : certReq vaut toujours TRUE (EX-5.4).", { digest: K2, nonce: 1n, cert_req: false }, "AN-5"),
  ];
  // Nonce encodé avec un zéro superflu : refusé à la relecture (la construction écrit toujours la forme minimale).
  const requeteMinimale = cases[1].expected.der;
  const nonMinimal = Buffer.from(requeteMinimale.slice(2).replace("0208018032ff0d74cfda", "020900018032ff0d74cfda").replace(/^3043/, "3044"), "hex");
  let messageRelecture = null;
  try {
    A.lireRequete(nonMinimal);
  } catch (e) {
    messageRelecture = e.message;
  }
  exiger(messageRelecture !== null && /non minimal/.test(messageRelecture), "relecture : nonce à zéro de tête superflu refusé");
  refusees.push({ id: "nonce-zero-superflu", description: "Requête point-k2-exemple dont le nonce est encodé 02 09 00 01 80 32 ff 0d 74 cf da (zéro de tête superflu) : la relecture la refuse, l'encodage DER est minimal (EX-5.1).", input: { der: "0x" + nonMinimal.toString("hex") }, expected: { refused: true, rule: "AN-5", message: messageRelecture } });
  return {
    fichier: { version: 0, family: "requetes", description: "Requêtes TimeStampReq construites octet pour octet (CT-5 EX-5.1 et annexe A.4) : version 1, messageImprint (SHA-256 avec paramètres NULL, empreinte), reqPolicy facultatif, nonce de 64 bits dérivé d'une étiquette, certReq TRUE.", cases },
    refusees: { version: 0, description: "Constructions refusées par la référence (EX-5.1, AN-5, AN-6) : la requête n'est pas produite, la règle et le message sont rendus.", cases: refusees },
  };
}

// ---------------------------------------------------------------------------
// Famille reponses (EX-5.10 à EX-5.12, A.4)
// ---------------------------------------------------------------------------

/** Autorité de test de CT-6 : clés (entrée), certificats, PEM de l'AC. */
function autoriteTest() {
  const cles = G.chargerCles(path.join(REPERTOIRE_CT6, "rfc3161", "cles"));
  const materiel = G.materielTest(cles);
  const acPem = fs.readFileSync(path.join(REPERTOIRE_CT6, "rfc3161", "cles", "ac-test.pem"), "utf8");
  const tsaPem = fs.readFileSync(path.join(REPERTOIRE_CT6, "rfc3161", "cles", "tsa-test.pem"), "utf8");
  exiger(H.decoderPEM(acPem, "CERTIFICATE").equals(materiel.certs["ac-test"]) && H.decoderPEM(tsaPem, "CERTIFICATE").equals(materiel.certs["tsa-test"]), "certificats de l'autorité de test de CT-6 différents des fichiers publiés");
  return { cles, materiel, acPem };
}

export function familleReponses(requetes, autorite) {
  const { cles, materiel, acPem } = autorite;
  const prestataire = { id: "tsa-test", accepted_policies: [A.POLITIQUE_TEST], anchor_certificates: [acPem], qualified: null };
  const freshness = { max_response_delay_s: 60, clock_tolerance_s: 120 };
  const retry = { initial_ms: 5000, factor: 2, max_ms: 300000, jitter_ms: 250 };
  const requete = (id) => requetes.cases.find((c) => c.id === id);
  const jeton = ({ digest, genTime, serie, nonce, politique = A.POLITIQUE_TEST, certificats = null }) =>
    G.construireJeton({ empreinte: Buffer.from(digest.slice(2), "hex"), genTime, serie, nonce, politique, tsaNom: materiel.nomTsa, certificats: certificats ?? [materiel.certs["tsa-test"]], signataire: certificats?.[0] ?? materiel.certs["tsa-test"], cle: cles["tsa-test"] });
  const genTimeDer = (iso) => iso.replace(/[-:]/g, "").replace("T", "").replace(/\.\d+Z$/, "Z");
  const cases = [];
  const fichiers = {};
  let serie = 1000;
  const ajouter = (id, description, { requete: r, reponse = null, http = {}, sent_at, received_at, tardives = 0, attendu, openssl_verify = null }) => {
    const octetsRequete = Buffer.from(r.expected.der.slice(2), "hex");
    const res = A.evaluerReponse({ requete: octetsRequete, reponse, http, sent_at, received_at, prestataire, freshness, tardives_precedentes: tardives });
    exiger(res.outcome === attendu.outcome && res.error_code === (attendu.error_code ?? null), `réponse ${id} : issue ${res.outcome}/${res.error_code}, attendu ${attendu.outcome}/${attendu.error_code ?? null}`);
    exiger(JSON.stringify(res.warnings) === JSON.stringify(attendu.warnings ?? []), `réponse ${id} : avertissements ${JSON.stringify(res.warnings)}`);
    if (reponse) fichiers[`${id}.tsr`] = reponse;
    if (res.token) fichiers[`${id}.der`] = res.token;
    const reprise = res.class === "transitoire" ? A.calculerAttente({ http_status: res.http_status, retry_after_s: http.retry_after_s ?? null, k: tardives + 1, premier_408_servi: false, retry, gigue: 0 }) : null;
    cases.push({
      id,
      description,
      input: {
        request: `../requetes/${r.expected.file}`,
        request_sha256: r.expected.sha256,
        http: { status: http.status ?? 200, content_type: http.content_type ?? "application/timestamp-reply", body_size: http.body_size ?? (reponse ? reponse.length : 0), retry_after_s: http.retry_after_s ?? null },
        response: reponse ? `${id}.tsr` : null,
        response_sha256: reponse ? sha256Hex(reponse) : null,
        sent_at,
        received_at,
        late_responses_before: tardives,
        checks_passed: res.checks_passed,
      },
      expected: {
        outcome: res.outcome,
        error_code: res.error_code,
        class: res.class,
        critical: res.critical,
        warnings: res.warnings,
        pki_status: res.pki_status,
        failure_info: res.failure_info,
        nonce_in_response: res.nonce_in_response,
        imprint_matches: res.imprint_matches,
        token: res.token ? `${id}.der` : null,
        token_sha256: res.token_sha256,
        token_size: res.token_size,
        gen_time: res.gen_time,
        accuracy_s: res.accuracy_s,
        upper_bound: res.upper_bound,
        retry: reprise,
        openssl_verify,
      },
    });
  };
  // granted pour chaque requête de requetes/
  const granted = [
    ["requete-point-k2", "Le jeton de CT-1 §11.2 lui-même (genTime 2026-11-03T13:53:02Z, numéro de série 1001, nonce de CT-1 §13), reconstruit à l'identique par l'autorité de test : réponse granted.", "2026-11-03T13:53:02Z", 1001, "2026-11-03T13:53:00.000Z", "2026-11-03T13:53:03.000Z"],
    ["point-k2-exemple", "granted de l'autorité de test à la requête point-k2-exemple (sans politique demandée ; la politique de l'autorité est admise).", "2026-11-03T13:53:02Z", null, "2026-11-03T13:53:00.000Z", "2026-11-03T13:53:03.000Z"],
    ["point-k2-exemple-politique-interne", "granted à la requête qui demande la politique 1.3.6.1.4.1.99999.1.1 : le jeton porte la même politique.", "2026-11-03T13:53:02Z", null, "2026-11-03T13:53:00.000Z", "2026-11-03T13:53:03.000Z"],
    ["periode-1-reference", "granted sur le periodHash de la période 1 de référence (genTime 14:00:05).", "2026-11-03T14:00:05Z", null, "2026-11-03T14:00:04.000Z", "2026-11-03T14:00:05.000Z"],
    ["periode-1-reference-tentative-2", "granted à la deuxième tentative (nonce frais).", "2026-11-03T14:00:10Z", null, "2026-11-03T14:00:09.000Z", "2026-11-03T14:00:10.000Z"],
    ["periode-1-vecteurs", "granted sur le periodHash de la période 1 des vecteurs CT-1 (genTime 2026-11-05T10:00:05Z).", "2026-11-05T10:00:05Z", null, "2026-11-05T10:00:04.000Z", "2026-11-05T10:00:05.000Z"],
  ];
  for (const [id, description, genTime, numero, sent, received] of granted) {
    const r = requete(id);
    const n = numero ?? ++serie;
    if (numero !== null) serie = Math.max(serie, numero);
    const token = jeton({ digest: r.input.digest, genTime: genTimeDer(genTime), serie: n, nonce: BigInt(r.expected.nonce) });
    ajouter(`granted-${id}`, description, { requete: r, reponse: A.construireReponseTsa({ status: 0, token }), sent_at: sent, received_at: received, attendu: { outcome: "obtenue" }, openssl_verify: "OK" });
  }
  exiger(fichiers["granted-requete-point-k2.der"].length === 2104 && sha256Hex(fichiers["granted-requete-point-k2.der"]) === "0x0a7cd7a11ffdea5b7ec14f0e9af35588bf8fdfa7fb70ac9b82b6be2d0a389f91", "le jeton de CT-1 §11.2 n'est pas reproduit (2104 octets, SHA-256 0x0a7c…9f91)");
  // écarts sur la requête point-k2-exemple
  const base = requete("point-k2-exemple");
  const nonceBase = BigInt(base.expected.nonce);
  const t0 = { sent_at: "2026-11-03T13:53:00.000Z", received_at: "2026-11-03T13:53:03.000Z" };
  const jetonBase = (autres = {}) => jeton({ digest: base.input.digest, genTime: "20261103135302Z", serie: ++serie, nonce: nonceBase, ...autres });
  ajouter("granted-nonce-different", "granted dont le nonce du TSTInfo diffère de celui de la requête (nonce + 1) : étape 4, erreur permanente nonce_different, alerte, relève (EX-5.10) ; openssl ts -verify -queryfile répond « nonce mismatch ».", { requete: base, reponse: A.construireReponseTsa({ status: 0, token: jetonBase({ nonce: nonceBase + 1n }) }), ...t0, attendu: { outcome: "echec_permanente", error_code: "nonce_different" }, openssl_verify: "nonce mismatch" });
  ajouter("granted-sans-nonce", "granted sans nonce dans le TSTInfo : nonce_absent, permanente (EX-5.10, étape 4).", { requete: base, reponse: A.construireReponseTsa({ status: 0, token: jetonBase({ nonce: null }) }), ...t0, attendu: { outcome: "echec_permanente", error_code: "nonce_absent" } });
  ajouter("granted-autre-empreinte", "granted sur une autre empreinte (le periodHash de la période 1 de référence) : empreinte_differente, permanente (EX-5.10, étape 3).", { requete: base, reponse: A.construireReponseTsa({ status: 0, token: jetonBase({ digest: PERIOD_HASH_1 }) }), ...t0, attendu: { outcome: "echec_permanente", error_code: "empreinte_differente" } });
  ajouter("granted-politique-hors-liste", "granted sous la politique 1.3.6.1.4.1.99999.1.2, hors accepted_policies du prestataire : politique_refusee, permanente (EX-5.10, étape 5).", { requete: base, reponse: A.construireReponseTsa({ status: 0, token: jetonBase({ politique: "1.3.6.1.4.1.99999.1.2" }) }), ...t0, attendu: { outcome: "echec_permanente", error_code: "politique_refusee" } });
  const avecPolitique = requete("point-k2-exemple-politique-interne");
  ajouter("granted-politique-differente", "La requête demandait 1.3.6.1.4.1.99999.1.1, le jeton porte 1.3.6.1.4.1.99999.1.2 : politique_differente, permanente (EX-5.4, EX-5.10 étape 5).", { requete: avecPolitique, reponse: A.construireReponseTsa({ status: 0, token: jeton({ digest: avecPolitique.input.digest, genTime: "20261103135302Z", serie: ++serie, nonce: BigInt(avecPolitique.expected.nonce), politique: "1.3.6.1.4.1.99999.1.2" }) }), ...t0, attendu: { outcome: "echec_permanente", error_code: "politique_differente" } });
  const rejetPolitique = A.construireReponseTsa({ status: 2, status_string: "Requested policy is not supported.", fail_info: "unacceptedPolicy" });
  exiger(rejetPolitique.length === 50, "rejet unacceptedPolicy : 50 octets attendus");
  ajouter("rejet-unacceptedPolicy", "PKIStatus 2 (rejection), PKIFailureInfo unacceptedPolicy, statusString d'openssl ts, 50 octets : echec_unacceptedPolicy, permanente, la requête est en cause (EX-5.12).", { requete: avecPolitique, reponse: rejetPolitique, ...t0, attendu: { outcome: "echec_permanente", error_code: "echec_unacceptedPolicy" } });
  ajouter("rejet-badAlg", "PKIStatus 2, PKIFailureInfo badAlg : echec_badAlg, permanente (EX-5.12).", { requete: base, reponse: A.construireReponseTsa({ status: 2, status_string: "Message digest algorithm is not supported.", fail_info: "badAlg" }), ...t0, attendu: { outcome: "echec_permanente", error_code: "echec_badAlg" } });
  ajouter("rejet-timeNotAvailable", "PKIStatus 2, PKIFailureInfo timeNotAvailable : echec_timeNotAvailable, transitoire, rejouée avec un nouveau nonce (EX-5.12).", { requete: base, reponse: A.construireReponseTsa({ status: 2, fail_info: "timeNotAvailable" }), ...t0, attendu: { outcome: "echec_transitoire", error_code: "echec_timeNotAvailable" } });
  ajouter("waiting", "PKIStatus 3 (waiting), sans jeton : statut_3, transitoire (EX-5.12).", { requete: base, reponse: A.construireReponseTsa({ status: 3 }), ...t0, attendu: { outcome: "echec_transitoire", error_code: "statut_3" } });
  ajouter("statut-5", "PKIStatus 5 (revocationNotification) : statut_5, permanente, alerte critique, relève immédiate (EX-5.12).", { requete: base, reponse: A.construireReponseTsa({ status: 5 }), ...t0, attendu: { outcome: "echec_permanente", error_code: "statut_5" } });
  const t6 = Buffer.from(jetonBase());
  t6[t6.length - 1] ^= 0xff;
  ajouter("t6-signature", "granted dont le dernier octet de la signature est inversé : T-6 échoue à l'acquisition, verification_T-6, permanente, le jeton est conservé comme pièce (EX-5.10, étape 6).", { requete: base, reponse: A.construireReponseTsa({ status: 0, token: t6 }), ...t0, attendu: { outcome: "echec_permanente", error_code: "verification_T-6" } });
  ajouter("http-503-retry-after-30", "Réponse HTTP 503 avec Retry-After: 30 (représentée, sans corps) : http_503, transitoire, reprise à 30 s (EX-5.12, EX-8.9).", { requete: base, http: { status: 503, retry_after_s: 30 }, ...t0, attendu: { outcome: "echec_transitoire", error_code: "http_503" } });
  ajouter("http-429", "HTTP 429 sans Retry-After : http_429, transitoire, attente de retry (5 s à la première reprise, gigue nulle ici).", { requete: base, http: { status: 429 }, ...t0, attendu: { outcome: "echec_transitoire", error_code: "http_429" } });
  ajouter("http-408", "HTTP 408 : http_408, transitoire, rejouée immédiatement une fois (EX-8.9).", { requete: base, http: { status: 408 }, ...t0, attendu: { outcome: "echec_transitoire", error_code: "http_408" } });
  ajouter("http-404", "HTTP 404 : http_404, permanente, jamais rejouée sans modification (EX-5.12).", { requete: base, http: { status: 404 }, ...t0, attendu: { outcome: "echec_permanente", error_code: "http_404" } });
  ajouter("http-401", "HTTP 401 : http_401, permanente, alerte (secret d'accès en cause, section 13).", { requete: base, http: { status: 401 }, ...t0, attendu: { outcome: "echec_permanente", error_code: "http_401" } });
  ajouter("type-contenu", "HTTP 200 de Content-Type text/html : type_contenu, permanente (EX-5.5).", { requete: base, http: { status: 200, content_type: "text/html", body_size: 512 }, ...t0, attendu: { outcome: "echec_permanente", error_code: "type_contenu" } });
  ajouter("corps-trop-long", "HTTP 200 dont le corps fait 131 073 octets (représenté) : taille, permanente, sans lecture (EX-5.5, EX-5.12).", { requete: base, http: { status: 200, body_size: 131073 }, ...t0, attendu: { outcome: "echec_permanente", error_code: "taille" } });
  const okTardif = A.construireReponseTsa({ status: 0, token: jetonBase() });
  ajouter("reponse-tardive-1", "granted valable reçu 63 s après l'envoi (max_response_delay_s 60) : reponse_tardive, le jeton est conservé sans être promu, nouvelle tentative avec un nouveau nonce (EX-5.11).", { requete: base, reponse: okTardif, sent_at: "2026-11-03T13:53:00.000Z", received_at: "2026-11-03T13:54:03.000Z", attendu: { outcome: "reponse_tardive", error_code: "reponse_tardive" }, openssl_verify: "OK" });
  ajouter("reponse-tardive-2", "Deuxième réponse tardive consécutive : encore reponse_tardive (attente de reprise 10 s).", { requete: base, reponse: okTardif, sent_at: "2026-11-03T13:53:00.000Z", received_at: "2026-11-03T13:54:03.000Z", tardives: 1, attendu: { outcome: "reponse_tardive", error_code: "reponse_tardive" }, openssl_verify: "OK" });
  ajouter("reponse-tardive-3", "Troisième réponse tardive consécutive : promue avec l'avertissement reponse_tardive, pour ne pas priver la période d'ancre (EX-5.11).", { requete: base, reponse: okTardif, sent_at: "2026-11-03T13:53:00.000Z", received_at: "2026-11-03T13:54:03.000Z", tardives: 2, attendu: { outcome: "obtenue", warnings: ["reponse_tardive"] }, openssl_verify: "OK" });
  ajouter("horloge-suspecte", "granted dont le genTime (13:53:02) s'écarte de 182 s de l'instant d'envoi (13:50:00), au-delà de clock_tolerance_s (120) : promu, marqué horloge_suspecte (EX-5.11).", { requete: base, reponse: okTardif, sent_at: "2026-11-03T13:50:00.000Z", received_at: "2026-11-03T13:50:02.000Z", attendu: { outcome: "obtenue", warnings: ["horloge_suspecte"] }, openssl_verify: "OK" });
  return {
    fichier: {
      version: 0,
      family: "reponses",
      description: "Réponses TimeStampResp de l'autorité de test de CT-6 (ac-test.pem, tsa-test.pem, politique 1.3.6.1.4.1.99999.1.1) et réponses HTTP représentées, classées selon CT-5 EX-5.10 à EX-5.12 (AN-8 à AN-11). Les vérifications T-1 à T-9 sont exécutées par horodatage.mjs ; `checks_passed` les déclare pour un lecteur qui ne les refait pas. `retry` est l'attente de reprise d'EX-8.9 pour une première reprise (k = late_responses_before + 1), gigue nulle.",
      provider: { id: prestataire.id, accepted_policies: prestataire.accepted_policies, anchor_certificates: ["../../ct-6/rfc3161/cles/ac-test.pem"], qualified: null },
      freshness,
      retry,
      cases,
    },
    fichiers,
  };
}

// ---------------------------------------------------------------------------
// Famille ots (EX-6.4, EX-6.6, A.2)
// ---------------------------------------------------------------------------

export function familleOts() {
  const attente = (uri) => ({ type: "attestation", attestation: { genre: "en_attente", uri } });
  const nomCalendrier = (uri) => new URL(uri).hostname.split(".")[0];
  const K2 = POINTS.K2.hash;
  const cases = [];
  const fichiers = {};
  const decrire = (id, file, octets, { digest, nonce, branches, description }) => {
    const r = O.verifierPreuve(octets, { periodHash: digest, entetes: null, ancres: null, langue: "fr" });
    const statuts = Object.fromEntries(r.checks.map((c) => [c.id, c.reason ? `${c.status}:${c.reason}` : c.status]));
    exiger(statuts["O-1"] === "reussi" && statuts["O-2"] === "reussi" && statuts["O-3"] === "reussi" && statuts["O-7"] === "non_execute:partie_absente", `preuve ${id} : statuts O- ${JSON.stringify(statuts)}`);
    exiger(A.etatPreuve(octets) === "en_attente", `preuve ${id} : en attente attendue`);
    fichiers[file] = octets;
    cases.push({ id, description, file, size: octets.length, sha256: sha256Hex(octets), digest, nonce: "0x" + nonce.toString("hex"), commitment: "0x" + A.engagementOts(digest, nonce).toString("hex"), branches, state: "en_attente", expected_checks: { "O-1": "reussi", "O-2": "reussi", "O-3": "reussi", "O-7": "non_execute", "O-7_reason": "partie_absente" } });
  };
  // point-k2-minimal : l'exemple d'EX-6.4
  const nonceMin = A.nonceOtsDepuisEtiquette("noortrace/vecteurs/v0/ct-5/ots/nonce/point-k2");
  const minimal = A.construireOts({ empreinte: K2, nonce: nonceMin, reponses: A.CALENDRIERS_VECTEURS.map((u) => [attente(u)]) });
  exiger(minimal.length === 195 && sha256Hex(minimal) === "0x64a62afc6526fdd0ea34c57ea70eb8e4711f2fc49ff8fc6a3c4cd38596efa8b6", "point-k2-minimal.ots : 195 octets, SHA-256 0x64a6…a8b6 attendus (EX-6.4)");
  decrire("point-k2-minimal", "point-k2-minimal.ots", minimal, { digest: K2, nonce: nonceMin, description: "L'exemple d'EX-6.4 : checkpointHash K2, nonce dérivé de l'étiquette …/ots/nonce/point-k2, deux attestations en attente nues sous l'engagement, triées par URI (alice avant bob) ; 195 octets.", branches: A.CALENDRIERS_VECTEURS.map((uri) => ({ calendar: nomCalendrier(uri), uri, ops: [], attestation: "en_attente" })) });
  // point-k2-en-attente et periode-1-en-attente : une branche par calendrier (A.2)
  const brancheCalendrier = (sujet, uri) => {
    const argument = sha256(Buffer.from(A.ETIQUETTES.calendrier({ ...sujet, calendrier: nomCalendrier(uri) }), "utf8")).subarray(0, 16);
    return { arbre: O.chemin([{ op: O.OP.prepend, argument }, { op: O.OP.sha256 }], [attente(uri)]), ops: [{ op: "prepend", argument: "0x" + argument.toString("hex") }, { op: "sha256" }] };
  };
  const enAttente = (id, sujet, description, attendus = null) => {
    const nonce = A.nonceOtsDepuisEtiquette(A.ETIQUETTES.nonceOts(sujet));
    const branches = A.CALENDRIERS_VECTEURS.map((uri) => ({ uri, ...brancheCalendrier(sujet, uri) }));
    const octets = A.construireOts({ empreinte: sujet.hash, nonce, reponses: branches.map((b) => b.arbre) });
    if (attendus) exiger(octets.length === attendus.size && sha256Hex(octets) === attendus.sha256 && nonce.toString("hex") === attendus.nonce, `${id}.ots : taille, SHA-256 ou nonce différents d'A.2`);
    decrire(id, `${id}.ots`, octets, { digest: sujet.hash, nonce, description, branches: branches.map((b) => ({ calendar: nomCalendrier(b.uri), uri: b.uri, ops: b.ops, attestation: "en_attente" })) });
  };
  enAttente("point-k2-en-attente", { journal: JOURNAL, sorte: "point", hash: K2 }, "Preuve en attente à deux calendriers sur checkpointHash K2 : nonce dérivé de …/ots/nonce/journal-principal/point/<K2>, puis une branche par calendrier (opération f1 d'un argument de 16 octets dérivé de …/ots/calendrier/<alice|bob>/<sujet>, 08, attestation en attente de l'URI) ; 233 octets.", { size: 233, sha256: "0x8bdf7ed01c73e1b53cb1765e7c456c0ca92056af9685bc3c537a06f51182687a", nonce: "67408294dbd584a4dda160e16129c6b5" });
  enAttente("periode-1-en-attente", { journal: JOURNAL, sorte: "periode", hash: PERIOD_HASH_1 }, "Même construction sur le periodHash de la période 1 de référence (étiquettes …/periode/<periodHash>).");
  // mise à niveau : o7-en-attente.ots → periode-1.ots de CT-6 (lus, jamais copiés)
  const avant = fs.readFileSync(path.join(REPERTOIRE_CT6, "ots", "preuves", "o7-en-attente.ots"));
  const apres = fs.readFileSync(path.join(REPERTOIRE_CT6, "ots", "preuves", "periode-1.ots"));
  const arbreApres = O.lireOts(apres).arbre;
  let noeud = arbreApres;
  for (let i = 0; i < 6; i++) noeud = noeud[0].arbre;
  const reponse = O.encoderArbre(noeud);
  const uri = A.CALENDRIERS_VECTEURS[0];
  const fusion = A.fusionnerOts(avant, { uri, reponse: A.lireReponseCalendrier(reponse) });
  exiger(fusion.equals(apres), "mise à niveau : la fusion de o7-en-attente.ots et de la réponse du calendrier doit redonner periode-1.ots");
  const miseANiveau = {
    version: 0,
    description: "Mise à niveau d'EX-6.6 sur les preuves de CT-6 (lues, non copiées) : la preuve en attente o7-en-attente.ots (attestation en attente du calendrier alice au bout des opérations d'agrégation) reçoit du calendrier, pour son engagement, le Timestamp `response` (opérations Bitcoin imitées puis attestation Bitcoin à la hauteur 1001) ; l'attestation en attente est remplacée par ce chemin et la preuve resérialisée est, octet pour octet, periode-1.ots (EX-6.7 : complete).",
    before: { file: "../../ct-6/ots/preuves/o7-en-attente.ots", size: avant.length, sha256: sha256Hex(avant), state: A.etatPreuve(avant) },
    calendar: uri,
    response: { der: "0x" + reponse.toString("hex"), size: reponse.length, sha256: sha256Hex(reponse) },
    after: { file: "../../ct-6/ots/preuves/periode-1.ots", size: apres.length, sha256: sha256Hex(apres), state: A.etatPreuve(apres) },
    expected: { state_before: "en_attente", state_after: "complete", merged_sha256: sha256Hex(fusion), merged_equals_after: true },
  };
  exiger(miseANiveau.before.state === "en_attente" && miseANiveau.after.state === "complete", "mise à niveau : états avant et après");
  return {
    fichier: { version: 0, family: "ots", description: "Fichiers .ots en attente écrits par CT-5 (EX-6.4) : en-tête, empreinte, f0 nonce (16 octets), 08, puis la fusion des réponses des calendriers dans l'ordre de la bibliothèque de référence (attestations avant opérations ; attestations en attente triées par URI). Lecture par ots.mjs : O-1 à O-3 réussies, O-7 non exécutée (partie_absente) ; réécriture identique par python-opentimestamps (confrontation/).", calendars: [...A.CALENDRIERS_VECTEURS], cases },
    miseANiveau,
    fichiers,
  };
}

// ---------------------------------------------------------------------------
// Famille cout (§12.3)
// ---------------------------------------------------------------------------

export function familleCout() {
  const base = { journals: 1, hours_per_year: 8760, checkpoint_interval_s: 60, rfc3161_checkpoint_interval_s: 300, activity_ratio: 1, checkpoints_provider_role: "second_rang", countersign_idle: false, registry_checkpoints: "nouveaux_evenements", unit_price_qualified: PRIX_SYMBOLIQUES.unit_price_qualified, unit_price_second_rank: PRIX_SYMBOLIQUES.unit_price_second_rank, subscription_fee: 0, subscription_quota: null, billable_retry_ratio: 0 };
  const cases = [];
  const ajouter = (id, description, variations = {}, attenduCout = null) => {
    const input = { ...base, ...variations };
    const expected = A.cout(input);
    if (attenduCout !== null) exiger(expected.cost_per_journal === attenduCout, `coût ${id} : ${expected.cost_per_journal} p, attendu ${attenduCout} p (§12.3)`);
    cases.push({ id, description, input, expected });
  };
  ajouter("defaut-second-rang-a1", "Cadences par défaut, points contresignés par un prestataire de second rang à p_s = 0,2 p_q, activité a = 1, un journal.", {}, 28032);
  ajouter("defaut-second-rang-a025", "Idem, activité a = 0,25 (nouveaux événements à un quart des échéances).", { activity_ratio: 0.25 }, 13578);
  ajouter("points-chez-principal-a025", "Points contresignés par le prestataire principal (qualifié), a = 0,25.", { activity_ratio: 0.25, checkpoints_provider_role: "principal" }, 32850);
  ajouter("points-chez-principal-a1-dix-journaux", "Points chez le principal, a = 1, dix journaux : les maxima de la table CT-5 §4.6.", { checkpoints_provider_role: "principal", journals: 10 }, 105120);
  ajouter("serveur-interne", "Points contresignés par le serveur interne (p_s = 0) ; seule la clôture horaire est facturée.", { checkpoints_provider_role: "interne", unit_price_second_rank: 0 }, 8760);
  ajouter("forfait-avec-quota", "Forfait annuel F = 10 000 p couvrant Q = 10 000 jetons qualifiés, points chez le second rang à p_s = 0,2, a = 1.", { subscription_fee: PRIX_SYMBOLIQUES.subscription_fee, subscription_quota: PRIX_SYMBOLIQUES.subscription_quota }, 29272);
  ajouter("forfait-depasse-points-principal", "Forfait F = 10 000 p, Q = 10 000, points chez le principal, a = 1 : dépassement facturé au jeton.", { subscription_fee: PRIX_SYMBOLIQUES.subscription_fee, subscription_quota: PRIX_SYMBOLIQUES.subscription_quota, checkpoints_provider_role: "principal" }, 105120);
  ajouter("sans-points", "c_T = 3600 (aucun point contresigné) et aucune ancre de point au registre : coût de la version antérieure.", { rfc3161_checkpoint_interval_s: 3600, checkpoints_provider_role: "aucun", registry_checkpoints: "aucun" }, 8760);
  ajouter("preuve-de-vie", "countersign_idle vrai : chaque échéance produit un jeton de second rang, quelle que soit l'activité.", { activity_ratio: 0.1, countersign_idle: true }, 28032);
  ajouter("reprises-facturees", "Dix pour cent de requêtes facturées en plus (r = 0,1), points chez le principal, a = 0,5.", { activity_ratio: 0.5, checkpoints_provider_role: "principal", billable_retry_ratio: 0.1 }, 62634);
  ajouter("cadence-une-minute-principal", "c_T = 60 (une échéance par minute), points chez le principal, a = 1, année bissextile (8 784 h).", { rfc3161_checkpoint_interval_s: 60, checkpoints_provider_role: "principal", hours_per_year: 8784 }, 527040);
  exiger(cases[3].expected.cost_total === 1051200 && cases[0].expected.registry_anchors_per_journal === 543120, "coût : totaux de §12.3 (N_a = 8 760 × 62)");
  // AN-59 : avec a = 1, N_q et N_s égalent la table de 4.6.
  for (const c of cases) {
    if (c.input.activity_ratio !== 1 && !c.input.countersign_idle) continue;
    const n = A.compterJetons({ checkpoint_interval_s: c.input.checkpoint_interval_s, rfc3161: { checkpoints: { interval_s: c.input.rfc3161_checkpoint_interval_s, provider_role: c.input.checkpoints_provider_role } }, registry: { checkpoints: c.input.registry_checkpoints } }, { hours_per_year: c.input.hours_per_year });
    exiger(n.per_year.qualified_tokens === c.expected.qualified_tokens_per_journal && (c.input.checkpoints_provider_role === "principal" || c.input.checkpoints_provider_role === "aucun" ? 0 : n.per_year.checkpoint_tokens) === c.expected.second_rank_tokens_per_journal, `coût ${c.id} : comptages de 4.6`);
  }
  return { version: 0, family: "cout", description: "Cas de la formule de coût de CT-5 §12 (comptages de CT-5 §4.6) : nombres de jetons et d'ancres par journal et par an, coûts en unités symboliques p (aucun prix réel : unit_price_qualified = 1, unit_price_second_rank = 0,2, subscription_fee = 10 000 sont des unités, jamais un prix).", cases };
}

// ---------------------------------------------------------------------------
// Famille completude (AN-61, EX-10.7)
// ---------------------------------------------------------------------------

/** Clé de chaîne de rec-test-01, émettrice de l'ancre du point de la capture de CT-6 (lue, EX-A.2). */
function emetteurCapture() {
  const c = J.analyserJSONStrict(fs.readFileSync(path.join(REPERTOIRE_CT6, "registre", "capture", "capture.json")));
  const e = c.points_de_controle?.[0]?.issuer;
  exiger(typeof e === "string" && /^0x[0-9a-f]{40}$/.test(e), "capture de CT-6 : émetteur de l'ancre du point attendu");
  return e;
}

export function familleCompletude() {
  const S1 = serieSinistres(1);
  const org_id = S1[0].org_id;
  const journal_id = S1[0].journal_id;
  const emetteur = emetteurCapture();
  const AUTRE = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"; // compte Hardhat 1, public : non inscrit comme clé de chaîne
  const ancres = (p, bloc, { issuer = emetteur, doc_type = J.DOC_TYPE_POINT_DE_CONTROLE, log_index = 0 } = {}) => ({ fingerprint: J.empreinteAncrePoint(org_id, journal_id, p.checkpoint_hash), doc_type, block_number: bloc, log_index, issuer });
  const publie = (serie) => [{ org_id, journal_id, points: serie.map((p) => ({ checkpoint_hash: p.checkpoint_hash, checkpoint_ts: p.checkpoint_ts })) }];
  const pt = (hhmm) => S1.find((p) => p.checkpoint_ts.slice(11, 16) === hhmm && p.checkpoint_ts.endsWith(":00.000Z"));
  const cloture = S1[S1.length - 1];
  // Série réécrite par qui tient la clé : à partir de 09:32, racine et last_hash d'une autre version (dérivés
  // d'étiquettes), chaînage et signatures recalculés sous les clés de test de CT-1 §13 (graines publiques).
  const cle = (id) => J.cleEd25519DepuisGraine(J.sha256(Buffer.from(`noortrace/vecteurs/v0/cle-enregistreur/${id}`, "utf8"))).clePrivee;
  const reecrite = [];
  let prec = null;
  for (const p of S1) {
    let point = { ...p.point };
    if (p.checkpoint_ts >= "2026-11-05T09:32:00.000Z") point = { ...point, root: J.sha256(Buffer.from(`noortrace/vecteurs/v0/ct-5/completude/racine-reecrite/${point.tree_size}`, "utf8")), last_hash: J.sha256(Buffer.from(`noortrace/vecteurs/v0/ct-5/completude/dernier-reecrit/${point.tree_size}`, "utf8")) };
    point.prev_checkpoint_hash = prec ? J.hachagePointDeControle(prec) : J.HASH_NUL;
    point = J.signerPointDeControle(point, cle(point.key_id));
    reecrite.push({ checkpoint_hash: J.hachagePointDeControle(point), checkpoint_ts: point.checkpoint_ts, tree_size: point.tree_size });
    prec = point;
  }
  const rpt = (hhmm) => reecrite.find((p) => p.checkpoint_ts.slice(11, 16) === hhmm && p.checkpoint_ts.endsWith(":00.000Z"));
  const cases = [];
  const ajouter = (id, description, input, attendu) => {
    const r = A.verifierCompletudeRegistre({ journaux: input.journals.map((j) => ({ org_id: j.org_id, journal_id: j.journal_id, points: j.points })), ancres: input.anchors, emetteurs: input.issuers, de_bloc: input.from_block, a_bloc: input.to_block });
    const expected = { complete: r.complet, orphans: r.orphelines.map((o) => o.fingerprint), out_of_order: r.hors_ordre.map((o) => o.fingerprint), attached: r.rattachees.length };
    exiger(JSON.stringify(expected) === JSON.stringify(attendu(expected)), `complétude ${id} : ${JSON.stringify(expected)}`);
    cases.push({ id, description, input, expected });
  };
  const base = { from_block: 30000, to_block: 30101, issuers: [emetteur] };
  const nominales = [ancres(pt("09:13"), 30013), ancres(pt("09:32"), 30032), ancres(cloture, 30100)];
  ajouter("serie-publiee-complete", "Série publiée de la période 1 du journal des vecteurs (61 points) et ancres Anchored capturées de la clé de chaîne entre l'ancre de la période précédente (bloc 30000, exclu) et l'ancre de la période (bloc 30101) : les trois points qui engagent un nouvel événement (09:13, 09:32, clôture) ; chaque ancre est rattachée à un point publié, dans l'ordre des checkpoint_ts.", { ...base, journals: publie(S1), anchors: nominales }, (e) => ({ complete: true, orphans: [], out_of_order: [], attached: 3 }));
  ajouter(
    "serie-reecrite-ancres-orphelines",
    "Le détenteur de la clé a réécrit la série à partir de 09:32 (racine et last_hash d'une autre version, chaînage et signatures recalculés) et ancré les nouveaux points aux blocs 30500 et 30501 ; la série publiée est la série réécrite. Les ancres d'origine des blocs 30032 et 30100 ne correspondent à aucun point publié : ancre_orpheline (alerte critique, EX-10.7). Un dossier isolé ne le montre pas (CT-6 §7.9).",
    { ...base, to_block: 30600, journals: publie(reecrite), anchors: [...nominales, ancres(rpt("09:32"), 30500), ancres(reecrite[reecrite.length - 1], 30501)] },
    () => ({ complete: false, orphans: [nominales[1].fingerprint, nominales[2].fingerprint], out_of_order: [], attached: 3 }),
  );
  ajouter("ancres-hors-ordre", "Série publiée d'origine ; l'ancre du point de clôture est incluse au bloc 30020, avant celle du point de 09:32 (bloc 30032) : l'ordre des blocs ne suit pas celui des checkpoint_ts (hors_ordre).", { ...base, journals: publie(S1), anchors: [ancres(pt("09:13"), 30013), ancres(cloture, 30020), ancres(pt("09:32"), 30032)] }, () => ({ complete: false, orphans: [], out_of_order: [nominales[1].fingerprint], attached: 3 }));
  // Premier point de la période 2 qui engage un événement (10:05) : ancré au bloc 30101, après l'ancre du point de
  // clôture de la période 1 (30100) et avant l'ancre de la période 1 (30102), qui attend le reçu de cette dernière (EX-9.4).
  const S2 = serieSinistres(2);
  const suivant = S2.find((p) => p.tree_size > 0);
  const fenetreLongue = { ...base, to_block: 30102 };
  const avecSuivant = [...nominales, ancres(suivant, 30101)];
  ajouter(
    "periode-suivante-dans-la-fenetre",
    "Séries publiées des périodes 1 et 2 du journal des vecteurs, servies ensemble comme EX-10.7 l'exige ; l'ancre de la période 1 est au bloc 30102. Le premier point de la période 2 qui engage un événement (10:05, tree_size 3) est ancré au bloc 30101, dans la fenêtre de la période 1 : il est rattaché à la série de la période 2, et l'ordre est confronté série par série.",
    { ...fenetreLongue, journals: [...publie(S1), ...publie(S2)], anchors: avecSuivant },
    () => ({ complete: true, orphans: [], out_of_order: [], attached: 4 }),
  );
  ajouter(
    "periode-suivante-non-servie",
    "Mêmes ancres, mais la série de la période 2 n'est pas servie : l'ancre du point de 10:05 ne se rattache à aucun point publié et paraît orpheline. C'est pourquoi EX-10.7 exige de servir aussi la série de la période suivante quand elle existe.",
    { ...fenetreLongue, journals: publie(S1), anchors: avecSuivant },
    () => ({ complete: false, orphans: [avecSuivant[3].fingerprint], out_of_order: [], attached: 3 }),
  );
  ajouter(
    "emetteur-doctype-et-fenetre",
    "Série publiée d'origine ; sont ignorées : une ancre de point émise par une adresse qui n'est pas une clé de chaîne inscrite (compte Hardhat 1), une ancre de docType période (celle de la période, même émetteur), une ancre de point antérieure à la fenêtre (bloc 29990) : seules les trois ancres nominales sont confrontées.",
    { ...base, journals: publie(S1), anchors: [ancres(pt("09:13"), 29990, { log_index: 1 }), ...nominales, ancres(pt("09:40"), 30050, { issuer: AUTRE }), { ...ancres(cloture, 30101), doc_type: DOC_TYPE_PERIODE }] },
    () => ({ complete: true, orphans: [], out_of_order: [], attached: 3 }),
  );
  return { version: 0, family: "completude", description: "Complétude au registre (AN-61, EX-10.7) : toute ancre Anchored de docType point de contrôle émise par une clé de chaîne de l'enregistreur dans la fenêtre de la période a pour empreinte keccak256(org_id || journal_id || checkpointHash) d'un point publié de la période ou de la période suivante, et l'ordre des blocs suit celui des checkpoint_ts dans chaque série. Blocs et ancres représentés ; émetteur : clé de chaîne de rec-test-01 de la capture de CT-6.", cases };
}

// ---------------------------------------------------------------------------
// constantes.json (A.2)
// ---------------------------------------------------------------------------

function constantes(ex, requetes, ots) {
  const k2 = ots.cases.find((c) => c.id === "point-k2-en-attente");
  return {
    version: 0,
    description: "Constantes des vecteurs CT-5 (annexe A.2) : identifiants et empreintes de l'exemple de référence de CT-1, étiquettes de dérivation des nonces et des opérations synthétiques, calendriers, prestataires des traces, formes représentées, prix symboliques. Clés et valeurs publiques, sans valeur hors des tests.",
    reference_journal: {
      name: JOURNAL,
      org_id: ORG_ID,
      journal_id: JOURNAL_ID,
      periods: [1, 2].map((n) => ({ index: n, period_start: ex.manifestes[n].period_start, period_end: ex.manifestes[n].period_end, count: ex.manifestes[n].count, period_hash: ex.periodHash[n], generated_at: ex.generatedAt[n], anchor_fingerprint: anchorFingerprint({ orgId: ORG_ID, journalId: JOURNAL_ID, periodHash: ex.periodHash[n] }) })),
      checkpoints: Object.fromEntries(Object.entries(POINTS).map(([nom, p]) => [nom, { checkpoint_hash: p.hash, tree_size: p.tree_size, checkpoint_ts: p.ts, period: p.periode, anchor_fingerprint: J.empreinteAncrePoint(ORG_ID, JOURNAL_ID, p.hash) }])),
    },
    vectors_journal: { name: "journal-sinistres", journal_id: journalIdOf("journal-sinistres"), period_hashes: [...G.PERIOD_HASHES] },
    doc_types: { period: DOC_TYPE_PERIODE, checkpoint: J.DOC_TYPE_POINT_DE_CONTROLE },
    labels: {
      rfc3161_nonce: "noortrace/vecteurs/v0/ct-5/nonce-tsa/<journal>/<periode|point>/<empreinte hex sans 0x>/<n> : 64 premiers bits de SHA-256(UTF-8(étiquette)), entier non signé, n ≥ 1 le rang de la tentative",
      ots_nonce: "noortrace/vecteurs/v0/ct-5/ots/nonce/<journal>/<periode|point>/<empreinte hex sans 0x> : 16 premiers octets de SHA-256(UTF-8(étiquette))",
      calendar_ops: "noortrace/vecteurs/v0/ct-5/ots/calendrier/<alice|bob>/<journal>/<periode|point>/<empreinte hex sans 0x> : 16 premiers octets, argument de f1, puis 08, puis l'attestation en attente de l'URI",
      ct1_example_nonce: { label: ETIQUETTE_NONCE_CT1, nonce: NONCE_CT1 },
      examples: { point_k2_first_attempt_nonce: requetes.cases.find((c) => c.id === "point-k2-exemple").expected.nonce, period_1_first_attempt_nonce: requetes.cases.find((c) => c.id === "periode-1-reference").expected.nonce, point_k2_minimal_ots_nonce: "0x" + A.nonceOtsDepuisEtiquette("noortrace/vecteurs/v0/ct-5/ots/nonce/point-k2").toString("hex"), point_k2_pending_ots: { nonce: k2.nonce, commitment: k2.commitment, alice: k2.branches[0].ops[0].argument, bob: k2.branches[1].ops[0].argument, size: k2.size, sha256: k2.sha256 } },
    },
    calendars: [...A.CALENDRIERS_VECTEURS],
    attempt_id: "<kind>:<16 premiers hex de l'empreinte>:<n>",
    trace_providers: Object.values(PRESTATAIRES),
    represented: { token_sha256: 'SHA-256(UTF-8("jeton <nom>"))', capture_sha256: 'SHA-256(UTF-8("capture <request_id> <bloc>"))', proof_sha256: 'SHA-256(UTF-8("preuve <nom>"))', capture_size: A.TAILLE_INDEX_CAPTURE, token_sizes: { internal_or_test_authority: 2104, qualified: 3082 }, pending_proof_size: 233, complete_proof_size: 316 },
    test_authority: { ca: "../ct-6/rfc3161/cles/ac-test.pem", tsu: "../ct-6/rfc3161/cles/tsa-test.pem", policy_oid: A.POLITIQUE_TEST, key_size: 3072, accuracy_s: 1 },
    symbolic_units: { p_q: PRIX_SYMBOLIQUES.unit_price_qualified, p_s: PRIX_SYMBOLIQUES.unit_price_second_rank, F: PRIX_SYMBOLIQUES.subscription_fee, Q: PRIX_SYMBOLIQUES.subscription_quota, note: "unités symboliques de la section 12 (p_q, p_s, F, Q), jamais un prix (AN-60)" },
  };
}

// ---------------------------------------------------------------------------
// INDEX.md
// ---------------------------------------------------------------------------

function index({ constantes: c, requetes, reponses, ots, traces: tr, cout, reprise }) {
  const L = [];
  L.push("# Vecteurs CT-5 — ancrage");
  L.push("");
  L.push("Produit par `scripts/vecteurs/generer-ct5.mjs` (`npm run vecteurs:ct5`) ; ne pas l'éditer à la main. Spécification : [`spec/CT-5-ancrage.md`](../../CT-5-ancrage.md), annexe A.");
  L.push("");
  L.push("Le générateur rejoue tout à l'identique (EX-A.1) ; il lit sans les réécrire l'exemple de référence de CT-1, les manifestes de `spec/vecteurs/ct-1`, les clés de l'autorité de test de CT-6 et deux preuves de `spec/vecteurs/ct-6/ots/preuves` (EX-A.2), et ne touche jamais à `verificateur-independant/` ni à `confrontation/`. Toutes les valeurs de `cout/` sont des unités symboliques, jamais un prix (AN-60) ; aucune adresse, aucun secret, aucun identifiant de compte ne figure dans ces vecteurs (AN-43).");
  L.push("");
  L.push("## Rejouer");
  L.push("");
  L.push("```bash");
  L.push("npm run vecteurs:ct5                                   # régénère spec/vecteurs/ct-5 (mêmes octets)");
  L.push("node -e 'import(\"./scripts/lib/ancrage.mjs\").then(A => console.log(A.verifierTrace(JSON.parse(require(\"fs\").readFileSync(\"spec/vecteurs/ct-5/planification/heure-nominale-reference.json\",\"utf8\")))))'");
  L.push("cd spec/vecteurs/ct-5/verificateur-independant && go run . ..   # vérificateur Go indépendant (A.5)");
  L.push("```");
  L.push("");
  L.push("## constantes.json (A.2)");
  L.push("");
  L.push("| Grandeur | Valeur |");
  L.push("|---|---|");
  L.push(`| Journal de référence | \`org_id\` \`${c.reference_journal.org_id}\`, \`journal_id\` \`${c.reference_journal.journal_id}\` (\`${c.reference_journal.name}\`) |`);
  for (const p of c.reference_journal.periods) L.push(`| Période ${p.index} | \`[${p.period_start}, ${p.period_end})\`, \`periodHash\` \`${p.period_hash}\`, \`generated_at\` ${p.generated_at}, empreinte d'ancre \`${p.anchor_fingerprint}\` |`);
  for (const [nom, k] of Object.entries(c.reference_journal.checkpoints)) L.push(`| Point ${nom} | \`checkpointHash\` \`${k.checkpoint_hash}\`, \`tree_size\` ${k.tree_size}, \`checkpoint_ts\` ${k.checkpoint_ts}, empreinte d'ancre \`${k.anchor_fingerprint}\` |`);
  L.push(`| Journal des vecteurs | \`journal-sinistres\`, \`periodHash\` ${c.vectors_journal.period_hashes.map((h) => `\`${h}\``).join(", ")} |`);
  L.push(`| \`docType\` | période \`${c.doc_types.period}\`, point \`${c.doc_types.checkpoint}\` |`);
  L.push(`| Nonce RFC 3161 | ${c.labels.rfc3161_nonce} ; CT-1 §13 : \`${c.labels.ct1_example_nonce.label}\` → \`${c.labels.ct1_example_nonce.nonce}\` |`);
  L.push(`| Nonce OpenTimestamps | ${c.labels.ots_nonce} ; \`point-k2-en-attente.ots\` : nonce \`${c.labels.examples.point_k2_pending_ots.nonce}\`, engagement \`${c.labels.examples.point_k2_pending_ots.commitment}\` ; \`point-k2-minimal.ots\` : \`${c.labels.examples.point_k2_minimal_ots_nonce}\` |`);
  L.push(`| Opérations de calendrier | ${c.labels.calendar_ops} ; alice \`${c.labels.examples.point_k2_pending_ots.alice}\`, bob \`${c.labels.examples.point_k2_pending_ots.bob}\` |`);
  L.push(`| Calendriers | ${c.calendars.map((u) => `\`${u}\``).join(", ")} |`);
  L.push(`| \`attempt_id\` | \`${c.attempt_id}\` |`);
  L.push(`| Prestataires des traces | ${c.trace_providers.map((p) => `\`${p.id}\` (${p.role}, qualified ${p.qualified}${p.policy_oid ? `, politique ${p.policy_oid}` : ""})`).join(" ; ")} |`);
  L.push(`| Formes représentées | jeton ${c.represented.token_sha256}, capture ${c.represented.capture_sha256} (${c.represented.capture_size} octets), preuve ${c.represented.proof_sha256} |`);
  L.push(`| Autorité de test | ${c.test_authority.ca}, ${c.test_authority.tsu}, politique \`${c.test_authority.policy_oid}\`, RSA ${c.test_authority.key_size}, précision ${c.test_authority.accuracy_s} s |`);
  L.push(`| Unités symboliques | p_q = ${c.symbolic_units.p_q}, p_s = ${c.symbolic_units.p_s}, F = ${c.symbolic_units.F}, Q = ${c.symbolic_units.Q} : unités, jamais un prix |`);
  L.push("");
  L.push("## requetes/ (EX-5.1, AN-5, AN-6)");
  L.push("");
  L.push("`requetes.json` (`#/$defs/fichier_vecteurs`) : chaque requête `TimeStampReq`, son fichier `.tsq`, octets exacts ; `refusees.json` : constructions que la référence refuse.");
  L.push("");
  L.push("| Cas | Empreinte | Politique | Nonce | Taille | SHA-256 | Fichier |");
  L.push("|---|---|---|---|---|---|---|");
  for (const x of requetes.fichier.cases) L.push(`| \`${x.id}\` | \`${x.input.digest.slice(0, 10)}…\` | ${x.input.policy_oid ?? "—"} | \`${x.expected.nonce}\` | ${x.expected.size} | \`${x.expected.sha256}\` | \`${x.expected.file}\` |`);
  L.push("");
  for (const x of requetes.fichier.cases) L.push(`- \`${x.id}\` : ${x.description}`);
  L.push("");
  L.push("Refusées :");
  L.push("");
  for (const x of requetes.refusees.cases) L.push(`- \`${x.id}\` (${x.expected.rule}) : ${x.description}`);
  L.push("");
  L.push("## reponses/ (EX-5.10 à EX-5.12, AN-8 à AN-11)");
  L.push("");
  L.push("`reponses.json` : chaque réponse (fichier `.tsr`, ou réponse HTTP représentée), la requête à laquelle elle répond, les instants d'envoi et de réception, et l'attendu du classement (issue d'EX-5.13, code d'EX-5.10, classe, avertissements, attente de reprise d'EX-8.9). Le jeton extrait est écrit en `.der`. `openssl_verify` : attendu de `openssl ts -verify -queryfile` (confrontation/).");
  L.push("");
  L.push("| Cas | Requête | Réponse | Issue | Code | Classe | Avertissements | Reprise | openssl |");
  L.push("|---|---|---|---|---|---|---|---|---|");
  for (const x of reponses.fichier.cases) L.push(`| \`${x.id}\` | \`${path.basename(x.input.request)}\` | ${x.input.response ? `\`${x.input.response}\`` : `HTTP ${x.input.http.status}${x.input.http.content_type !== "application/timestamp-reply" ? ` (${x.input.http.content_type})` : ""}${x.input.http.body_size > 131072 ? ` (${x.input.http.body_size} octets)` : ""}`} | ${x.expected.outcome} | ${x.expected.error_code ?? "—"} | ${x.expected.class ?? "—"} | ${x.expected.warnings.join(", ") || "—"} | ${x.expected.retry ? `${x.expected.retry.delay_ms} ms (${x.expected.retry.reason})` : "—"} | ${x.expected.openssl_verify ?? "—"} |`);
  L.push("");
  for (const x of reponses.fichier.cases) L.push(`- \`${x.id}\` : ${x.description}`);
  L.push("");
  L.push("## ots/ (EX-6.4 à EX-6.7, AN-17 à AN-19)");
  L.push("");
  L.push("`ots.json` décrit chaque preuve (empreinte, nonce, engagement, branches) ; `mise-a-niveau.json` la paire avant/après de l'EX-6.6 sur les preuves de CT-6.");
  L.push("");
  L.push("| Preuve | Empreinte | Taille | SHA-256 | Attendu |");
  L.push("|---|---|---|---|---|");
  for (const x of ots.fichier.cases) L.push(`| \`${x.file}\` | \`${x.digest.slice(0, 10)}…\` | ${x.size} | \`${x.sha256}\` | O-1 à O-3 réussies, O-7 non exécutée (partie_absente), en attente |`);
  L.push(`| \`mise-a-niveau.json\` | période 1 des vecteurs CT-1 | ${ots.miseANiveau.before.size} → ${ots.miseANiveau.after.size} | \`${ots.miseANiveau.after.sha256}\` | en_attente → complete, fusion égale à \`periode-1.ots\` |`);
  L.push("");
  for (const x of ots.fichier.cases) L.push(`- \`${x.file}\` : ${x.description}`);
  L.push(`- \`mise-a-niveau.json\` : ${ots.miseANiveau.description}`);
  L.push("");
  L.push("## planification/ (§8.10, AN-32 à AN-42)");
  L.push("");
  L.push("Chaque trace est conforme à la racine de `planificateur-ancrage-v0.schema.json` ; `rejouerTrace` de `scripts/lib/ancrage.mjs` rend `expected` et `queue_after` à l'identique (formes canoniques JCS v0, dans l'ordre). La trace de référence est, forme canonique pour forme canonique, l'exemple de CT-5 §8.10.");
  L.push("");
  L.push("| Trace | Entrées | Actions | File au départ | File à l'arrêt | Règles exercées |");
  L.push("|---|---|---|---|---|---|");
  const regles = {
    "heure-nominale-reference": "EX-4.2, EX-4.3, EX-4.6, EX-4.7, EX-6.2, EX-8.4, EX-8.5",
    "principal-injoignable": "EX-5.7, EX-5.8, EX-5.12, EX-8.6, EX-8.8, EX-8.9 (AN-37, AN-38)",
    "refus-permanent-releve": "EX-4.4, EX-5.7, EX-5.12, EX-8.3, EX-8.8",
    "reponse-tardive": "EX-4.3 (sans_objet), EX-4.6, EX-5.11, EX-8.9",
    "horloge-suspecte": "EX-5.11 (horloge_suspecte), EX-4.3",
    "echeance-remplacee": "EX-4.4, EX-8.4, EX-8.9 (plafond retry.max_ms)",
    "registre-indisponible": "EX-4.5, EX-4.7, EX-8.4, EX-8.10, EX-8.12, EX-9.4, EX-9.6, EX-9.7 (AN-36, AN-40)",
    "redemarrage-reprise": "EX-8.5, EX-8.12 (AN-33)",
    "ots-mise-a-niveau": "EX-6.1, EX-6.6, EX-6.7, EX-8.11 (AN-41)",
    "preuve-de-vie": "EX-4.3 (countersign_idle), EX-4.6, EX-8.4 règle 3",
    "file-pleine": "EX-8.5 règle 4, EX-4.4",
    "prestataire-min-interval": "EX-8.7, EX-5.5, EX-4.4 (AN-39)",
  };
  for (const { trace: t } of tr) L.push(`| \`${t.id}.json\` | ${t.inputs.length} | ${t.expected.length} | ${t.queue_before.length} | ${t.queue_after.length} | ${regles[t.id]} |`);
  L.push("");
  for (const { trace: t } of tr) L.push(`- \`${t.id}\` : ${t.description}`);
  L.push("");
  L.push("## reprise/ (EX-8.12, AN-33)");
  L.push("");
  L.push("Files NDJSON (une demande par ligne, JCS intégral) avant et après le `demarrage` de deux traces : une seule demande par `id`, la dernière ligne fait foi.");
  L.push("");
  for (const r of reprise) L.push(`- \`${r.id}.avant.ndjson\` (${r.avant} ligne(s)), \`${r.id}.apres.ndjson\` (${r.apres} ligne(s)) : file de \`planification/${r.id}.json\`.`);
  L.push("");
  L.push("## cout/ (§12.3, AN-59, AN-60)");
  L.push("");
  L.push("`cout.json` (`#/$defs/fichier_vecteurs`) : les onze cas de §12.3, six grandeurs par cas ; `p` est une unité symbolique.");
  L.push("");
  L.push("| Cas | `N_q` | `N_s` | `N_a` (au plus) | Gaz (au plus) | `C_j` | `C` |");
  L.push("|---|---|---|---|---|---|---|");
  for (const x of cout.cases) L.push(`| \`${x.id}\` | ${x.expected.qualified_tokens_per_journal} | ${x.expected.second_rank_tokens_per_journal} | ${x.expected.registry_anchors_per_journal} | ${x.expected.gas_upper_bound_per_journal} | ${x.expected.cost_per_journal} p | ${x.expected.cost_total} p |`);
  L.push("");
  for (const x of cout.cases) L.push(`- \`${x.id}\` : ${x.description}`);
  L.push("");
  return L.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Génération
// ---------------------------------------------------------------------------

function validerTraces(liste, schema) {
  exiger(J.motsClesHorsSousEnsemble(schema).length === 0, "planificateur-ancrage-v0 : mots-clés hors du sous-ensemble de validerSchema");
  for (const { trace } of liste) {
    const erreurs = J.validerSchema(trace, schema);
    exiger(erreurs.length === 0, `trace ${trace.id} hors schéma : ${JSON.stringify(erreurs.slice(0, 3))}`);
    for (const d of [...trace.queue_before, ...trace.queue_after]) {
      const e = J.validerSchema(d, schema, { fragment: "#/$defs/demande" });
      exiger(e.length === 0, `trace ${trace.id}, demande ${d.id} hors schéma : ${JSON.stringify(e.slice(0, 3))}`);
    }
    exiger(new Set(trace.queue_after.map((d) => d.id)).size === trace.queue_after.length, `trace ${trace.id} : deux demandes de même id`);
    for (const d of trace.queue_after) exiger(d.kind !== "jeton_periode" || !["complete", "sans_objet", "refusee", "remplacee"].includes(d.state), `trace ${trace.id} : jeton_periode dans un état final autre qu'obtenue (AN-34)`);
    exiger(A.verifierTrace(trace).length === 0, `trace ${trace.id} : le rejeu ne redonne pas l'attendu`);
    // chaque request_sha256 est celui de la requête reconstruite avec le nonce indiqué (A.7)
    for (const a of trace.expected.filter((x) => x.action === "envoyer_rfc3161")) {
      const der = A.construireRequete({ digest: a.detail.digest, nonce: BigInt(a.detail.nonce), policy_oid: a.detail.policy_oid });
      exiger(sha256Hex(der) === a.detail.request_sha256 && der.length === a.detail.request_size, `trace ${trace.id} : request_sha256 de ${a.request_id} tentative ${a.detail.attempt}`);
    }
  }
}

/** Trace de référence : identique, forme canonique pour forme canonique, à l'exemple de CT-5 §8.10. */
function confronterReference(trace) {
  const blocs = blocsSpec(SPEC_CT5, "planificateur-ancrage");
  exiger(blocs.length === 1, "CT-5 : un exemple annoté planificateur-ancrage attendu");
  const spec = blocs[0];
  for (const k of ["version", "id", "description", "config", "jitter_ms", "queue_before", "inputs", "expected", "queue_after"]) {
    exiger(J.canonicaliserJCS(spec[k]) === J.canonicaliserJCS(trace[k]), `trace de référence : ${k} différent de l'exemple de CT-5 §8.10`);
  }
}

export function genererCt5({ racine = REPERTOIRE_CT5 } = {}) {
  fs.mkdirSync(racine, { recursive: true });
  const etrangeres = fs.readdirSync(racine).filter((e) => !CONSERVEES.has(e) && !ENTREES_GENEREES.includes(e)).sort();
  exiger(etrangeres.length === 0, `${racine} porte des entrées que le générateur n'écrit pas (${etrangeres.slice(0, 3).join(", ")}) : nommer un répertoire vide ou déjà produit par lui`);
  for (const e of ENTREES_GENEREES) fs.rmSync(path.join(racine, e), { recursive: true, force: true });
  const schema = J.analyserJSONStrict(fs.readFileSync(SCHEMA_PLANIFICATEUR));

  const ex = exempleCT1();
  const requetes = familleRequetes();
  const reponses = familleReponses(requetes.fichier, autoriteTest());
  const ots = familleOts();
  const cout = familleCout();
  const completude = familleCompletude();
  const liste = traces(ex);
  validerTraces(liste, schema);
  confronterReference(liste[0].trace);
  for (const f of [requetes.fichier, cout, completude]) {
    const e = J.validerSchema(f, schema, { fragment: "#/$defs/fichier_vecteurs" });
    exiger(e.length === 0, `famille ${f.family} hors schéma : ${JSON.stringify(e.slice(0, 3))}`);
  }
  const c = constantes(ex, requetes.fichier, ots.fichier);

  // Écriture.
  fs.writeFileSync(path.join(racine, "constantes.json"), texteJSON(c));
  fs.mkdirSync(path.join(racine, "requetes"));
  fs.writeFileSync(path.join(racine, "requetes", "requetes.json"), texteJSON(requetes.fichier));
  fs.writeFileSync(path.join(racine, "requetes", "refusees.json"), texteJSON(requetes.refusees));
  for (const x of requetes.fichier.cases) fs.writeFileSync(path.join(racine, "requetes", x.expected.file), Buffer.from(x.expected.der.slice(2), "hex"));
  fs.mkdirSync(path.join(racine, "reponses"));
  fs.writeFileSync(path.join(racine, "reponses", "reponses.json"), texteJSON(reponses.fichier));
  for (const [nom, octets] of Object.entries(reponses.fichiers)) fs.writeFileSync(path.join(racine, "reponses", nom), octets);
  fs.mkdirSync(path.join(racine, "ots"));
  fs.writeFileSync(path.join(racine, "ots", "ots.json"), texteJSON(ots.fichier));
  fs.writeFileSync(path.join(racine, "ots", "mise-a-niveau.json"), texteJSON(ots.miseANiveau));
  for (const [nom, octets] of Object.entries(ots.fichiers)) fs.writeFileSync(path.join(racine, "ots", nom), octets);
  fs.mkdirSync(path.join(racine, "planification"));
  for (const { trace } of liste) fs.writeFileSync(path.join(racine, "planification", `${trace.id}.json`), texteJSON(trace));
  fs.mkdirSync(path.join(racine, "reprise"));
  const reprise = [];
  for (const { trace, fichiers } of liste) {
    if (trace.queue_before.length === 0) continue;
    // Fichiers de file d'époques successives relus ensemble (EX-8.5, EX-8.12) : leur relecture donne queue_before.
    for (const [i, f] of (fichiers ?? []).entries()) fs.writeFileSync(path.join(racine, "reprise", `${trace.id}.epoque-${i + 1}.ndjson`), f.texte);
    fs.writeFileSync(path.join(racine, "reprise", `${trace.id}.avant.ndjson`), A.ecrireFile(trace.queue_before));
    fs.writeFileSync(path.join(racine, "reprise", `${trace.id}.apres.ndjson`), A.ecrireFile(trace.queue_after));
    const relue = A.lireFile(A.ecrireFile(trace.queue_after));
    exiger(!relue.truncated && relue.errors.length === 0 && relue.demandes.length === trace.queue_after.length, `reprise ${trace.id} : relecture de la file`);
    reprise.push({ id: trace.id, avant: trace.queue_before.length, apres: trace.queue_after.length });
  }
  fs.mkdirSync(path.join(racine, "cout"));
  fs.writeFileSync(path.join(racine, "cout", "cout.json"), texteJSON(cout));
  fs.mkdirSync(path.join(racine, "completude"));
  fs.writeFileSync(path.join(racine, "completude", "completude.json"), texteJSON(completude));
  fs.writeFileSync(path.join(racine, "INDEX.md"), index({ constantes: c, requetes, reponses, ots, traces: liste, cout, reprise }));
  return { constantes: c, requetes, reponses, ots, traces: liste, cout, reprise };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const i = process.argv.indexOf("--sortie");
  if (i !== -1 && (!process.argv[i + 1] || process.argv[i + 1].startsWith("--"))) {
    process.stderr.write("generer-ct5 : --sortie attend un répertoire\n");
    process.exit(2);
  }
  const racine = i !== -1 ? path.resolve(process.argv[i + 1]) : REPERTOIRE_CT5;
  const r = genererCt5({ racine });
  process.stdout.write(`ct-5 : ${r.requetes.fichier.cases.length} requêtes, ${r.reponses.fichier.cases.length} réponses, ${r.ots.fichier.cases.length} preuves, ${r.traces.length} traces, ${r.cout.cases.length} cas de coût sous ${racine}\n`);
}
