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
//   planification/    les soixante-deux traces normatives de §8.10 et A.3,
//                     rejouées par scripts/lib/ancrage.mjs (rejouerTrace),
//                     dont empreinte-squattee (menace MN-58 ; voir
//                     traceEmpreinteSquattee), publiée par défaut depuis la
//                     décision du porteur du 2026-11-16 (variante B) ;
//   reprise/          files NDJSON avant et après le redémarrage des traces qui partent d'une file ;
//   cout/             les onze cas de la formule de coût (§12.3) ;
//   configuration/    cas valides et refusés de la configuration ancrage-v0
//                     (AN-1, EX-4.9 : règles 4, 4 bis et 9 ; complément du
//                     2026-11-16), avec leur verdict et leurs règles violées ;
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
import { fileURLToPath } from "node:url";
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
const ENTREES_GENEREES = ["INDEX.md", "constantes.json", "requetes", "reponses", "ots", "planification", "reprise", "cout", "completude", "configuration"];

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
  /** Démarrage ; `acquisitions` (complément du 2026-11-16, EX-5.8) : enregistrements obtenue promus relus d'acquisitions.ndjson. */
  demarrage(t, { acquisitions = null } = {}) {
    return this.entree(t, "demarrage", acquisitions ? { acquisitions } : {});
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
  /** Clôture d'une période du journal des vecteurs (clotureSinistres), reçue à `t` (son generated_at par défaut). */
  clotureSerie(c, { t = null } = {}) {
    return this.entree(t ?? c.generated_at, "periode_close", c);
  }
  /** Objets durables sans ancre obtenue relus dans le stockage (EX-8.12). */
  stockage(t, { periods = [], checkpoints = [], acquisitions = null }) {
    return this.entree(t, "stockage_relu", { periods, checkpoints: checkpoints.map(donneesPoint), ...(acquisitions ? { acquisitions } : {}) });
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

/**
 * Les soixante-deux traces normatives (A.3), dans l'ordre d'A.3 (23 et 24 : révision 0.6 ; 25 à 28 : revue de l'étape 8,
 * CT-5 EX-8.8, CT-5 EX-8.12, CT-5 EX-8.5 ; 29 à 62 : complément du 2026-11-16). La trace empreinte-squattee (menace
 * MN-58) est publiée par défaut depuis la décision du porteur du 2026-11-16 (variante B) : après le refus de l'ancre de
 * la période, le jeton de clôture reste attente_registre et la période signalée registry_pending (EX-8.4, règle 2 ;
 * AN-36 ; EX-9.7 ; CT-4 EX-8.6) ; empreinte-squattee-repli exerce le repli de clôture après ce refus (EX-8.4, règle 2 ;
 * EX-9.7) et registre-saut-horloge la borne des rejeux par passe (EX-8.10) ; redemarrage-due-at-borne la borne de
 * due_at au démarrage (EX-4.13), redemarrage-jeton-sans-acquisition la réouverture d'EX-5.8, file-perdue-jeton-point-obtenu
 * et file-perdue-jeton-periode-obtenu la demande recréée obtenue d'EX-8.12, depuis le membre acquisitions des entrées
 * demarrage et stockage_relu ; redemarrage-jeton-recree-couvrant EX-4.4 appliquée à une demande recréée obtenue,
 * redemarrage-ancres-a-reprendre le due_at gardé au démarrage par une ancre au registre et une soumission
 * OpenTimestamps a_reprendre, repli-ancre-incluse-jeton-retenu le repli de clôture lu à la lettre (EX-8.4, règle 2) ;
 * ots-reponses-insuffisantes la soumission OpenTimestamps qui obtient moins de min_responses réponses valables (EX-8.11)
 * et redemarrage-ots-soumission-envoyee la soumission en cours close par le redémarrage (EX-8.12, EX-8.9) ;
 * ots-preuve-absente la réponse des calendriers sans preuve écrite (EX-8.11) et les réponses qui ne s'appliquent pas
 * (EX-8.5, règle 2), redemarrage-ots-a-reprendre-en-cours la ligne a_reprendre d'une version antérieure qui porte
 * encore une soumission en cours (EX-8.12, EX-8.16), reponses-hors-tentative les réponses RFC 3161 et événements du
 * registre qui ne s'appliquent pas et les détails des tentatives closes (EX-8.5, EX-5.10, EX-8.10), registre-renvois
 * les renvois au registre et les due_at d'ancre (EX-8.10), redemarrage-releve-deux-series le redémarrage des deux
 * séries de la relève (EX-8.12, EX-8.8), minuteries-simultanees l'ordre de deux minuteries de même échéance
 * (EX-8.16) et jeton-tardif-avertissements la précision hors de la plage d'un instant et la réponse tardive promue avec
 * ses deux avertissements (EX-5.10, EX-5.11) ; redemarrage-ordre-de-la-file et redemarrage-a-envoyer-cle-libre l'ordre
 * du démarrage (une passe sur la file dans l'ordre de la file, a_envoyer comprise, puis les départs ; EX-8.12, EX-9.4),
 * redemarrage-echeances-remplacees les échéances d'une demande remplacee relue (EX-8.12, EX-4.4) et
 * registre-inclusion-apres-attente le délai d'inclusion compté depuis la création de l'ancre (EX-8.10),
 * redemarrage-prestataires-epuises les prestataires épuisés relus de la file au démarrage (EX-8.12, EX-8.8) ;
 * registre-cle-par-journal le verrou de la clé de chaîne, porté par le journal du sujet de l'ancre (EX-9.4) ;
 * minuteries-deux-journaux l'ordre d'armement des minuteries de période de deux journaux au même instant (EX-8.16) ;
 * registre-refus-ancre-periode le refus définitif de l'ancre d'une période (EX-8.10) et registre-ordre-des-points l'ordre
 * des ancres de points d'une clé, par checkpoint_ts (EX-9.4) ; registre-periode-apres-point-de-cloture l'ancre de la
 * période partie après le reçu de celle de son point de clôture (EX-9.4) et redemarrage-ots-abandon-origine l'âge
 * d'abandon d'une preuve OpenTimestamps compté depuis created_at (EX-8.11) ; registre-periode-retient-la-cle l'ancre de
 * période sans reçu qui retient sa clé (EX-9.4), redemarrage-ots-abandon-soumission-tardive la soumission
 * OpenTimestamps aboutie au-delà de l'âge d'abandon (EX-8.11) et registre-refus-ancre-periode-redemarrage l'alerte du
 * refus de l'ancre d'une période levée de nouveau après un redémarrage (EX-8.10) ; registre-points-en-reprise l'ancre d'un
 * point en reprise quand le point suivant de sa période est admis : remplacée si rien n'est parti, attendue sinon
 * (EX-9.5, EX-9.4).
 */
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
    // File écrite avant la révision 0.6 : aucune ligne ne porte attempts_total (EX-8.5, règle 7, lecture).
    for (const d of fileAvant) delete d.attempts_total;
    const s = new Scenario(
      "redemarrage-reprise",
      "La trace de référence interrompue à 14:00:02.500 et redémarrée : la file porte le jeton de K4 envoyee (réponse non reçue), l'ancre de la période envoyee sans reçu, le jeton de clôture en attente_registre et la preuve OpenTimestamps en_attente. Transitions d'EX-8.12 : envoyee devient a_reprendre et repart aussitôt avec un nouveau nonce (tentative 2) ; l'ancre est renvoyée ; l'inclusion est interrogée ; la mise à niveau est reprogrammée à max(due_at, now). La réponse à la tentative 1 de K4, arrivée après le redémarrage, est conservée sans changer l'état (EX-8.5). La file relue a été écrite avant la révision 0.6 : ses lignes ne portent pas attempts_total, qui vaut alors le nombre de leurs tentatives (EX-8.5, règle 7) ; chaque ligne réécrite le porte, une demande que le redémarrage ne réécrit pas garde sa ligne telle quelle.",
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
      "queue.max_pending abaissé à 100 et une file qui porte déjà cent jetons de clôture en a_reprendre (cent heures de panne du prestataire, représentées ; prochaine tentative après la fin de la trace, à 14:30, que retry.max_ms porté à une heure admet : au démarrage, une reprise plus lointaine que retry.max_ms serait ramenée à cette borne, EX-4.13, complément du 2026-11-16) : les points K1, K2 et K4 ne sont plus ancrés (anchor_queue_full, alerte file_pleine critique) mais la clôture crée toujours ses trois demandes et le jeton de clôture est obtenu (EX-8.5, règle 4). Les échéances de points restées ouvertes sont closes remplacee par la clôture (EX-4.4).",
      configuration({ queue: { max_pending: 100 }, retry: { max_ms: 3600000 } }),
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
      "Journal des vecteurs, période 1 (un point par minute) ; le registre n'inclut plus rien à partir de l'ancre du point de 09:13 (inclusion_alert_s porté à 1800 s pour raccourcir la trace). L'ancre du point de 09:32 attend la clé (a_envoyer) puis est remplacée par celle du point de clôture (EX-9.5, rattrapage). À la clôture, le jeton de la période attend l'inclusion de son ancre ; squat_wait_s après la clôture, le point de clôture (tree_size 9, aucune échéance ne l'a sélectionné) reçoit un jeton_point de repli auprès du prestataire des points (EX-4.2, EX-8.4 règle 2), envoyé squat_wait_s plus tard avec ordre_ancres_non_respecte, ce qui borne la date du dernier intervalle. Le registre revient à 10:20 : ancre du point de clôture, puis ancre de la période, puis jeton qualifié de la clôture. EX-9.4 (complément du 2026-11-16 : « l'ancre de la période ne part qu'après le reçu de l'ancre du point de clôture de la même clé ») : l'ancre du point de clôture attendait le nonce à la clôture ; elle part la première au reçu de l'ancre de 09:13, l'ancre de la période à son reçu.",
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
    s.inclusion(jour("10:20:00"), AS(pt(S1, "09:13")), 30013).inclusion(jour("10:20:02"), AS(clotureS1), 31201).inclusion(jour("10:20:04"), APS1, 31203);
    s.granted(jour("10:20:06"), PHS1, 1, { gen_time: "2026-11-05T10:20:05Z", nom: "sinistres periode 1", size: 3082, journal: SIN }).arret(jour("10:21:00"));
    ajouter(s, (t) => [
      ["ancre du point de 09:32 remplacée par celle du point de clôture (EX-9.5)", dem(t, AS(pt(S1, "09:32"))).state === "remplacee" && dem(t, AS(pt(S1, "09:32"))).replaced_by === AS(clotureS1) && actions(t, "envoyer_registre", (a) => a.request_id === AS(pt(S1, "09:32"))).length === 0],
      ["repli : jeton_point du point de clôture sans échéance, créé squat_wait_s après la clôture", actions(t, "journaliser", (a) => a.detail.event === "checkpoint_closing_fallback").length === 1 && JSON.stringify(dem(t, JS(clotureS1)).deadlines) === "[]" && dem(t, JS(clotureS1)).state === "obtenue"],
      ["jeton de repli envoyé avec ordre_ancres_non_respecte", actions(t, "journaliser", (a) => a.request_id === JS(clotureS1) && a.detail.event === "ordre_ancres_non_respecte").length === 1],
      ["contresignature du repli marquée closing_fallback", actions(t, "journaliser", (a) => a.request_id === JS(clotureS1) && a.detail.event === "checkpoint_countersigned")[0]?.detail.closing_fallback === true],
      ["jeton de clôture obtenu après le retour du registre", dem(t, PHS1).state === "obtenue"],
      ["EX-9.4 : l'ancre du point de clôture part au reçu de celle de 09:13, l'ancre de la période au reçu de celle du point de clôture", JSON.stringify(actions(t, "envoyer_registre", (a) => a.t >= jour("10:20:00")).map((a) => [a.t, a.request_id])) === JSON.stringify([[jour("10:20:00"), AS(clotureS1)], [jour("10:20:02"), APS1]])],
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

  // 22. point-manquant-saut-horloge (révision 0.4 ; EX-4.1, 8.9) : le délai de 2 × c_K court depuis le
  // checkpoint_ts du dernier point admis, de sorte qu'un point reçu longtemps après sa production
  // (saut d'horloge, arrêt) lève l'alerte dès sa relecture ; le point de clôture n'en arme aucune.
  {
    const s = new Scenario(
      "point-manquant-saut-horloge",
      "Journal des vecteurs, période 1 : le composant admet le point de 09:00, puis son horloge saute à 12:30 (arrêt du processus ou saut d'horloge) et il reçoit alors, produits à l'heure, le point de 09:59, le point de clôture et la clôture. À 12:30, l'alerte point_manquant due à 09:02 (aucun point pendant 2 x c_K après 09:00) est émise, puis celle due à 10:01 (aucun point pendant 2 x c_K après le checkpoint_ts 09:59 du point admis à 12:30) : le délai court depuis l'instant déclaré du dernier point admis, non depuis son admission (EX-4.1, 8.9) ; le point de clôture n'arme aucune minuterie de cadence. Le point de 09:59, admis 2 h 31 min après sa production, sert D_1 à D_11 (EX-4.3) et sa contresignature est tardive (contresignature_tardive, 8.9).",
      configuration(),
    );
    s.demarrage(jour("08:59:30")).pointSerie(pt(S1, "09:00")).tic(jour("09:01:00")).pointSerie(pt(S1, "09:59"), { t: jour("12:30:00") });
    s.inclusion(jour("12:30:02"), AS(pt(S1, "09:59")), 30359).granted(jour("12:30:04"), JS(pt(S1, "09:59")), 1, { gen_time: "2026-11-05T12:30:03Z", nom: "sinistres point 09:59 tardif", journal: SIN });
    s.pointSerie(clotureS1, { t: jour("12:30:10") }).clotureSerie(C1, { t: jour("12:30:10") }).ots(jour("12:30:11"), OPS1, { nom: "en attente sinistres periode 1 tardive" });
    s.inclusion(jour("12:30:12"), AS(clotureS1), 30360).inclusion(jour("12:30:13"), APS1, 30361).granted(jour("12:30:14"), PHS1, 1, { gen_time: "2026-11-05T12:30:14Z", nom: "sinistres periode 1 tardive", size: 3082, journal: SIN }).arret(jour("12:31:00"));
    ajouter(s, (t) => {
      const alertes = actions(t, "alerter", (a) => a.detail.code === "point_manquant");
      const derniereAvantSaut = t.expected.map((a) => a.t).filter((x) => x <= jour("09:01:00")).length;
      return [
        ["point_manquant due à 09:02 puis due à 10:01, et aucune après le point de clôture", JSON.stringify(alertes.map((a) => a.t)) === JSON.stringify([jour("09:02:00"), jour("10:01:00")])],
        ["les deux alertes sont émises après le saut d'horloge (après toute action de 09:01 ou avant)", alertes.every((a) => t.expected.indexOf(a) >= derniereAvantSaut)],
        ["le point de 09:59 sert D_1 à D_11", JSON.stringify(dem(t, JS(pt(S1, "09:59"))).deadlines) === "[1,2,3,4,5,6,7,8,9,10,11]"],
        ["contresignature tardive du point de 09:59 (genTime − checkpoint_ts > c_T)", actions(t, "alerter", (a) => a.detail.code === "contresignature_tardive" && a.request_id === JS(pt(S1, "09:59"))).length === 1],
      ];
    });
  }

  // 23 et 24. file-fenetre-32 (révision 0.6 ; EX-8.5 règle 7, EX-8.12) : une demande de plus de 32 tentatives.
  const configFenetre = () => configuration({ prestataires: ["principal", "interne"] });
  let fenetre;
  {
    const s = new Scenario(
      "file-fenetre-32",
      "Clôture de la période 1 de référence, sans prestataire de secours (aucune relève) : après l'inclusion de l'ancre de la période, le principal répond 39 fois HTTP 503 avec Retry-After 5 s (attente de 5 s, bornée par [initial_ms, max_ms], EX-8.9) ; la tentative 40 part à 14:03:56 et reste sans réponse. Révision 0.6 (EX-8.5, règle 7) : chaque ligne de la file porte au plus les 32 dernières tentatives, par n croissant, et attempts_total ; la file à l'arrêt porte les tentatives 9 à 40, attempts_total 40, sans renumérotation (n et attempt_id restent uniques). La réponse accordée à la tentative 3, sortie de la fenêtre, arrive tard : elle est conservée (stocker) sans être promue, consignée tentative_close avec son rang et son attempt_id (EX-8.15), et l'état ne change pas.",
      configFenetre(),
    );
    s.demarrage("2026-11-03T13:59:00.000Z").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" }).inclusion("2026-11-03T14:00:02.000Z", AP1, 21087);
    let envoi = "2026-11-03T14:00:02.000Z";
    for (let k = 1; k < 40; k++) {
      s.echec(plusMs(envoi, 1000), PH1, k, { http_status: 503, retry_after_s: 5 });
      envoi = plusMs(envoi, 6000);
    }
    s.tic(envoi).granted(plusMs(envoi, 500), PH1, 3, { gen_time: "2026-11-03T14:00:15Z", nom: "periode 1 tentative 3", size: 3082 }).arret(plusMs(envoi, 4000));
    ajouter(s, (t) => [
      ["40 requêtes, rangs 1 à 40", JSON.stringify(actions(t, "envoyer_rfc3161", (a) => a.request_id === PH1).map((a) => a.detail.attempt)) === JSON.stringify(Array.from({ length: 40 }, (_, i) => i + 1))],
      ["file à l'arrêt : tentatives 9 à 40, attempts_total 40, envoyee", JSON.stringify(dem(t, PH1).attempts.map((a) => a.n)) === JSON.stringify(Array.from({ length: 32 }, (_, i) => i + 9)) && dem(t, PH1).attempts_total === 40 && dem(t, PH1).state === "envoyee"],
      ["aucune ligne écrite de plus de 32 tentatives", s.lignes.every((l) => JSON.parse(l).attempts.length <= 32)],
      ["réponse à la tentative 3 conservée, non promue", actions(t, "stocker", (a) => a.request_id === PH1).length === 1 && actions(t, "journaliser", (a) => a.detail.event === "anchor_response_rejected" && a.detail.error_code === "tentative_close" && a.detail.attempt === 3 && a.detail.attempt_id === A.identifiantCorrelation("jeton_periode", ex.periodHash[1], 3)).length === 1 && dem(t, PH1).result === null],
    ]);
    fenetre = s.trace;
  }
  {
    const s = new Scenario(
      "file-fenetre-32-redemarrage",
      "La trace file-fenetre-32 interrompue et redémarrée à 14:05 sur sa file : le jeton de clôture est envoyee, sa ligne porte les tentatives 9 à 40 et attempts_total 40. Transitions d'EX-8.12 : la tentative 40, en cours, est close (redemarrage) et la demande repart aussitôt au rang attempts_total + 1 = 41, nouveau nonce et nouvel attempt_id, jamais au rang « nombre de tentatives portées + 1 » (révision 0.6 ; EX-8.5, règle 7). La réponse à la tentative 40, reçue après le redémarrage, est conservée sans promotion ; le jeton de la tentative 41 est promu, et la file à l'arrêt porte les tentatives 10 à 41, attempts_total 41.",
      configFenetre(),
      { queue_before: JSON.parse(JSON.stringify(fenetre.queue_after)) },
    );
    s.demarrage("2026-11-03T14:05:00.000Z").granted("2026-11-03T14:05:01.000Z", PH1, 40, { gen_time: "2026-11-03T14:03:57Z", nom: "periode 1 tentative 40", size: 3082 });
    s.granted("2026-11-03T14:05:02.000Z", PH1, 41, { gen_time: "2026-11-03T14:05:01Z", nom: "periode 1 tentative 41", size: 3082 }).arret("2026-11-03T14:06:00.000Z");
    ajouter(s, (t) => [
      ["reprise au rang 41", JSON.stringify(actions(t, "envoyer_rfc3161").map((a) => a.detail.attempt)) === "[41]" && actions(t, "envoyer_rfc3161")[0].t === "2026-11-03T14:05:00.000Z"],
      ["réponse à la tentative 40 conservée, non promue", actions(t, "journaliser", (a) => a.detail.event === "anchor_response_rejected" && a.detail.error_code === "tentative_close" && a.detail.attempt === 40).length === 1],
      ["jeton de la tentative 41 promu ; tentatives 10 à 41, attempts_total 41", dem(t, PH1).state === "obtenue" && dem(t, PH1).result.sha256 === shaTexte("jeton periode 1 tentative 41") && JSON.stringify(dem(t, PH1).attempts.map((a) => a.n)) === JSON.stringify(Array.from({ length: 32 }, (_, i) => i + 10)) && dem(t, PH1).attempts_total === 41],
    ]);
  }

  // 25. releve-pendant-reprise (EX-8.8 ; revue de l'étape 8) : la relève par délai tombe pendant l'attente de reprise du
  // principal ; les deux séries sont poursuivies en parallèle jusqu'à la première promotion.
  {
    const s = new Scenario(
      "releve-pendant-reprise",
      "Clôture de la période 1 de référence ; le principal ne répond pas (délai d'attente dix secondes après chaque départ, gigue nulle, retry.max_ms abaissé à 60 s) : attentes de 5, 10, 20, 40, 60 et 60 s (EX-8.9). La relève par le secours tombe à 14:05:02, 300 s après la première tentative (manifest.fallback_after_s, EX-8.8), pendant que la demande attend sa reprise au principal (a_reprendre, programmée à 14:05:27) : les deux séries de tentatives sont poursuivies en parallèle (tentative 8 au secours à 14:05:02, tentative 9 au principal à 14:05:27, qui échoue encore à 14:05:37), jusqu'au jeton promu du secours à 14:05:40 ; la reprise du principal programmée à 14:06:37 ne part pas (demande finale : les tentatives de l'autre prestataire sont arrêtées, EX-8.8). Revue de l'étape 8.",
      configuration({ retry: { max_ms: 60000 } }),
      { jitter: [0, 0, 0, 0, 0, 0, 0, 0] },
    );
    s.demarrage("2026-11-03T13:59:00.000Z").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" }).inclusion("2026-11-03T14:00:02.000Z", AP1, 21087);
    s.echec("2026-11-03T14:00:12.000Z", PH1, 1, { transport: "delai" });
    s.echec("2026-11-03T14:00:27.000Z", PH1, 2, { transport: "delai" });
    s.echec("2026-11-03T14:00:47.000Z", PH1, 3, { transport: "delai" });
    s.echec("2026-11-03T14:01:17.000Z", PH1, 4, { transport: "delai" });
    s.echec("2026-11-03T14:02:07.000Z", PH1, 5, { transport: "delai" });
    s.echec("2026-11-03T14:03:17.000Z", PH1, 6, { transport: "delai" });
    s.echec("2026-11-03T14:04:27.000Z", PH1, 7, { transport: "delai" });
    s.tic("2026-11-03T14:05:10.000Z");
    s.echec("2026-11-03T14:05:37.000Z", PH1, 9, { transport: "delai" });
    s.granted("2026-11-03T14:05:40.000Z", PH1, 8, { gen_time: "2026-11-03T14:05:39Z", nom: "periode 1 secours", size: 3082 });
    s.arret("2026-11-03T14:07:00.000Z");
    ajouter(s, (t) => {
      const envois = actions(t, "envoyer_rfc3161", (a) => a.request_id === PH1);
      const releve = actions(t, "releve");
      const etatsAvantReleve = actions(t, "ecrire_file", (a) => a.request_id === PH1 && a.t < "2026-11-03T14:05:02.000Z").map((a) => a.detail.state);
      const relevee = actions(t, "journaliser", (a) => a.detail.event === "anchor_fallback");
      return [
        ["relève à 14:05:02 pendant l'attente de reprise (dernier état écrit avant elle : a_reprendre)", releve.length === 1 && releve[0].t === "2026-11-03T14:05:02.000Z" && releve[0].detail.provider === "qtsa-secours" && etatsAvantReleve.at(-1) === "a_reprendre"],
        ["tentative 8 au secours à 14:05:02, puis tentative 9 au principal à 14:05:27 : les deux séries se poursuivent", JSON.stringify(envois.slice(7).map((a) => [a.t, a.detail.provider, a.detail.attempt])) === JSON.stringify([["2026-11-03T14:05:02.000Z", "qtsa-secours", 8], ["2026-11-03T14:05:27.000Z", "qtsa-principal", 9]])],
        ["jeton promu du secours ; aucune requête après la promotion", dem(t, PH1).state === "obtenue" && dem(t, PH1).result.provider === "qtsa-secours" && envois.every((a) => a.t <= "2026-11-03T14:05:40.000Z")],
        ["ligne anchor_fallback de raison delai, portant la tentative 7", relevee.length === 1 && relevee[0].detail.reason === "delai" && relevee[0].detail.attempt === 7],
      ];
    });
  }

  // 26. redemarrage-releve (EX-8.8, EX-8.12 ; revue de l'étape 8) : redémarré pendant la panne du principal, le planificateur
  // repose la minuterie de relève à premier envoi + fallback_after_s.
  {
    const avant = new Scenario("redemarrage-releve-avant", "x", configuration(), { jitter: [0, 0, 0, 0] });
    avant.demarrage("2026-11-03T13:59:00.000Z").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" }).inclusion("2026-11-03T14:00:02.000Z", AP1, 21087);
    avant.echec("2026-11-03T14:00:12.000Z", PH1, 1, { transport: "delai" });
    avant.tic("2026-11-03T14:00:19.000Z");
    avant.construire();
    const fichier = avant.lignes.map((l) => l + "\n").join("");
    const lus = A.lireFile(fichier);
    exiger(!lus.truncated && lus.errors.length === 0 && lus.demandes.find((d) => d.id === PH1)?.state === "envoyee", `redemarrage-releve : file avant le redémarrage (${JSON.stringify({ truncated: lus.truncated, errors: lus.errors, etat: lus.demandes.find((d) => d.id === PH1)?.state })})`);
    const s = new Scenario(
      "redemarrage-releve",
      "Clôture de la période 1 de référence, principal en panne (délais d'attente) ; le processus s'arrête à 14:00:19 pendant la tentative 2 et redémarre à 14:00:20 : envoyee devient a_reprendre et la tentative 3 part aussitôt (EX-8.12) ; la minuterie de relève d'EX-8.8, perdue avec le processus, est reposée à premier envoi (14:00:02) + manifest.fallback_after_s (300 s) = 14:05:02 : le secours est relevé à cet instant (tentative 9), pendant que le principal échoue encore (attentes 5, 10, 20, 40, 80, 160 s), et son jeton est promu à 14:05:05. Sans cette reposition, la demande tournerait indéfiniment sur le principal (revue de l'étape 8).",
      configuration(),
      { jitter: [0, 0, 0, 0, 0, 0, 0, 0], queue_before: lus.demandes },
    );
    s.demarrage("2026-11-03T14:00:20.000Z");
    s.echec("2026-11-03T14:00:30.000Z", PH1, 3, { transport: "delai" });
    s.echec("2026-11-03T14:00:45.000Z", PH1, 4, { transport: "delai" });
    s.echec("2026-11-03T14:01:05.000Z", PH1, 5, { transport: "delai" });
    s.echec("2026-11-03T14:01:35.000Z", PH1, 6, { transport: "delai" });
    s.echec("2026-11-03T14:02:25.000Z", PH1, 7, { transport: "delai" });
    s.echec("2026-11-03T14:03:55.000Z", PH1, 8, { transport: "delai" });
    s.granted("2026-11-03T14:05:05.000Z", PH1, 9, { gen_time: "2026-11-03T14:05:04Z", nom: "periode 1 secours", size: 3082 });
    s.arret("2026-11-03T14:06:00.000Z");
    ajouter(s, (t) => {
      const envois = actions(t, "envoyer_rfc3161", (a) => a.request_id === PH1);
      const releve = actions(t, "releve");
      return [
        ["3 demandes relues ; tentative 3 au principal dès le démarrage", t.expected[0].detail.queue_entries === 3 && envois[0]?.t === "2026-11-03T14:00:20.000Z" && envois[0].detail.attempt === 3 && envois[0].detail.provider === "qtsa-principal"],
        ["relève reposée : action releve à 14:05:02 (premier envoi 14:00:02 + 300 s), anchor_fallback de raison delai", releve.length === 1 && releve[0].t === "2026-11-03T14:05:02.000Z" && actions(t, "journaliser", (a) => a.detail.event === "anchor_fallback" && a.detail.reason === "delai").length === 1],
        ["tentative 9 au secours à 14:05:02, jeton promu du secours", envois.some((a) => a.t === "2026-11-03T14:05:02.000Z" && a.detail.provider === "qtsa-secours" && a.detail.attempt === 9) && dem(t, PH1).state === "obtenue" && dem(t, PH1).result.provider === "qtsa-secours"],
      ];
    });
    liste[liste.length - 1].fichiers = [{ nom: "file-1.ndjson", texte: fichier }];
  }

  // 27. redemarrage-echeance-remplacee (EX-4.4, EX-8.12 ; revue de l'étape 8) : arrêt entre la ligne obtenue du jeton de K2 et
  // la ligne remplacee du jeton de K1 ; au redémarrage, EX-4.4 est appliquée aux demandes de points relues.
  {
    const base = new Scenario("redemarrage-echeance-remplacee-avant", "x", configuration({ retry: { initial_ms: 60000 } }), { jitter: [0, 0, 0, 0] });
    base.demarrage("2026-11-03T13:40:00.000Z").point("K1").inclusion("2026-11-03T13:42:03.000Z", ANCRE("K1"), 20001);
    base.echec("2026-11-03T13:42:08.000Z", JETON("K1"), 1, { transport: "delai" });
    base.echec("2026-11-03T13:43:13.000Z", JETON("K1"), 2, { transport: "delai" });
    base.tic("2026-11-03T13:45:00.000Z");
    base.echec("2026-11-03T13:45:18.000Z", JETON("K1"), 3, { transport: "delai" });
    base.echec("2026-11-03T13:49:23.000Z", JETON("K1"), 4, { transport: "delai" });
    base.tic("2026-11-03T13:50:00.000Z").point("K2").inclusion("2026-11-03T13:53:02.000Z", ANCRE("K2"), 20660).granted("2026-11-03T13:53:04.000Z", JETON("K2"), 1, { gen_time: "2026-11-03T13:53:03Z", nom: "K2" });
    base.construire();
    const etat = (l) => JSON.parse(l);
    const iO = base.lignes.findLastIndex((l) => etat(l).id === JETON("K2") && etat(l).state === "obtenue");
    exiger(iO >= 0 && etat(base.lignes[iO + 1]).id === JETON("K1") && etat(base.lignes[iO + 1]).state === "remplacee", "redemarrage-echeance-remplacee : lignes obtenue de K2 puis remplacee de K1 attendues consécutives");
    const fichier = base.lignes.slice(0, iO + 1).map((l) => l + "\n").join("");
    const lus = A.lireFile(fichier);
    exiger(!lus.truncated && lus.errors.length === 0 && lus.demandes.find((d) => d.id === JETON("K1")).state === "a_reprendre", "redemarrage-echeance-remplacee : file coupée");
    const s = new Scenario(
      "redemarrage-echeance-remplacee",
      "Même panne du serveur interne sur K1 que echeance-remplacee (retry.initial_ms 60 s, gigue nulle) ; le processus s'arrête à 13:53:04 entre la ligne obtenue du jeton de K2 (échéances D_9 et D_10) et la ligne remplacee du jeton de K1 (D_1 à D_8), qu'EX-8.3 fait écrire l'une après l'autre. Au redémarrage à 13:53:04.500, la file porte le jeton de K1 a_reprendre et celui de K2 obtenue : EX-8.12 applique EX-4.4 aux demandes de points relues, la demande de K1 est close remplacee (replaced_by le jeton de K2) avec la ligne checkpoint_anchor_late et l'alerte mineure du serveur interne, et sa reprise programmée à 13:54:23 ne part jamais : aucun rattrapage des points (revue de l'étape 8). La suite de la période est servie normalement.",
      configuration({ retry: { initial_ms: 60000 } }),
      { jitter: [0, 0, 0, 0], queue_before: lus.demandes },
    );
    s.demarrage("2026-11-03T13:53:04.500Z").point("K3").tic("2026-11-03T13:55:00.000Z").point("K4").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" });
    s.inclusion("2026-11-03T14:00:02.000Z", ANCRE("K4"), 21085).granted("2026-11-03T14:00:03.000Z", JETON("K4"), 1, { gen_time: "2026-11-03T14:00:02Z", nom: "K4" });
    s.inclusion("2026-11-03T14:00:04.000Z", AP1, 21087).granted("2026-11-03T14:00:05.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:05Z", nom: "periode 1", size: 3082 }).arret("2026-11-03T14:01:00.000Z");
    ajouter(s, (t) => {
      const remplacer = actions(t, "remplacer", (a) => a.request_id === JETON("K1"));
      const tardif = actions(t, "journaliser", (a) => a.request_id === JETON("K1") && a.detail.event === "checkpoint_anchor_late");
      return [
        ["K1 remplacee au démarrage par le jeton de K2, échéances D_1 à D_8 remplacee", remplacer.length === 1 && remplacer[0].t === "2026-11-03T13:53:04.500Z" && remplacer[0].detail.replaced_by === JETON("K2") && dem(t, JETON("K1")).state === "remplacee" && dem(t, JETON("K1")).replaced_by === JETON("K2") && actions(t, "echeance", (a) => a.request_id === JETON("K1") && a.detail.state === "remplacee").length === 8],
        ["ligne checkpoint_anchor_late et alerte mineure (serveur interne) au démarrage", tardif.length === 1 && JSON.stringify(tardif[0].detail.deadlines) === "[1,2,3,4,5,6,7,8]" && tardif[0].detail.replaced_by === JETON("K2") && actions(t, "alerter", (a) => a.request_id === JETON("K1") && a.detail.code === "checkpoint_anchor_late" && a.detail.severity === "mineure").length === 1],
        ["aucune nouvelle requête RFC 3161 pour K1 : aucun rattrapage", actions(t, "envoyer_rfc3161", (a) => a.request_id === JETON("K1")).length === 0],
        ["clôture servie : jeton de K4 et jeton de clôture obtenus", dem(t, JETON("K4")).state === "obtenue" && dem(t, PH1).state === "obtenue"],
      ];
    });
    liste[liste.length - 1].fichiers = [{ nom: "file-1.ndjson", texte: fichier }];
  }

  // 28. file-lignes-illisibles (EX-8.5 règle 3, EX-8.12 ; revue de l'étape 8) : un fichier de file fini par un
  // fragment et dont une ligne, bien formée en JSON, ne porte pas attempts : la ligne est ignorée et consignée, la ligne valide
  // précédente du même id fait foi, la reprise se fait quel que soit l'état de la file.
  {
    const base = new Scenario("file-lignes-illisibles-avant", "x", configuration());
    base.demarrage("2026-11-03T13:40:00.000Z").point("K1").inclusion("2026-11-03T13:42:03.000Z", ANCRE("K1"), 20001).granted("2026-11-03T13:42:05.000Z", JETON("K1"), 1, { gen_time: "2026-11-03T13:42:04Z", nom: "K1" });
    base.tic("2026-11-03T13:45:00.000Z").tic("2026-11-03T13:50:00.000Z").point("K2").inclusion("2026-11-03T13:53:02.000Z", ANCRE("K2"), 20660).granted("2026-11-03T13:53:04.000Z", JETON("K2"), 1, { gen_time: "2026-11-03T13:53:03Z", nom: "K2" });
    base.point("K3").tic("2026-11-03T13:55:00.000Z").point("K4").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" });
    base.inclusion("2026-11-03T14:00:02.000Z", ANCRE("K4"), 21085);
    base.construire();
    const lignes = [...base.lignes];
    const iK4 = lignes.findLastIndex((l) => JSON.parse(l).id === JETON("K4"));
    const corrompue = JSON.parse(lignes[iK4]);
    exiger(corrompue.state === "envoyee", "file-lignes-illisibles : dernière ligne du jeton de K4 envoyee attendue");
    delete corrompue.attempts;
    lignes[iK4] = A.ligneFile(corrompue);
    const fragment = '{"version":0,"id":"ancre_registre_periode:' + ex.periodHash[1] + '","kind":"ancre_registre_periode","subject":{"kind":"periode"';
    const fichier = lignes.map((l) => l + "\n").join("") + fragment;
    const lus = A.lireFile(fichier);
    exiger(lus.truncated && lus.errors.length === 1 && /mal formée/.test(lus.errors[0]) && lus.demandes.length === 9 && lus.demandes.find((d) => d.id === JETON("K4")).state === "attente_registre", `file-lignes-illisibles : relecture (${JSON.stringify(lus.errors)}, ${lus.truncated})`);
    const s = new Scenario(
      "file-lignes-illisibles",
      "La trace de référence interrompue à 14:00:02 ; sur le disque, la dernière ligne du jeton de K4 (envoyee) a perdu son membre attempts et le fichier finit par un fragment de la ligne suivante (EX-8.5, règle 3 : une ligne tronquée ou mal formée est ignorée et consignée, jamais réparée ; la ligne valide précédente du même id, attente_registre, fait foi). Au redémarrage à 14:00:02.500, la reprise se fait quel que soit l'état de la file relue (EX-8.12) : neuf demandes, le jeton de K4 est en attente_registre et son ancre obtenue, la tentative 1 part aussitôt avec un nonce frais ; la réponse à la tentative perdue serait rejetée tentative_inconnue. Revue de l'étape 8 : fragment de ligne retiré, ligne sans attempts (qui arrêtait la reprise par une exception).",
      configuration(),
      { queue_before: lus.demandes },
    );
    s.demarrage("2026-11-03T14:00:02.500Z").granted("2026-11-03T14:00:03.500Z", JETON("K4"), 1, { gen_time: "2026-11-03T14:00:03Z", nom: "K4 apres redemarrage" });
    s.inclusion("2026-11-03T14:00:04.000Z", AP1, 21087).granted("2026-11-03T14:00:05.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:05Z", nom: "periode 1", size: 3082 }).arret("2026-11-03T14:01:00.000Z");
    ajouter(s, (t) => [
      ["9 demandes relues ; K4 en attente_registre relu puis envoyé aussitôt (tentative 1, ancre déjà obtenue)", t.expected[0].detail.queue_entries === 9 && actions(t, "envoyer_rfc3161", (a) => a.request_id === JETON("K4"))[0]?.t === "2026-11-03T14:00:02.500Z" && actions(t, "envoyer_rfc3161", (a) => a.request_id === JETON("K4"))[0].detail.attempt === 1],
      ["jeton de K4 et jeton de clôture obtenus", dem(t, JETON("K4")).state === "obtenue" && dem(t, PH1).state === "obtenue"],
    ]);
    liste[liste.length - 1].fichiers = [{ nom: "file-1.ndjson", texte: fichier }];
  }

  // 29. empreinte-squattee : l'empreinte d'ancre de la période est prise par un tiers (menace MN-58).
  {
    const s = new Scenario(
      "empreinte-squattee",
      "Clôture de la période 1 de référence ; l'ancre de la période part au registre avant toute requête RFC 3161 sur periodHash (CT-4 EX-8.4, EX-4.7), puis le registre répond empreinte_squattee : l'empreinte est déjà ancrée par un autre émetteur (CT-4 OP-9, §8.3). La demande passe refusee sans nouvel essai, ni renvoi ni remplacement au même nonce, l'alerte est critique et la ligne anchor_refused consigne l'incident (CT-4 EX-8.6 ; EX-8.10, EX-9.7). La requête RFC 3161 du periodHash ne part jamais : son ancre n'est pas incluse (EX-8.4, règle 2 ; AN-36) ; le jeton de clôture reste attente_registre et la période est signalée registry_pending à chaque inclusion_alert_s (60 s ; CT-4 EX-8.6). La preuve OpenTimestamps, soumise à la clôture, reste en attente ; l'ancre et le jeton du point de clôture K4, d'une autre empreinte, sont obtenus : ce jeton date la tête de la période.",
      configuration(),
    );
    s.demarrage("2026-11-03T13:59:00.000Z").point("K4").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" });
    s.inclusion("2026-11-03T14:00:02.000Z", ANCRE("K4"), 21085).granted("2026-11-03T14:00:03.000Z", JETON("K4"), 1, { gen_time: "2026-11-03T14:00:02Z", nom: "K4" });
    s.echecRegistre("2026-11-03T14:00:04.000Z", AP1, "empreinte_squattee");
    s.tic("2026-11-03T14:01:10.000Z").tic("2026-11-03T14:02:10.000Z").arret("2026-11-03T14:03:00.000Z");
    ajouter(s, (t) => {
      const rang = (pred) => t.expected.findIndex(pred);
      const refus = rang((a) => a.action === "journaliser" && a.request_id === AP1 && a.detail.event === "anchor_refused");
      return [
        ["une seule transaction d'ancre de la période, aucun nouvel essai", actions(t, "envoyer_registre", (a) => a.request_id === AP1).length === 1 && actions(t, "journaliser", (a) => a.request_id === AP1 && a.detail.event === "anchor_retry").length === 0],
        ["ancre de la période refusee, tentative unique en échec permanent empreinte_squattee", dem(t, AP1).state === "refusee" && dem(t, AP1).attempts.length === 1 && dem(t, AP1).attempts[0].outcome === "echec_permanente" && dem(t, AP1).attempts[0].error_code === "empreinte_squattee" && dem(t, AP1).result === null],
        ["alerte critique empreinte_squattee et ligne anchor_refused, une fois chacune", actions(t, "alerter", (a) => a.request_id === AP1 && a.detail.code === "empreinte_squattee" && a.detail.severity === "critique").length === 1 && actions(t, "journaliser", (a) => a.detail.event === "anchor_refused" && a.detail.error_code === "empreinte_squattee").length === 1],
        ["aucune requête RFC 3161 sur periodHash ; jeton de clôture en attente_registre", actions(t, "envoyer_rfc3161", (a) => a.request_id === PH1).length === 0 && dem(t, PH1).state === "attente_registre" && dem(t, PH1).attempts.length === 0],
        ["registry_pending consigné à 14:01:00.250 et 14:02:00.250, alerté une fois", JSON.stringify(actions(t, "journaliser", (a) => a.request_id === PH1 && a.detail.event === "registry_pending").map((a) => a.t)) === JSON.stringify(["2026-11-03T14:01:00.250Z", "2026-11-03T14:02:00.250Z"]) && actions(t, "alerter", (a) => a.detail.code === "registry_pending").length === 1],
        ["aucune action sur l'ancre de la période après son refus", t.expected.slice(refus + 1).every((a) => a.request_id !== AP1)],
        ["ancre du point de clôture K4 incluse, jeton de K4 obtenu, preuve OpenTimestamps en attente", dem(t, ANCRE("K4")).state === "obtenue" && dem(t, JETON("K4")).state === "obtenue" && dem(t, OP1).state === "en_attente"],
      ];
    });
  }

  // 30. empreinte-squattee-repli (EX-8.4 règle 2, EX-9.7) : l'ancre de la période est refusée avant squat_wait_s ; le point
  // de clôture, qu'aucune échéance n'a sélectionné, reçoit le jeton de repli, qui date la tête de la période.
  {
    const config = configuration();
    config.rfc3161.checkpoints.interval_s = 600;
    const s = new Scenario(
      "empreinte-squattee-repli",
      "Période 1 de référence avec c_T = 600 s (n_T = 6 ; D_1 à D_5 de 13:10 à 13:50) : K1 sert D_1 à D_4, K2 sert D_5, de sorte que le point de clôture K4 (tree_size 5, nouvel événement) n'est sélectionné par aucune échéance. À la clôture, l'ancre du point de clôture est incluse à 14:00:02 et l'ancre de la période part aussitôt (EX-9.4) ; le registre répond empreinte_squattee à 14:00:03 : demande refusee sans nouvel essai, alerte critique, anchor_refused (EX-9.7 ; CT-4 EX-8.6). Le refus ne libère pas le jeton de clôture, qui reste attente_registre (EX-8.4, règle 2 ; AN-36), et n'abandonne pas le repli : squat_wait_s (5 s) après la clôture, à 14:00:05.250, le point de clôture reçoit une demande jeton_point sans échéance (checkpoint_closing_fallback ; EX-4.2, EX-8.4 règle 2), envoyée aussitôt puisque son ancre est incluse, et obtenue à 14:00:07 : ce jeton date la tête de la période (EX-9.7). La période est signalée registry_pending à chaque inclusion_alert_s (60 s ; CT-4 EX-8.6) ; la preuve OpenTimestamps reste en attente.",
      config,
    );
    s.demarrage("2026-11-03T13:40:00.000Z").point("K1").inclusion("2026-11-03T13:42:03.000Z", ANCRE("K1"), 20001).granted("2026-11-03T13:42:05.000Z", JETON("K1"), 1, { gen_time: "2026-11-03T13:42:04Z", nom: "K1" });
    s.tic("2026-11-03T13:45:00.000Z").tic("2026-11-03T13:50:00.000Z").point("K2").inclusion("2026-11-03T13:53:02.000Z", ANCRE("K2"), 20660).granted("2026-11-03T13:53:04.000Z", JETON("K2"), 1, { gen_time: "2026-11-03T13:53:03Z", nom: "K2" });
    s.point("K3").tic("2026-11-03T13:55:00.000Z").point("K4").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" });
    s.inclusion("2026-11-03T14:00:02.000Z", ANCRE("K4"), 21085).echecRegistre("2026-11-03T14:00:03.000Z", AP1, "empreinte_squattee");
    s.granted("2026-11-03T14:00:07.000Z", JETON("K4"), 1, { gen_time: "2026-11-03T14:00:06Z", nom: "K4" });
    s.tic("2026-11-03T14:01:10.000Z").tic("2026-11-03T14:02:10.000Z").arret("2026-11-03T14:03:00.000Z");
    ajouter(s, (t) => [
      ["K1 sert D_1 à D_4, K2 sert D_5", JSON.stringify(dem(t, JETON("K1")).deadlines) === "[1,2,3,4]" && JSON.stringify(dem(t, JETON("K2")).deadlines) === "[5]"],
      ["ancre de la période envoyée une fois, refusee, alerte critique", actions(t, "envoyer_registre", (a) => a.request_id === AP1).length === 1 && dem(t, AP1).state === "refusee" && actions(t, "alerter", (a) => a.request_id === AP1 && a.detail.code === "empreinte_squattee" && a.detail.severity === "critique").length === 1],
      ["repli à 14:00:05.250 après le refus (checkpoint_closing_fallback)", JSON.stringify(actions(t, "journaliser", (a) => a.detail.event === "checkpoint_closing_fallback").map((a) => [a.t, a.request_id])) === JSON.stringify([["2026-11-03T14:00:05.250Z", JETON("K4")]])],
      ["jeton du point de clôture sans échéance, obtenu, contresignature closing_fallback", JSON.stringify(dem(t, JETON("K4")).deadlines) === "[]" && dem(t, JETON("K4")).state === "obtenue" && actions(t, "journaliser", (a) => a.request_id === JETON("K4") && a.detail.event === "checkpoint_countersigned")[0]?.detail.closing_fallback === true],
      ["aucune requête RFC 3161 sur periodHash ; jeton de clôture en attente_registre", actions(t, "envoyer_rfc3161", (a) => a.request_id === PH1).length === 0 && dem(t, PH1).state === "attente_registre"],
      ["registry_pending consigné à 14:01:00.250 et 14:02:00.250", JSON.stringify(actions(t, "journaliser", (a) => a.request_id === PH1 && a.detail.event === "registry_pending").map((a) => a.t)) === JSON.stringify(["2026-11-03T14:01:00.250Z", "2026-11-03T14:02:00.250Z"])],
    ]);
  }

  // 31. registre-saut-horloge (EX-8.10) : au plus REJEUX_PAR_PASSE_MAX rejeux par minuterie, par demande et par passe.
  {
    const s = new Scenario(
      "registre-saut-horloge",
      "Clôture de la période 1 de référence : l'ancre du point de clôture K4 est incluse et son jeton obtenu ; l'ancre de la période, envoyée à 14:00:02, n'est pas incluse (inclusion_alert_s = 60 s). L'entrée suivante arrive à 14:40:00 (saut d'horloge) : la passe franchit trente-neuf échéances de renvoi de l'ancre (14:01:02 à 14:39:02) et autant d'examen de l'attente du registre (14:01:00.250 à 14:39:00.250). Au plus quatre rejeux par minuterie et par demande (EX-8.10) : l'ancre est renvoyée à 14:01:02 (renvoi des mêmes octets, inclusion_late mineure), puis remplacée au même nonce à 14:02:02, 14:03:02 et 14:04:02 (inclusion_late majeure) ; la ligne anchor_retry du quatrième rejeu (mode renvoi, error_code recu_absent, rang et attempt_id de la tentative close) porte missed_deadlines = 35, les échéances de 14:05:02 à 14:39:02, jamais rejouées une à une, et le renvoi suivant est programmé à 14:40:02. L'attente du registre du jeton de clôture est examinée quatre fois (registry_pending de 14:01:00.250 à 14:04:00.250, alerte majeure une fois), puis à 14:40:00.250 ; les examens sautés ne sont pas consignés. L'ancre est incluse à 14:40:01 et le jeton de clôture obtenu à 14:40:03.",
      configuration(),
    );
    s.demarrage("2026-11-03T13:59:00.000Z").point("K4").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" });
    s.inclusion("2026-11-03T14:00:02.000Z", ANCRE("K4"), 21085).granted("2026-11-03T14:00:03.000Z", JETON("K4"), 1, { gen_time: "2026-11-03T14:00:02Z", nom: "K4" });
    s.tic("2026-11-03T14:40:00.000Z").inclusion("2026-11-03T14:40:01.000Z", AP1, 23487);
    s.granted("2026-11-03T14:40:03.000Z", PH1, 1, { gen_time: "2026-11-03T14:40:02Z", nom: "periode 1", size: 3082 }).arret("2026-11-03T14:41:00.000Z");
    ajouter(s, (t) => {
      const ap1 = dem(t, AP1);
      const retry = actions(t, "journaliser", (a) => a.request_id === AP1 && a.detail.event === "anchor_retry");
      return [
        ["ancre de la période envoyée à 14:00:02 puis rejouée quatre fois dans la passe", JSON.stringify(actions(t, "envoyer_registre", (a) => a.request_id === AP1).map((a) => a.t)) === JSON.stringify(["2026-11-03T14:00:02.000Z", "2026-11-03T14:01:02.000Z", "2026-11-03T14:02:02.000Z", "2026-11-03T14:03:02.000Z", "2026-11-03T14:04:02.000Z"])],
        ["inclusion_late mineure puis trois majeures", JSON.stringify(actions(t, "alerter", (a) => a.request_id === AP1 && a.detail.code === "inclusion_late").map((a) => a.detail.severity)) === JSON.stringify(["mineure", "majeure", "majeure", "majeure"])],
        ["une ligne anchor_retry, au quatrième rejeu, missed_deadlines 35, tentative close 4", retry.length === 1 && retry[0].t === "2026-11-03T14:04:02.000Z" && JSON.stringify(retry[0].detail) === JSON.stringify({ event: "anchor_retry", kind: "ancre_registre_periode", mode: "renvoi", error_code: "recu_absent", missed_deadlines: 35, attempt: 4, attempt_id: A.identifiantCorrelation("ancre_registre_periode", ex.periodHash[1], 4) })],
        ["registry_pending quatre fois dans la passe, puis à 14:40:00.250", JSON.stringify(actions(t, "journaliser", (a) => a.request_id === PH1 && a.detail.event === "registry_pending").map((a) => [a.t, a.detail.age_s])) === JSON.stringify([["2026-11-03T14:01:00.250Z", 60], ["2026-11-03T14:02:00.250Z", 120], ["2026-11-03T14:03:00.250Z", 180], ["2026-11-03T14:04:00.250Z", 240], ["2026-11-03T14:40:00.250Z", 2400]])],
        ["ancre obtenue en cinq tentatives, jeton de clôture obtenu", ap1.state === "obtenue" && ap1.attempts_total === 5 && dem(t, PH1).state === "obtenue"],
      ];
    });
  }

  // 32. redemarrage-due-at-borne (EX-4.13 ; complément du 2026-11-16) : l'heure murale, avancée de deux heures, a daté la
  // reprise d'un jeton ; redémarré après la correction de l'heure, le planificateur ramène ce due_at à now + retry.max_ms.
  {
    const avant = new Scenario("redemarrage-due-at-borne-avant", "x", configuration(), { jitter: [0] });
    avant.demarrage("2026-11-03T13:40:00.000Z").point("K1").inclusion("2026-11-03T13:42:03.000Z", ANCRE("K1"), 20001);
    avant.echec("2026-11-03T15:42:05.000Z", JETON("K1"), 1, { transport: "delai" });
    avant.construire();
    const lus = A.lireFile(avant.lignes.map((l) => l + "\n").join(""));
    const jk1 = lus.demandes.find((d) => d.id === JETON("K1"));
    exiger(!lus.truncated && lus.errors.length === 0 && jk1?.state === "a_reprendre" && jk1.due_at === "2026-11-03T15:42:10.000Z", `redemarrage-due-at-borne : file avant le redémarrage (${JSON.stringify({ etat: jk1?.state, due_at: jk1?.due_at })})`);
    const s = new Scenario(
      "redemarrage-due-at-borne",
      "Période 1 de référence, serveur interne pour les points : la requête du jeton de K1, partie à 13:42:03, reste sans réponse ; l'heure murale ayant avancé de deux heures, son délai est constaté à 15:42:05 et la reprise programmée à 15:42:10 (a_reprendre, retry.initial_ms, gigue nulle). Le composant s'arrête ; l'heure est corrigée ; il redémarre à 13:43:00 sur cette file. EX-4.13 (complément du 2026-11-16) : au démarrage, le due_at d'une demande a_reprendre postérieur à l'instant courant plus retry.max_ms (300 s) est ramené à cette borne, 13:48:00 (programmer backoff, ligne réécrite) ; la tentative 2 part à 13:48:00 et le jeton est obtenu. Sans la borne, la reprise attendrait deux heures.",
      configuration(),
      { queue_before: lus.demandes },
    );
    s.demarrage("2026-11-03T13:43:00.000Z").tic("2026-11-03T13:47:59.000Z").tic("2026-11-03T13:48:00.000Z");
    s.granted("2026-11-03T13:48:01.000Z", JETON("K1"), 2, { gen_time: "2026-11-03T13:48:00Z", nom: "K1 reprise" }).arret("2026-11-03T13:49:00.000Z");
    ajouter(s, (t) => [
      ["due_at ramené à 13:48:00 au démarrage (programmer backoff, puis ligne a_reprendre)", JSON.stringify(t.expected.slice(1, 3).map((a) => [a.t, a.action, a.request_id, a.detail])) === JSON.stringify([["2026-11-03T13:43:00.000Z", "programmer", JETON("K1"), { next_at: "2026-11-03T13:48:00.000Z", reason: "backoff" }], ["2026-11-03T13:43:00.000Z", "ecrire_file", JETON("K1"), { state: "a_reprendre" }]])],
      ["tentative 2 envoyée à 13:48:00, aucune avant", JSON.stringify(actions(t, "envoyer_rfc3161").map((a) => [a.t, a.detail.attempt])) === JSON.stringify([["2026-11-03T13:48:00.000Z", 2]])],
      ["jeton de K1 obtenu", dem(t, JETON("K1")).state === "obtenue" && dem(t, JETON("K1")).attempts_total === 2],
    ]);
  }

  const nominale = liste.find((x) => x.trace.id === "heure-nominale-reference").trace;
  const acquisitionDe = (d) => ({ request_id: d.id, result: { ...d.result } });

  // 33. redemarrage-jeton-sans-acquisition (EX-5.8 ; complément du 2026-11-16) : la demande du jeton de clôture est
  // obtenue dans la file, mais acquisitions.ndjson ne porte pas son enregistrement promu : elle est rouverte et renvoyée.
  {
    const file = JSON.parse(JSON.stringify(nominale.queue_after));
    const relues = file.filter((d) => (d.kind === "jeton_point" || d.kind === "jeton_periode") && d.state === "obtenue" && d.id !== PH1).map(acquisitionDe);
    const s = new Scenario(
      "redemarrage-jeton-sans-acquisition",
      "La file finale de la trace de référence, relue au redémarrage de 14:05:00 avec les enregistrements obtenue promus d'acquisitions.ndjson (entrée demarrage, membre acquisitions) : ceux des jetons de K1, K2 et K4 y sont, celui du jeton de clôture manque (fragment perdu, EX-5.14). EX-5.8 (complément du 2026-11-16) : la demande du jeton de clôture, obtenue dans la file sans enregistrement de même token_sha256, est rouverte (résultat effacé, a_reprendre à 14:05:00, ligne réécrite, alerte file_perdue critique) et renvoyée au principal au rang 2 ; le jeton obtenu à 14:05:01 est promu. Les trois autres demandes ne changent pas.",
      configuration(),
      { queue_before: file },
    );
    s.demarrage("2026-11-03T14:05:00.000Z", { acquisitions: relues });
    s.granted("2026-11-03T14:05:01.000Z", PH1, 2, { gen_time: "2026-11-03T14:05:01Z", nom: "periode 1 reprise", size: 3082 }).arret("2026-11-03T14:06:00.000Z");
    ajouter(s, (t) => [
      ["trois enregistrements relus, le jeton de clôture n'en a pas", relues.length === 3],
      ["jeton de clôture rouvert au démarrage : ligne a_reprendre et alerte file_perdue", JSON.stringify(t.expected.slice(1, 3).map((a) => [a.action, a.request_id, a.detail])) === JSON.stringify([["ecrire_file", PH1, { state: "a_reprendre" }], ["alerter", PH1, { code: "file_perdue", severity: "critique" }]])],
      ["renvoyé au principal au rang 2, puis obtenu avec le nouveau jeton", JSON.stringify(actions(t, "envoyer_rfc3161").map((a) => [a.t, a.request_id, a.detail.provider, a.detail.attempt])) === JSON.stringify([["2026-11-03T14:05:00.000Z", PH1, "qtsa-principal", 2]]) && dem(t, PH1).state === "obtenue" && dem(t, PH1).result.sha256 === shaTexte("jeton periode 1 reprise")],
      ["aucune autre demande réécrite", actions(t, "ecrire_file", (a) => a.request_id !== PH1).length === 0],
    ]);
  }

  // 34. file-perdue-jeton-point-obtenu (EX-8.12 ; complément du 2026-11-16) : comme file-perdue, mais acquisitions.ndjson
  // porte le jeton promu de K3 : sa demande est recréée obtenue, sans requête.
  {
    const s = new Scenario(
      "file-perdue-jeton-point-obtenu",
      "Période 1 de l'exemple de référence : la file est perdue après l'obtention du jeton de K3 ; le composant redémarre à 13:56 avec une file vide. L'enregistreur relève dans son stockage les points K1 à K3 (stockage_relu) et le composant y joint l'enregistrement obtenue promu du jeton de K3 relu d'acquisitions.ndjson (membre acquisitions). EX-8.12 (complément du 2026-11-16) : le dernier point de la période ouverte, K3, est traité comme admis ; son ancre au registre est recréée et envoyée, sa demande de jeton est recréée obtenue avec ce résultat, sans requête, et satisfait D_1 à D_10 ; anchoring_queue_rebuilt et alerte file_perdue. La suite de l'heure est servie normalement.",
      configuration(),
    );
    const resultatK3 = { sha256: shaTexte("jeton K3"), size: 2104, provider: "tsa-interne", obtained_at: "2026-11-03T13:54:04.000Z", bound: "2026-11-03T13:54:04.000Z" };
    s.demarrage("2026-11-03T13:56:00.000Z").stockage("2026-11-03T13:56:00.000Z", { checkpoints: ["K1", "K2", "K3"].map((n) => ({ org_id: ORG_ID, journal_id: JOURNAL_ID, period_start: PERIOD_START_1, tree_size: POINTS[n].tree_size, checkpoint_hash: POINTS[n].hash, checkpoint_ts: POINTS[n].ts })), acquisitions: [{ request_id: JETON("K3"), result: resultatK3 }] });
    s.inclusion("2026-11-03T13:56:02.000Z", ANCRE("K3"), 20730);
    s.point("K4").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" });
    s.inclusion("2026-11-03T14:00:02.000Z", ANCRE("K4"), 21085).granted("2026-11-03T14:00:03.000Z", JETON("K4"), 1, { gen_time: "2026-11-03T14:00:02Z", nom: "K4" });
    s.inclusion("2026-11-03T14:00:04.000Z", AP1, 21087).granted("2026-11-03T14:00:05.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:05Z", nom: "periode 1", size: 3082 }).arret("2026-11-03T14:01:00.000Z");
    ajouter(s, (t) => [
      ["deux demandes recréées (ancre et jeton de K3), file_perdue", actions(t, "journaliser", (a) => a.detail.event === "anchoring_queue_rebuilt")[0]?.detail.recreated === 2 && actions(t, "alerter", (a) => a.detail.code === "file_perdue").length === 1],
      ["jeton de K3 recréé obtenu avec le résultat relu, sans requête", JSON.stringify(dem(t, JETON("K3")).result) === JSON.stringify(resultatK3) && dem(t, JETON("K3")).state === "obtenue" && dem(t, JETON("K3")).attempts_total === 0 && actions(t, "envoyer_rfc3161", (a) => a.request_id === JETON("K3")).length === 0],
      ["D_1 à D_10 satisfaites par le jeton recréé", JSON.stringify(actions(t, "echeance", (a) => a.request_id === JETON("K3") && a.detail.state === "satisfaite").map((a) => a.detail.k)) === "[1,2,3,4,5,6,7,8,9,10]"],
      ["ancre de K3 recréée et incluse ; K4 et la clôture servis", dem(t, ANCRE("K3")).state === "obtenue" && dem(t, JETON("K4")).state === "obtenue" && dem(t, PH1).state === "obtenue"],
    ]);
  }

  // 35. file-perdue-jeton-periode-obtenu (EX-8.12 ; complément du 2026-11-16) : la file est perdue après la clôture ; le
  // jeton de clôture promu est relu d'acquisitions.ndjson : sa demande est recréée obtenue, sans requête.
  {
    const s = new Scenario(
      "file-perdue-jeton-periode-obtenu",
      "Période 1 de l'exemple de référence : la file est perdue après l'obtention du jeton de clôture, avant l'inclusion de l'ancre de la période ; le composant redémarre à 14:05 avec une file vide. L'enregistreur relève le manifeste de la période 1, sans ancre obtenue (stockage_relu), et le composant y joint l'enregistrement obtenue promu du jeton de clôture relu d'acquisitions.ndjson (membre acquisitions). EX-8.12 (complément du 2026-11-16) : la période close reçoit ses trois demandes ; celle du jeton de clôture est créée obtenue avec ce résultat, sans requête, et satisfait l'échéance n_T ; l'ancre de la période est envoyée puis incluse ; la preuve OpenTimestamps est soumise ; anchoring_queue_rebuilt et alerte file_perdue.",
      configuration(),
    );
    const resultatPH1 = { sha256: shaTexte("jeton periode 1"), size: 3082, provider: "qtsa-principal", obtained_at: "2026-11-03T14:00:05.000Z", bound: "2026-11-03T14:00:06.000Z" };
    s.demarrage("2026-11-03T14:05:00.000Z").stockage("2026-11-03T14:05:00.000Z", { periods: [sujetPeriode(ex, 1)], acquisitions: [{ request_id: PH1, result: resultatPH1 }] });
    s.inclusion("2026-11-03T14:05:02.000Z", AP1, 21187).ots("2026-11-03T14:05:03.000Z", OP1, { nom: "en attente periode 1" }).arret("2026-11-03T14:06:00.000Z");
    ajouter(s, (t) => [
      ["trois demandes recréées, file_perdue", actions(t, "journaliser", (a) => a.detail.event === "anchoring_queue_rebuilt")[0]?.detail.recreated === 3 && actions(t, "alerter", (a) => a.detail.code === "file_perdue").length === 1],
      ["jeton de clôture recréé obtenu avec le résultat relu, sans requête ni attente du registre", JSON.stringify(dem(t, PH1).result) === JSON.stringify(resultatPH1) && dem(t, PH1).state === "obtenue" && actions(t, "envoyer_rfc3161").length === 0 && actions(t, "programmer", (a) => a.request_id === PH1).length === 0],
      ["échéance n_T satisfaite par le jeton recréé", JSON.stringify(actions(t, "echeance", (a) => a.request_id === PH1).map((a) => a.detail)) === JSON.stringify([{ k: 12, state: "satisfaite" }])],
      ["ancre de la période incluse, preuve en attente", dem(t, AP1).state === "obtenue" && dem(t, OP1).state === "en_attente"],
    ]);
  }

  // 36. redemarrage-jeton-recree-couvrant (EX-8.12, EX-4.4 ; complément du 2026-11-16) : la demande de jeton recréée
  // obtenue s'applique comme à sa promotion : elle clôt remplacee la demande de point relue qui sert des échéances
  // antérieures.
  {
    const avant = new Scenario("redemarrage-jeton-recree-couvrant-avant", "x", configuration(), { jitter: [0] });
    avant.demarrage("2026-11-03T13:40:00.000Z").point("K1").inclusion("2026-11-03T13:42:03.000Z", ANCRE("K1"), 20001);
    avant.echec("2026-11-03T13:42:13.000Z", JETON("K1"), 1, { transport: "delai" });
    avant.construire();
    const lus = A.lireFile(avant.lignes.map((l) => l + "\n").join(""));
    const jk1 = lus.demandes.find((d) => d.id === JETON("K1"));
    exiger(!lus.truncated && lus.errors.length === 0 && jk1?.state === "a_reprendre" && JSON.stringify(jk1.deadlines) === "[1,2,3,4,5,6,7,8]", `redemarrage-jeton-recree-couvrant : file avant le redémarrage (${JSON.stringify({ etat: jk1?.state, deadlines: jk1?.deadlines })})`);
    const resultatK3 = { sha256: shaTexte("jeton K3"), size: 2104, provider: "tsa-interne", obtained_at: "2026-11-03T13:54:04.000Z", bound: "2026-11-03T13:54:04.000Z" };
    const s = new Scenario(
      "redemarrage-jeton-recree-couvrant",
      "Période 1 de l'exemple de référence, serveur interne pour les points. La file relue ne porte que les demandes de K1 : son ancre incluse et son jeton (D_1 à D_8) a_reprendre après un délai d'attente à 13:42:13 ; le fichier de file qui portait la suite est perdu (EX-8.5, règle 6). Au redémarrage de 13:56:00, le jeton de K1, dont la reprise est échue, part aussitôt au rang 2 (EX-8.12). L'enregistreur relit K1 à K3 dans son stockage (stockage_relu) et le composant y joint l'enregistrement obtenue promu du jeton de K3 (membre acquisitions) : K3, dernier point de la période ouverte sans demande, est admis, son ancre recréée et envoyée, et sa demande de jeton recréée obtenue avec ce résultat, sans requête, qui satisfait D_9 et D_10. EX-8.12 (complément du 2026-11-16) : la demande recréée obtenue s'applique comme à sa promotion (EX-4.4 ; EX-8.4, règle 1) : la demande de K1, qui sert D_1 à D_8, est close remplacee (replaced_by le jeton de K3), avec la ligne checkpoint_anchor_late (window_s : borne du jeton de K3 moins D_1) et l'alerte mineure du serveur interne. Sans cette règle, la demande de K1 resterait active pour des échéances déjà couvertes.",
      configuration(),
      { queue_before: lus.demandes },
    );
    s.demarrage("2026-11-03T13:56:00.000Z").stockage("2026-11-03T13:56:00.000Z", { checkpoints: ["K1", "K2", "K3"].map((n) => ({ org_id: ORG_ID, journal_id: JOURNAL_ID, period_start: PERIOD_START_1, tree_size: POINTS[n].tree_size, checkpoint_hash: POINTS[n].hash, checkpoint_ts: POINTS[n].ts })), acquisitions: [{ request_id: JETON("K3"), result: resultatK3 }] });
    s.inclusion("2026-11-03T13:56:02.000Z", ANCRE("K3"), 20730).arret("2026-11-03T13:57:00.000Z");
    ajouter(s, (t) => {
      const late = actions(t, "journaliser", (a) => a.detail.event === "checkpoint_anchor_late");
      return [
        ["jeton de K1 renvoyé au rang 2 au démarrage", JSON.stringify(actions(t, "envoyer_rfc3161").map((a) => [a.t, a.request_id, a.detail.attempt])) === JSON.stringify([["2026-11-03T13:56:00.000Z", JETON("K1"), 2]])],
        ["jeton de K3 recréé obtenu, D_9 et D_10 satisfaites", dem(t, JETON("K3")).state === "obtenue" && JSON.stringify(dem(t, JETON("K3")).deadlines) === "[9,10]" && dem(t, JETON("K3")).attempts_total === 0],
        ["demande de K1 close remplacee par le jeton recréé de K3", dem(t, JETON("K1")).state === "remplacee" && dem(t, JETON("K1")).replaced_by === JETON("K3")],
        ["checkpoint_anchor_late de K1 (D_1 à D_8, window_s 2944), alerte mineure", late.length === 1 && late[0].request_id === JETON("K1") && late[0].detail.window_s === 2944 && JSON.stringify(late[0].detail.deadlines) === "[1,2,3,4,5,6,7,8]" && actions(t, "alerter", (a) => a.detail.code === "checkpoint_anchor_late")[0]?.detail.severity === "mineure"],
      ];
    });
  }

  // 37. redemarrage-ancres-a-reprendre (EX-8.10, EX-8.12, EX-4.13 ; complément du 2026-11-16) : une ancre au registre et
  // une soumission OpenTimestamps a_reprendre gardent leur due_at au démarrage.
  {
    const avant = new Scenario("redemarrage-ancres-a-reprendre-avant", "x", configuration(), { jitter: [0, 0] });
    avant.demarrage("2026-11-03T13:59:00.000Z").cloture(ex, 1).echecRegistre("2026-11-03T14:00:01.000Z", AP1, "noeud_injoignable");
    avant.ots("2026-11-03T14:00:02.000Z", OP1, { calendars_answered: 1, nom: null });
    avant.construire();
    const lus = A.lireFile(avant.lignes.map((l) => l + "\n").join(""));
    const ap = lus.demandes.find((d) => d.id === AP1);
    const op = lus.demandes.find((d) => d.id === OP1);
    exiger(!lus.truncated && lus.errors.length === 0 && ap?.state === "a_reprendre" && ap.due_at === "2026-11-03T14:00:06.000Z" && op?.state === "a_reprendre" && op.due_at === "2026-11-03T14:00:07.000Z", `redemarrage-ancres-a-reprendre : file avant le redémarrage (${JSON.stringify({ ancre: [ap?.state, ap?.due_at], ots: [op?.state, op?.due_at] })})`);
    const s = new Scenario(
      "redemarrage-ancres-a-reprendre",
      "Clôture de la période 1 de référence. Avant l'arrêt, le registre signale noeud_injoignable pour l'ancre de la période (14:00:01) : échec transitoire, l'ancre passe a_reprendre, due_at 14:00:06 (retry.initial_ms, gigue nulle ; ligne anchor_retry de mode reprise, EX-8.10) ; la soumission OpenTimestamps n'obtient qu'un calendrier sur deux (14:00:02) : a_reprendre, due_at 14:00:07 (EX-8.11). Le composant s'arrête et redémarre à 14:00:04 sur cette file. EX-8.12 (a_reprendre garde due_at) et EX-4.13 (complément du 2026-11-16) : ni l'ancre ni la soumission ne repartent au démarrage ; l'ancre est renvoyée à 14:00:06 (rang 2), la soumission rejouée à 14:00:07 avec un nouvel essai (rang 2) ; leurs due_at sont sous la borne t + retry.max_ms. L'ancre est incluse à 14:00:08 ; le jeton de clôture, qui attendait son inclusion (attente_registre), part alors au principal et il est obtenu ; la preuve est en attente à 14:00:09.",
      configuration(),
      { queue_before: lus.demandes, jitter: [] },
    );
    s.demarrage("2026-11-03T14:00:04.000Z").tic("2026-11-03T14:00:05.000Z").tic("2026-11-03T14:00:07.000Z");
    s.inclusion("2026-11-03T14:00:08.000Z", AP1, 21087).ots("2026-11-03T14:00:09.000Z", OP1, { nom: "en attente periode 1" });
    s.granted("2026-11-03T14:00:10.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:10Z", nom: "periode 1", size: 3082 }).arret("2026-11-03T14:01:00.000Z");
    ajouter(s, (t) => [
      ["rien ne repart au démarrage (14:00:04)", actions(t, "envoyer_registre").every((a) => a.t !== "2026-11-03T14:00:04.000Z") && actions(t, "soumettre_ots").every((a) => a.t !== "2026-11-03T14:00:04.000Z")],
      ["ancre de la période renvoyée à 14:00:06 au rang 2", JSON.stringify(actions(t, "envoyer_registre").map((a) => [a.t, a.request_id])) === JSON.stringify([["2026-11-03T14:00:06.000Z", AP1]]) && dem(t, AP1).attempts_total === 2 && dem(t, AP1).state === "obtenue"],
      ["soumission OpenTimestamps rejouée à 14:00:07, puis en attente", JSON.stringify(actions(t, "soumettre_ots").map((a) => [a.t, a.request_id])) === JSON.stringify([["2026-11-03T14:00:07.000Z", OP1]]) && dem(t, OP1).state === "en_attente"],
      ["jeton de clôture envoyé après l'inclusion, obtenu", actions(t, "envoyer_rfc3161", (a) => a.request_id === PH1)[0]?.t === "2026-11-03T14:00:08.000Z" && dem(t, PH1).state === "obtenue"],
    ]);
  }

  // 38. repli-ancre-incluse-jeton-retenu (EX-8.4 règle 2, EX-4.2 ; complément du 2026-11-16) : lu à la lettre, le repli
  // de clôture part quand jeton_periode est encore attente_registre squat_wait_s après la clôture, même si l'ancre de la
  // période est incluse et que seule min_interval_ms du principal retient le jeton.
  {
    const config = configuration({ provider_role: "principal", min_interval: { principal: 480000 } });
    config.rfc3161.checkpoints.interval_s = 600;
    const s = new Scenario(
      "repli-ancre-incluse-jeton-retenu",
      "Période 1 de référence avec c_T = 600 s (n_T = 6) et les points contresignés par le principal, dont min_interval_ms vaut 480 000 (huit minutes) : K1 sert D_1 à D_4 (jeton à 13:42:03), K2 sert D_5 (jeton à 13:53:02, qui rend le principal indisponible jusqu'à 14:01:02), et le point de clôture K4 n'est sélectionné par aucune échéance. À la clôture, l'ancre de K4 est incluse à 14:00:02, puis l'ancre de la période à 14:00:03 : le jeton de clôture est prêt, mais retenu par min_interval_ms jusqu'à 14:01:02 (EX-8.7) ; sa ligne reste attente_registre. EX-8.4, règle 2, lue à la lettre (complément du 2026-11-16) : squat_wait_s (5 s) après la clôture, à 14:00:05.250, jeton_periode est encore attente_registre ; le point de clôture reçoit donc la demande du repli (checkpoint_closing_fallback), prête au principal derrière le jeton de clôture (EX-8.7). À 14:01:02 le jeton de clôture part le premier ; obtenu à 14:01:03, il clôt remplacee la demande du repli, qui n'est jamais envoyée (EX-4.2) : aucun jeton de plus que les maxima d'EX-4.11.",
      config,
    );
    s.demarrage("2026-11-03T13:40:00.000Z").point("K1").inclusion("2026-11-03T13:42:03.000Z", ANCRE("K1"), 20001).granted("2026-11-03T13:42:05.000Z", JETON("K1"), 1, { gen_time: "2026-11-03T13:42:04Z", nom: "K1 qualifie", size: 3082 });
    s.tic("2026-11-03T13:45:00.000Z").tic("2026-11-03T13:50:00.000Z").point("K2").inclusion("2026-11-03T13:53:02.000Z", ANCRE("K2"), 20660).granted("2026-11-03T13:53:04.000Z", JETON("K2"), 1, { gen_time: "2026-11-03T13:53:03Z", nom: "K2 qualifie", size: 3082 });
    s.point("K3").tic("2026-11-03T13:55:00.000Z").point("K4").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" });
    s.inclusion("2026-11-03T14:00:02.000Z", ANCRE("K4"), 21085).inclusion("2026-11-03T14:00:03.000Z", AP1, 21087);
    s.granted("2026-11-03T14:01:03.000Z", PH1, 1, { gen_time: "2026-11-03T14:01:03Z", nom: "periode 1", size: 3082 }).arret("2026-11-03T14:02:00.000Z");
    ajouter(s, (t) => [
      ["K1 sert D_1 à D_4, K2 sert D_5 ; K4 sans échéance", JSON.stringify(dem(t, JETON("K1")).deadlines) === "[1,2,3,4]" && JSON.stringify(dem(t, JETON("K2")).deadlines) === "[5]" && JSON.stringify(dem(t, JETON("K4")).deadlines) === "[]"],
      ["ancre de la période obtenue à 14:00:03, jeton de clôture retenu jusqu'à 14:01:02", dem(t, AP1).state === "obtenue" && JSON.stringify(actions(t, "envoyer_rfc3161", (a) => a.request_id === PH1).map((a) => a.t)) === JSON.stringify(["2026-11-03T14:01:02.000Z"])],
      ["repli à 14:00:05.250 (checkpoint_closing_fallback) malgré l'ancre incluse", JSON.stringify(actions(t, "journaliser", (a) => a.detail.event === "checkpoint_closing_fallback").map((a) => [a.t, a.request_id])) === JSON.stringify([["2026-11-03T14:00:05.250Z", JETON("K4")]])],
      ["repli jamais envoyé, clos remplacee par le jeton de clôture", actions(t, "envoyer_rfc3161", (a) => a.request_id === JETON("K4")).length === 0 && dem(t, JETON("K4")).state === "remplacee" && dem(t, JETON("K4")).replaced_by === PH1 && dem(t, PH1).state === "obtenue"],
    ]);
  }

  // 39. ots-reponses-insuffisantes (EX-8.11, EX-6.2, EX-8.9 ; complément du 2026-11-16) : une soumission OpenTimestamps
  // qui obtient moins de min_responses réponses valables, quelle que soit l'attestation, est rejetée comme une réponse
  // RFC 3161 en échec transitoire (rejeter_reponse, anchor_response_rejected), puis rejouée à l'attente d'EX-8.9.
  {
    const s = new Scenario(
      "ots-reponses-insuffisantes",
      "Clôture de la période 1 de référence, deux calendriers et min_responses 2 (gigues 250 et 500 ms). EX-8.11 (complément du 2026-11-16) : la soumission OpenTimestamps n'obtient qu'un calendrier à 14:00:01 : la tentative 1 est close echec_transitoire, code reponses_insuffisantes, comme une réponse RFC 3161 en échec transitoire (EX-5.12) : action rejeter_reponse de classe transitoire et ligne anchor_response_rejected (rang et attempt_id de la tentative, provider nul) ; la demande passe a_reprendre, programmée à l'attente d'EX-8.9 (k = 1 : retry.initial_ms plus la gigue, 14:00:06.250). La tentative 2 rapporte à 14:00:07 une attestation Bitcoin d'un seul calendrier : moins de min_responses réponses valables, la soumission échoue encore (EX-6.2, point 4), même code, k = 2 (14:00:17.500). La tentative 3 obtient les deux calendriers à 14:00:18 : la preuve est en attente, la série est close (EX-8.9) et la mise à niveau programmée à upgrade.first_after_s. L'ancre de la période est incluse et le jeton de clôture obtenu entre-temps.",
      configuration(),
      { jitter: [250, 500] },
    );
    s.demarrage("2026-11-03T13:59:00.000Z").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { calendars_answered: 1, nom: null });
    s.inclusion("2026-11-03T14:00:02.000Z", AP1, 21087).granted("2026-11-03T14:00:03.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:03Z", nom: "periode 1", size: 3082 });
    s.tic("2026-11-03T14:00:06.250Z").ots("2026-11-03T14:00:07.000Z", OP1, { attestation: "complete", calendars_answered: 1, nom: "complete d'un seul calendrier", size: 316 });
    s.tic("2026-11-03T14:00:17.500Z").ots("2026-11-03T14:00:18.000Z", OP1, { nom: "en attente periode 1" }).arret("2026-11-03T14:01:00.000Z");
    ajouter(s, (t) => {
      const ots = dem(t, OP1);
      const rejets = actions(t, "journaliser", (a) => a.request_id === OP1 && a.detail.event === "anchor_response_rejected");
      return [
        ["deux rejets reponses_insuffisantes de classe transitoire", JSON.stringify(actions(t, "rejeter_reponse").map((a) => [a.t, a.request_id, a.detail.error_code, a.detail.class])) === JSON.stringify([["2026-11-03T14:00:01.000Z", OP1, "reponses_insuffisantes", "transitoire"], ["2026-11-03T14:00:07.000Z", OP1, "reponses_insuffisantes", "transitoire"]])],
        ["deux lignes anchor_response_rejected (rangs 1 et 2, attempt_id, provider nul)", JSON.stringify(rejets.map((a) => [a.detail.error_code, a.detail.attempt, a.detail.attempt_id, a.detail.provider])) === JSON.stringify([["reponses_insuffisantes", 1, A.identifiantCorrelation("ots_periode", ex.periodHash[1], 1), null], ["reponses_insuffisantes", 2, A.identifiantCorrelation("ots_periode", ex.periodHash[1], 2), null]])],
        ["reprises à l'attente d'EX-8.9 (k = 1 puis 2, gigue comprise)", JSON.stringify(actions(t, "programmer", (a) => a.request_id === OP1 && a.detail.reason === "backoff").map((a) => a.detail.next_at)) === JSON.stringify(["2026-11-03T14:00:06.250Z", "2026-11-03T14:00:17.500Z"]) && JSON.stringify(actions(t, "soumettre_ots").map((a) => a.t)) === JSON.stringify(["2026-11-03T14:00:00.250Z", "2026-11-03T14:00:06.250Z", "2026-11-03T14:00:17.500Z"])],
        ["attestation Bitcoin d'un seul calendrier refusée, puis preuve en attente au rang 3", JSON.stringify(ots.attempts.map((a) => [a.n, a.outcome, a.error_code])) === JSON.stringify([[1, "echec_transitoire", "reponses_insuffisantes"], [2, "echec_transitoire", "reponses_insuffisantes"], [3, "obtenue", null]]) && ots.state === "en_attente" && ots.result.sha256 === shaTexte("preuve en attente periode 1")],
        ["même nonce à chaque soumission (EX-6.2)", new Set(actions(t, "soumettre_ots").map((a) => a.detail.nonce)).size === 1],
      ];
    });
  }

  // 40. redemarrage-ots-soumission-envoyee (EX-8.12, EX-8.9, EX-8.11 ; complément du 2026-11-16) : une soumission
  // OpenTimestamps envoyee au démarrage est close redemarrage, comme la tentative d'un jeton, et repart aussitôt ; la
  // tentative redemarrage interrompt sa série.
  {
    const avant = new Scenario("redemarrage-ots-soumission-envoyee-avant", "x", configuration(), { jitter: [0] });
    avant.demarrage("2026-11-03T13:59:00.000Z").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { calendars_answered: 1, nom: null });
    avant.inclusion("2026-11-03T14:00:02.000Z", AP1, 21087).granted("2026-11-03T14:00:03.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:03Z", nom: "periode 1", size: 3082 }).tic("2026-11-03T14:00:06.000Z");
    avant.construire();
    const lus = A.lireFile(avant.lignes.map((l) => l + "\n").join(""));
    const op = lus.demandes.find((d) => d.id === OP1);
    exiger(!lus.truncated && lus.errors.length === 0 && op?.state === "envoyee" && JSON.stringify(op.attempts.map((a) => [a.n, a.outcome, a.error_code])) === JSON.stringify([[1, "echec_transitoire", "reponses_insuffisantes"], [2, "en_cours", null]]) && lus.demandes.filter((d) => d.state === "obtenue").length === 2, `redemarrage-ots-soumission-envoyee : file avant le redémarrage (${JSON.stringify({ etat: op?.state, tentatives: op?.attempts.map((a) => [a.n, a.outcome]) })})`);
    const s = new Scenario(
      "redemarrage-ots-soumission-envoyee",
      "Clôture de la période 1 de référence. Avant l'arrêt, la soumission OpenTimestamps n'a obtenu qu'un calendrier sur deux (14:00:01, tentative 1 close reponses_insuffisantes) et sa reprise est partie à 14:00:06 (tentative 2, envoyee) ; l'ancre de la période et le jeton de clôture sont obtenus. Le composant s'arrête et redémarre à 14:00:30 sur cette file. EX-8.12 (complément du 2026-11-16) : la soumission envoyee est traitée comme la tentative d'un jeton : sa tentative en cours est close echec_transitoire, code redemarrage (la réponse des calendriers a pu se perdre), la demande passe a_reprendre et la soumission repart aussitôt au rang 3, avec le même nonce et le même engagement (EX-6.2). Elle n'obtient encore qu'un calendrier à 14:00:31 : rejeter_reponse et anchor_response_rejected (reponses_insuffisantes, EX-8.11) ; la tentative redemarrage a interrompu la série (EX-8.9) : k = 1, attente retry.initial_ms plus la gigue de 750 ms (14:00:36.750), et non celle de deux ou trois échecs. La tentative 4 obtient les deux calendriers à 14:00:37 : preuve en attente.",
      configuration(),
      { queue_before: lus.demandes, jitter: [750] },
    );
    s.demarrage("2026-11-03T14:00:30.000Z").ots("2026-11-03T14:00:31.000Z", OP1, { calendars_answered: 1, nom: null });
    s.tic("2026-11-03T14:00:36.750Z").ots("2026-11-03T14:00:37.000Z", OP1, { nom: "en attente periode 1" }).arret("2026-11-03T14:01:00.000Z");
    ajouter(s, (t) => {
      const ots = dem(t, OP1);
      return [
        ["au démarrage : tentative 2 close redemarrage, a_reprendre, programmée immédiatement", JSON.stringify(t.expected.filter((a) => a.t === "2026-11-03T14:00:30.000Z" && a.request_id === OP1).map((a) => [a.action, a.detail.state ?? a.detail.reason ?? null])) === JSON.stringify([["ecrire_file", "a_reprendre"], ["programmer", "immediat"], ["ecrire_file", "envoyee"], ["soumettre_ots", null]]) && ots.attempts.find((a) => a.n === 2)?.error_code === "redemarrage"],
        ["soumission rejouée au rang 3 avec le nonce d'avant l'arrêt (EX-6.2)", actions(t, "soumettre_ots")[0]?.detail.nonce === actions(avant.trace, "soumettre_ots")[0]?.detail.nonce && ots.attempts.find((a) => a.n === 3)?.started_at === "2026-11-03T14:00:30.000Z"],
        ["reponses_insuffisantes rejetée et consignée au rang 3", JSON.stringify(actions(t, "rejeter_reponse").map((a) => [a.t, a.detail.error_code, a.detail.class])) === JSON.stringify([["2026-11-03T14:00:31.000Z", "reponses_insuffisantes", "transitoire"]]) && actions(t, "journaliser", (a) => a.detail.event === "anchor_response_rejected" && a.detail.attempt === 3).length === 1],
        ["série interrompue par la tentative redemarrage : k = 1 (5 s plus 750 ms)", JSON.stringify(actions(t, "programmer", (a) => a.request_id === OP1 && a.detail.reason === "backoff").map((a) => a.detail.next_at)) === JSON.stringify(["2026-11-03T14:00:36.750Z"])],
        ["preuve en attente au rang 4", ots.state === "en_attente" && ots.attempts_total === 4 && JSON.stringify(ots.attempts.map((a) => [a.n, a.outcome, a.error_code])) === JSON.stringify([[1, "echec_transitoire", "reponses_insuffisantes"], [2, "echec_transitoire", "redemarrage"], [3, "echec_transitoire", "reponses_insuffisantes"], [4, "obtenue", null]])],
      ];
    });
  }


  // 41. ots-preuve-absente (EX-8.11, EX-8.5 règle 2, 8.9 ; complément du 2026-11-16) : une réponse des calendriers sans
  // preuve écrite n'est jamais promue (soumission : preuve_absente ; mise à niveau : la preuve reste en attente) ; une
  // réponse qui ne s'applique pas est consignée (tentative_close, demande_close, demande_inconnue).
  {
    const OK2 = ID("ots_point", POINTS.K2.hash);
    const s = new Scenario(
      "ots-preuve-absente",
      "Clôture de la période 1 de référence, deux calendriers et min_responses 2 (gigues 250 et 500 ms). EX-8.11 (complément du 2026-11-16) : à 14:00:01 la soumission OpenTimestamps obtient les deux calendriers, attestation en attente, mais sans preuve écrite (proof_sha256 nul) : elle n'est jamais promue ; la tentative 1 est close echec_transitoire, code preuve_absente, avec rejeter_reponse de classe transitoire et la ligne anchor_response_rejected, puis a_reprendre à l'attente d'EX-8.9 (k = 1, 14:00:06.250). Une seconde réponse à 14:00:02, sans tentative en cours, est consignée tentative_close (EX-8.5, règle 2 : rang et attempt_id de la dernière tentative, provider nul, kept faux) et ne change rien. La tentative 2 rapporte à 14:00:07 une attestation Bitcoin de deux calendriers, toujours sans preuve : preuve_absente, k = 2 (14:00:17.500). La tentative 3 obtient la preuve en attente à 14:00:18 ; la mise à niveau part à upgrade.first_after_s (20:00:18). Sa réponse à 20:00:19 annonce une attestation Bitcoin sans preuve écrite : la preuve reste en attente, comme après une réponse 404, et la mise à niveau suivante part à upgrade.interval_s (20:30:19) ; elle rend l'attestation Bitcoin avec sa preuve à 20:30:20 : complete. Une réponse tardive à 20:30:21 est consignée demande_close (kept vrai : elle portait une preuve) ; une réponse des calendriers à une demande que la file ne connaît pas (ots_point de K2), demande_inconnue.",
      configuration(),
      { jitter: [250, 500] },
    );
    s.demarrage("2026-11-03T13:59:00.000Z").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: null });
    s.ots("2026-11-03T14:00:02.000Z", OP1, { nom: null });
    s.inclusion("2026-11-03T14:00:03.000Z", AP1, 21087).granted("2026-11-03T14:00:04.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:04Z", nom: "periode 1", size: 3082 });
    s.tic("2026-11-03T14:00:06.250Z").ots("2026-11-03T14:00:07.000Z", OP1, { attestation: "complete", nom: null });
    s.tic("2026-11-03T14:00:17.500Z").ots("2026-11-03T14:00:18.000Z", OP1, { nom: "en attente periode 1" });
    s.tic("2026-11-03T20:00:18.000Z").ots("2026-11-03T20:00:19.000Z", OP1, { attestation: "complete", nom: null });
    s.tic("2026-11-03T20:30:19.000Z").ots("2026-11-03T20:30:20.000Z", OP1, { attestation: "complete", nom: "complete periode 1", size: 316 });
    s.ots("2026-11-03T20:30:21.000Z", OP1, { attestation: "complete", nom: "complete periode 1", size: 316 });
    s.ots("2026-11-03T20:30:22.000Z", OK2, { nom: "en attente K2" }).arret("2026-11-03T20:31:00.000Z");
    ajouter(s, (t) => {
      const ots = dem(t, OP1);
      const rejets = actions(t, "journaliser", (a) => a.detail.event === "anchor_response_rejected").map((a) => [a.t, a.request_id, a.detail.error_code, a.detail.attempt ?? null, a.detail.attempt_id ?? null, a.detail.provider, a.detail.kept ?? null]);
      const id = (n) => A.identifiantCorrelation("ots_periode", ex.periodHash[1], n);
      return [
        ["deux rejets preuve_absente de classe transitoire", JSON.stringify(actions(t, "rejeter_reponse").map((a) => [a.t, a.detail.error_code, a.detail.class])) === JSON.stringify([["2026-11-03T14:00:01.000Z", "preuve_absente", "transitoire"], ["2026-11-03T14:00:07.000Z", "preuve_absente", "transitoire"]])],
        ["lignes anchor_response_rejected : preuve_absente (rangs 1 et 2), tentative_close, demande_close, demande_inconnue", JSON.stringify(rejets) === JSON.stringify([
          ["2026-11-03T14:00:01.000Z", OP1, "preuve_absente", 1, id(1), null, null],
          ["2026-11-03T14:00:02.000Z", OP1, "tentative_close", 1, id(1), null, false],
          ["2026-11-03T14:00:07.000Z", OP1, "preuve_absente", 2, id(2), null, null],
          ["2026-11-03T20:30:21.000Z", OP1, "demande_close", 5, id(5), null, true],
          ["2026-11-03T20:30:22.000Z", OK2, "demande_inconnue", null, null, null, false],
        ])],
        ["aucun stocker sans preuve ; reprises à l'attente d'EX-8.9 (k = 1 puis 2)", actions(t, "stocker", (a) => a.request_id === OP1).every((a) => a.detail.sha256 !== null) && JSON.stringify(actions(t, "programmer", (a) => a.request_id === OP1 && a.detail.reason === "backoff").map((a) => a.detail.next_at)) === JSON.stringify(["2026-11-03T14:00:06.250Z", "2026-11-03T14:00:17.500Z"])],
        ["attestation Bitcoin sans preuve à la mise à niveau : en attente, mise à niveau suivante à interval_s", JSON.stringify(ots.attempts.map((a) => [a.n, a.outcome, a.error_code])) === JSON.stringify([[1, "echec_transitoire", "preuve_absente"], [2, "echec_transitoire", "preuve_absente"], [3, "obtenue", null], [4, "echec_transitoire", "en_attente"], [5, "obtenue", null]]) && actions(t, "programmer", (a) => a.request_id === OP1 && a.t === "2026-11-03T20:00:19.000Z")[0]?.detail.next_at === "2026-11-03T20:30:19.000Z"],
        ["complete avec la preuve de 20:30:20", ots.state === "complete" && ots.result.sha256 === shaTexte("preuve complete periode 1")],
      ];
    });
  }

  // 42. redemarrage-ots-a-reprendre-en-cours (EX-8.12, EX-8.16 ; complément du 2026-11-16) : une ligne a_reprendre qui
  // porte encore une soumission en cours (file écrite par une version antérieure du composant) se reprend au démarrage
  // comme une soumission envoyee ; la tentative de soumission porte le détail « soumission a <n> calendriers ».
  {
    const avant = new Scenario("redemarrage-ots-a-reprendre-en-cours-avant", "x", configuration(), { jitter: [0] });
    avant.demarrage("2026-11-03T13:59:00.000Z").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { calendars_answered: 1, nom: null });
    avant.inclusion("2026-11-03T14:00:02.000Z", AP1, 21087).granted("2026-11-03T14:00:03.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:03Z", nom: "periode 1", size: 3082 }).tic("2026-11-03T14:00:06.000Z");
    avant.construire();
    const lus = A.lireFile(avant.lignes.map((l) => l + "\n").join(""));
    // La ligne qu'écrivait au démarrage un composant d'avant ce complément : a_reprendre, due_at à l'instant de ce
    // démarrage (14:00:20), la tentative 2 laissée en_cours.
    const file = lus.demandes.map((d) => (d.id === OP1 ? { ...d, state: "a_reprendre", due_at: "2026-11-03T14:00:20.000Z" } : d));
    const op = file.find((d) => d.id === OP1);
    exiger(!lus.truncated && lus.errors.length === 0 && JSON.stringify(op.attempts.map((a) => [a.n, a.outcome, a.error_code])) === JSON.stringify([[1, "echec_transitoire", "reponses_insuffisantes"], [2, "en_cours", null]]), "redemarrage-ots-a-reprendre-en-cours : file avant le redémarrage");
    const s = new Scenario(
      "redemarrage-ots-a-reprendre-en-cours",
      "Clôture de la période 1 de référence. La soumission OpenTimestamps n'a obtenu qu'un calendrier (14:00:01, tentative 1 close reponses_insuffisantes) et sa reprise est partie à 14:00:06 (tentative 2) ; l'ancre de la période et le jeton de clôture sont obtenus. Un composant d'une version antérieure a redémarré à 14:00:20 : il a réécrit la ligne a_reprendre (due_at 14:00:20) en laissant la tentative 2 en_cours. Le composant redémarre à 14:00:30 sur cette file. EX-8.12 (complément du 2026-11-16) : une ligne a_reprendre qui porte encore une tentative en_cours se reprend comme une soumission envoyee : la tentative 2 est close echec_transitoire, code redemarrage, la ligne est réécrite a_reprendre et la soumission repart aussitôt (programmer immediat) au rang 3, avec le même nonce (EX-6.2). Le composant s'arrête à 14:01:00 sans réponse : la file finale porte la soumission en cours, de détail « soumission a 2 calendriers » (EX-8.16).",
      configuration(),
      { queue_before: file, jitter: [] },
    );
    s.demarrage("2026-11-03T14:00:30.000Z").arret("2026-11-03T14:01:00.000Z");
    ajouter(s, (t) => {
      const ots = dem(t, OP1);
      return [
        ["au démarrage : tentative 2 close redemarrage, a_reprendre, programmée immédiatement, soumise au rang 3", JSON.stringify(t.expected.filter((a) => a.request_id === OP1).map((a) => [a.t, a.action, a.detail.state ?? a.detail.reason ?? null])) === JSON.stringify([["2026-11-03T14:00:30.000Z", "ecrire_file", "a_reprendre"], ["2026-11-03T14:00:30.000Z", "programmer", "immediat"], ["2026-11-03T14:00:30.000Z", "ecrire_file", "envoyee"], ["2026-11-03T14:00:30.000Z", "soumettre_ots", null]])],
        ["même nonce qu'avant l'arrêt (EX-6.2)", actions(t, "soumettre_ots")[0]?.detail.nonce === actions(avant.trace, "soumettre_ots")[0]?.detail.nonce],
        ["file finale : rangs 2 redemarrage et 3 en cours, détail « soumission a 2 calendriers »", ots.state === "envoyee" && JSON.stringify(ots.attempts.map((a) => [a.n, a.outcome, a.error_code, a.detail])) === JSON.stringify([[1, "echec_transitoire", "reponses_insuffisantes", "1 calendrier(s) ; moins de 2 reponses valables"], [2, "echec_transitoire", "redemarrage", "redemarrage : reponse non recue"], [3, "en_cours", null, "soumission a 2 calendriers"]])],
      ];
    });
  }

  // 43. reponses-hors-tentative (EX-8.5 règles 1 et 2, EX-5.10 étape 2, EX-5.12, EX-8.10, 8.9 ; complément du
  // 2026-11-16) : réponses et événements du registre qui ne s'appliquent pas ; détails des tentatives en échec.
  {
    const JK2 = ID("jeton_point", POINTS.K2.hash);
    const AK2 = ID("ancre_registre_point", POINTS.K2.hash);
    const s = new Scenario(
      "reponses-hors-tentative",
      "Clôture de la période 1 de référence. EX-8.5, règle 2, et 8.9 (complément du 2026-11-16) : une réponse RFC 3161 pour une demande que la file ne connaît pas (jeton de K2, 14:00:00.500) est consignée demande_inconnue, rien n'est gardé ; un échec du registre pour une ancre inconnue (14:00:00.750), anchor_duplicate_ignored de raison demande_inconnue. L'ancre de la période est incluse à 14:00:02 ; un second reçu et un échec du registre pour cette ancre obtenue (14:00:03) sont ignorés et consignés avec son état (EX-8.10). Le jeton de clôture part au principal (rang 1). Une réponse granted d'un rang que la demande n'a jamais ouvert (rang 9, 14:00:04) : son jeton est gardé comme pièce, sans borne, et la ligne tentative_inconnue porte ce rang, attempt_id nul (EX-8.5, règle 1) ; la même réponse de status 2 (14:00:04.500) ne porte pas de jeton (EX-5.10, étape 2) : rien n'est gardé, kept faux. EX-5.10, étape 2 : une réponse de status 0 sans TimeStampToken (14:00:05) est reponse_illisible, permanente, jamais promue : relève au secours (rang 2). Une réponse tardive du principal au rang 1, de nonce faux (14:00:06), est gardée sans borne (le jeton ne passe pas les étapes 3 à 6 pour cette tentative) et consignée tentative_close. Le secours répond status 2 avec un PKIFailureInfo hors de la liste de la RFC (autre, 14:00:07) : statut_2, permanente ; les deux prestataires sont épuisés et le jeton de clôture alterne au pas retry.max_ms (EX-8.8) : nonce différent (rang 3, détail portant les deux nonces), politique différente (rang 4), HTTP 400 avec Retry-After (rang 5, permanente, le Retry-After lu est rapporté ; le jeton que l'entrée porte n'est pas gardé : un refus avant l'étape 3 ne fait pas de pièce), puis granted au rang 6 (14:20:11). Les détails des tentatives closes sont ceux de la référence (EX-8.16).",
      configuration(),
      { jitter: [] },
    );
    s.demarrage("2026-11-03T13:59:00.000Z").cloture(ex, 1);
    s.granted("2026-11-03T14:00:00.500Z", JK2, 1, { gen_time: "2026-11-03T14:00:00Z", nom: "K2 inconnu", journal: JOURNAL });
    s.echecRegistre("2026-11-03T14:00:00.750Z", AK2, "noeud_injoignable");
    s.inclusion("2026-11-03T14:00:02.000Z", AP1, 21087);
    s.inclusion("2026-11-03T14:00:03.000Z", AP1, 21087).echecRegistre("2026-11-03T14:00:03.000Z", AP1, "noeud_injoignable");
    s.granted("2026-11-03T14:00:04.000Z", PH1, 9, { gen_time: "2026-11-03T14:00:04Z", nom: "rang inconnu", size: 3082 });
    s.echec("2026-11-03T14:00:04.500Z", PH1, 9, { pki_status: 2, failure_info: "unacceptedPolicy", extra: { token_sha256: shaTexte("jeton statut 2"), token_size: 10 } });
    s.granted("2026-11-03T14:00:05.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:05Z", nom: "sans jeton", size: 3082, extra: { token_sha256: null, token_size: null } });
    s.granted("2026-11-03T14:00:06.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:06Z", nom: "tardif nonce faux", size: 3082, nonce: "0x0123456789abcdef" });
    s.echec("2026-11-03T14:00:07.000Z", PH1, 2, { pki_status: 2, failure_info: "autre" });
    s.tic("2026-11-03T14:05:07.000Z").granted("2026-11-03T14:05:08.000Z", PH1, 3, { gen_time: "2026-11-03T14:05:08Z", nom: "nonce faux", size: 3082, nonce: "0x0123456789abcdef" });
    s.tic("2026-11-03T14:10:08.000Z").granted("2026-11-03T14:10:09.000Z", PH1, 4, { gen_time: "2026-11-03T14:10:09Z", nom: "politique", size: 3082, extra: { policy_check: "politique_differente" } });
    s.tic("2026-11-03T14:15:09.000Z").echec("2026-11-03T14:15:10.000Z", PH1, 5, { http_status: 400, retry_after_s: 5, extra: { pki_status: 0, token_sha256: shaTexte("jeton http 400"), token_size: 2104 } });
    s.tic("2026-11-03T14:20:10.000Z").granted("2026-11-03T14:20:11.000Z", PH1, 6, { gen_time: "2026-11-03T14:20:11Z", nom: "periode 1", size: 3082 });
    s.ots("2026-11-03T14:20:12.000Z", OP1, { nom: "en attente periode 1" }).arret("2026-11-03T14:21:00.000Z");
    ajouter(s, (t) => {
      const ph = dem(t, PH1);
      const ligne = (tt) => actions(t, "journaliser", (a) => a.t === tt)[0]?.detail ?? null;
      const id = (n) => A.identifiantCorrelation("jeton_periode", ex.periodHash[1], n);
      return [
        ["demande inconnue : demande_inconnue, rien n'est gardé", JSON.stringify(ligne("2026-11-03T14:00:00.500Z")) === JSON.stringify({ event: "anchor_response_rejected", error_code: "demande_inconnue", attempt: 1, provider: null, kept: false }) && actions(t, "stocker", (a) => a.request_id === JK2).length === 0],
        ["événements du registre qui ne s'appliquent pas : demande_inconnue, puis état de l'ancre obtenue", JSON.stringify(ligne("2026-11-03T14:00:00.750Z")) === JSON.stringify({ event: "anchor_duplicate_ignored", reason: "demande_inconnue" }) && JSON.stringify(actions(t, "journaliser", (a) => a.t === "2026-11-03T14:00:03.000Z").map((a) => a.detail)) === JSON.stringify([{ event: "anchor_duplicate_ignored", state: "obtenue" }, { event: "anchor_duplicate_ignored", state: "obtenue" }])],
        ["rang jamais ouvert : jeton gardé sans borne, tentative_inconnue au rang 9, attempt_id nul", JSON.stringify(actions(t, "stocker", (a) => a.t === "2026-11-03T14:00:04.000Z").map((a) => a.detail.bound)) === "[null]" && JSON.stringify(ligne("2026-11-03T14:00:04.000Z")) === JSON.stringify({ event: "anchor_response_rejected", error_code: "tentative_inconnue", attempt: 9, attempt_id: null, provider: null, kept: true })],
        ["status 2 : aucun jeton gardé, kept faux ; HTTP 400 : jeton de l'entrée non gardé", actions(t, "stocker", (a) => a.t === "2026-11-03T14:00:04.500Z" || a.t === "2026-11-03T14:15:10.000Z").length === 0 && ligne("2026-11-03T14:00:04.500Z")?.kept === false],
        ["réponse tardive de nonce faux : gardée sans borne, tentative_close", JSON.stringify(actions(t, "stocker", (a) => a.t === "2026-11-03T14:00:06.000Z").map((a) => a.detail.bound)) === "[null]" && JSON.stringify(ligne("2026-11-03T14:00:06.000Z")) === JSON.stringify({ event: "anchor_response_rejected", error_code: "tentative_close", attempt: 1, attempt_id: id(1), provider: "qtsa-principal", kept: true })],
        ["codes et détails des tentatives closes", JSON.stringify(ph.attempts.map((a) => [a.n, a.outcome, a.error_code, a.detail])) === JSON.stringify([
          [1, "echec_permanente", "reponse_illisible", "TimeStampToken absent"],
          [2, "echec_permanente", "statut_2", "PKIStatus 2 (rejection)"],
          [3, "echec_permanente", "nonce_different", "nonce 0x0123456789abcdef different de " + nonceDe("periode", ex.periodHash[1], 3)],
          [4, "echec_permanente", "politique_differente", "politique differente de la politique demandee"],
          [5, "echec_permanente", "http_400", "http 400 ; Retry-After 5 s"],
          [6, "obtenue", null, "granted ; T-1 a T-9 reussies"],
        ]) && ph.state === "obtenue"],
      ];
    });
  }

  // 44. registre-renvois (EX-8.10, EX-8.16, CT-4 EX-8.16 ; complément du 2026-11-16) : détails des renvois au registre ;
  // reçu et échec pour une ancre sans transaction en vol ; due_at d'une ancre renvoyée et d'une ancre qui attend le nonce.
  {
    const s = new Scenario(
      "registre-renvois",
      "Point K1 admis à 13:42 : son ancre part au registre (rang 1, « transaction envoyee »). Aucun reçu en registry.inclusion_alert_s : renvoi des mêmes octets à 13:43 (rang 2). Le registre signale noeud_injoignable à 13:43:30 : rang 2 clos, a_reprendre, reprise à 13:43:40 (EX-8.10, k = 2, gigue nulle). EX-8.10 (complément du 2026-11-16) : un reçu (13:43:35) et un échec (13:43:36) pour cette ancre, qui n'a plus de transaction en vol, sont ignorés et consignés avec son état (a_reprendre). À 13:43:40 l'ancre repart (rang 3, « transaction envoyee ») : la ligne envoyee n'a plus de due_at. Sans reçu, les renvois suivants remplacent la transaction au même nonce (CT-4 EX-8.16 : « remplacement au meme nonce »), le dernier au rang 8 dans la passe de 13:53 (EX-8.10 : missed_deadlines 4). Le point K2 admis à 13:53 trouve la clé occupée : son ancre attend le nonce (programmer attente_nonce) et sa ligne porte due_at = 13:53. Le composant s'arrête à 13:53:30 : la file finale porte le renvoi en cours de K1 et l'ancre de K2 a_envoyer.",
      configuration(),
      { jitter: [0] },
    );
    s.demarrage("2026-11-03T13:40:00.000Z").point("K1").tic("2026-11-03T13:43:00.000Z");
    s.echecRegistre("2026-11-03T13:43:30.000Z", ANCRE("K1"), "noeud_injoignable");
    s.inclusion("2026-11-03T13:43:35.000Z", ANCRE("K1"), 20001).echecRegistre("2026-11-03T13:43:36.000Z", ANCRE("K1"), "noeud_injoignable");
    s.tic("2026-11-03T13:43:40.000Z").tic("2026-11-03T13:44:40.000Z");
    s.point("K2").arret("2026-11-03T13:53:30.000Z");
    ajouter(s, (t) => {
      const k1 = dem(t, ANCRE("K1"));
      const k2 = dem(t, ANCRE("K2"));
      return [
        ["reçu et échec sur l'ancre a_reprendre : ignorés, consignés avec son état", JSON.stringify(actions(t, "journaliser", (a) => a.request_id === ANCRE("K1") && a.detail.event === "anchor_duplicate_ignored").map((a) => [a.t, a.detail.state])) === JSON.stringify([["2026-11-03T13:43:35.000Z", "a_reprendre"], ["2026-11-03T13:43:36.000Z", "a_reprendre"]])],
        ["ancre de K1 en vol au rang 8, « remplacement au meme nonce », due_at nul", k1.state === "envoyee" && k1.due_at === null && k1.attempts.at(-1).n === 8 && k1.attempts.at(-1).outcome === "en_cours" && k1.attempts.at(-1).detail === "remplacement au meme nonce" && k1.attempts.find((a) => a.n === 2)?.error_code === "noeud_injoignable"],
        ["ancre de K2 en attente du nonce, due_at 13:53", k2.state === "a_envoyer" && k2.due_at === "2026-11-03T13:53:00.000Z" && actions(t, "programmer", (a) => a.request_id === ANCRE("K2"))[0]?.detail.reason === "attente_nonce"],
      ];
    });
  }

  // 45. redemarrage-releve-deux-series (EX-8.12, EX-8.8, EX-8.5 ; complément du 2026-11-16) : redémarrage d'un jeton dont
  // les deux séries de la relève avaient une tentative en cours ; erreur permanente d'une série pendant que l'autre est
  // en vol.
  {
    const avant1 = new Scenario("redemarrage-releve-deux-series-avant-1", "x", configuration(), { jitter: [] });
    avant1.demarrage("2026-11-03T13:59:00.000Z").cloture(ex, 1).inclusion("2026-11-03T14:00:01.000Z", AP1, 21087).ots("2026-11-03T14:00:02.000Z", OP1, { nom: "en attente periode 1" });
    avant1.tic("2026-11-03T14:05:01.000Z").arret("2026-11-03T14:05:30.000Z");
    avant1.construire();
    const lus1 = A.lireFile(avant1.lignes.map((l) => l + "\n").join(""));
    const avant2 = new Scenario("redemarrage-releve-deux-series-avant-2", "x", configuration(), { queue_before: lus1.demandes, jitter: [0] });
    avant2.demarrage("2026-11-03T14:06:00.000Z").echec("2026-11-03T14:06:01.000Z", PH1, 3, { http_status: 503 }).tic("2026-11-03T14:06:06.000Z").arret("2026-11-03T14:06:10.000Z");
    avant2.construire();
    // La file est en ajout seul : les lignes des deux marches avant ce démarrage, relues ensemble.
    const lus = A.lireFile([...avant1.lignes, ...avant2.lignes].map((l) => l + "\n").join(""));
    const ph = lus.demandes.find((d) => d.id === PH1);
    exiger(!lus.truncated && lus.errors.length === 0 && lus.demandes.length === 3 && JSON.stringify(ph.attempts.map((a) => [a.n, a.provider, a.outcome, a.error_code])) === JSON.stringify([[1, "qtsa-principal", "echec_transitoire", "redemarrage"], [2, "qtsa-secours", "echec_transitoire", "redemarrage"], [3, "qtsa-principal", "echec_transitoire", "http_503"], [4, "qtsa-secours", "en_cours", null], [5, "qtsa-principal", "en_cours", null]]), `redemarrage-releve-deux-series : file avant le redémarrage (${JSON.stringify(ph.attempts.map((a) => [a.n, a.provider, a.outcome, a.error_code]))})`);
    const s = new Scenario(
      "redemarrage-releve-deux-series",
      "Clôture de la période 1 de référence ; ancre incluse à 14:00:01, jeton de clôture au principal (rang 1), relève au secours à 14:05:01 (rang 2, EX-8.8). Un premier redémarrage à 14:06:00 a clos les rangs 1 et 2 (redemarrage) et renvoyé le principal (rang 3) puis le secours (rang 4) ; le principal a répondu 503 à 14:06:01 et sa reprise est partie à 14:06:06 (rang 5). Le composant redémarre à 14:06:30 sur cette file : les deux séries ont une tentative en cours, celle du secours (rang 4) avant celle du principal (rang 5). EX-8.12 (complément du 2026-11-16) : les deux tentatives sont closes redemarrage ; une seule action programmer de raison immediat pour la demande ; chaque série repart dans l'ordre des tentatives closes par ce démarrage : le secours (rang 6) puis le principal (rang 7), les tentatives closes par le redémarrage précédent n'y comptant pas. Le principal refuse à 14:06:31 (unacceptedPolicy, permanente) pendant que le secours est en vol : la tentative close est écrite, la ligne reste envoyee (EX-8.5 : une ligne par état successif). Le secours rend le jeton à 14:06:32.",
      configuration(),
      { queue_before: lus.demandes, jitter: [] },
    );
    s.demarrage("2026-11-03T14:06:30.000Z");
    s.echec("2026-11-03T14:06:31.000Z", PH1, 7, { pki_status: 2, failure_info: "unacceptedPolicy" });
    s.granted("2026-11-03T14:06:32.000Z", PH1, 6, { gen_time: "2026-11-03T14:06:32Z", nom: "periode 1 secours", size: 3082 }).arret("2026-11-03T14:07:00.000Z");
    ajouter(s, (t) => {
      const d = dem(t, PH1);
      return [
        ["une seule action programmer immediat au démarrage", actions(t, "programmer", (a) => a.request_id === PH1 && a.t === "2026-11-03T14:06:30.000Z").length === 1],
        ["secours renvoyé avant le principal (rangs 6 et 7)", JSON.stringify(actions(t, "envoyer_rfc3161").map((a) => [a.t, a.detail.provider, a.detail.attempt])) === JSON.stringify([["2026-11-03T14:06:30.000Z", "qtsa-secours", 6], ["2026-11-03T14:06:30.000Z", "qtsa-principal", 7]])],
        ["refus du principal écrit, la ligne reste envoyee", JSON.stringify(t.expected.filter((a) => a.t === "2026-11-03T14:06:31.000Z").map((a) => [a.action, a.detail.state ?? a.detail.event ?? a.detail.error_code])) === JSON.stringify([["rejeter_reponse", "echec_unacceptedPolicy"], ["journaliser", "anchor_response_rejected"], ["ecrire_file", "envoyee"]])],
        ["jeton du secours obtenu", d.state === "obtenue" && d.result.provider === "qtsa-secours"],
      ];
    });
  }

  // 46. minuteries-simultanees (EX-8.16, EX-8.10, EX-8.4 règle 2 ; complément du 2026-11-16) : deux minuteries de même
  // échéance, de deux demandes, armées dans l'ordre inverse de la file, se déclenchent dans l'ordre de la file.
  {
    const s = new Scenario(
      "minuteries-simultanees",
      "Clôture de la période 1 de référence : l'ancre de la période part au registre, le jeton de clôture attend son inclusion (attente_registre, examen toutes les registry.inclusion_alert_s). Sans reçu, l'ancre est renvoyée à 14:01:00.250 ; le registre signale noeud_injoignable à 14:01:50.250 : reprise de l'ancre à 14:02:00.250 (k = 1, gigue nulle), le même instant que l'examen suivant du jeton de clôture, armé avant elle. EX-8.16 (complément du 2026-11-16) : deux minuteries de même échéance se déclenchent dans l'ordre de la file (created_at puis id), celles des périodes d'abord, et, pour une même demande, dans l'ordre où elles ont été armées : l'ancre repart avant l'examen du jeton. L'ancre est incluse à 14:02:01 et le jeton de clôture obtenu à 14:02:02.",
      configuration(),
      { jitter: [0] },
    );
    s.demarrage("2026-11-03T13:59:00.000Z").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" });
    s.tic("2026-11-03T14:01:00.250Z").echecRegistre("2026-11-03T14:01:50.250Z", AP1, "noeud_injoignable").tic("2026-11-03T14:02:00.250Z");
    s.inclusion("2026-11-03T14:02:01.000Z", AP1, 21087).granted("2026-11-03T14:02:02.000Z", PH1, 1, { gen_time: "2026-11-03T14:02:02Z", nom: "periode 1", size: 3082 }).arret("2026-11-03T14:03:00.000Z");
    ajouter(s, (t) => [
      ["à 14:02:00.250, l'ancre (avant dans la file) repart avant l'examen du jeton de clôture", JSON.stringify(t.expected.filter((a) => a.t === "2026-11-03T14:02:00.250Z").map((a) => [a.action, a.request_id])) === JSON.stringify([["ecrire_file", AP1], ["envoyer_registre", AP1], ["journaliser", PH1], ["programmer", PH1]])],
      ["examen du jeton armé avant la reprise de l'ancre", actions(t, "programmer", (a) => a.request_id === PH1 && a.detail.next_at === "2026-11-03T14:02:00.250Z")[0]?.t === "2026-11-03T14:01:00.250Z" && actions(t, "programmer", (a) => a.request_id === AP1 && a.detail.next_at === "2026-11-03T14:02:00.250Z")[0]?.t === "2026-11-03T14:01:50.250Z"],
      ["ancre incluse, jeton de clôture obtenu", dem(t, AP1).state === "obtenue" && dem(t, PH1).state === "obtenue"],
    ]);
  }

  // 47. jeton-tardif-avertissements (EX-5.10 étapes 6 à 8, EX-5.11, EX-8.16 ; complément du 2026-11-16) : précision hors
  // de la plage d'un instant, pièce sans borne, troisième réponse tardive promue avec ses deux avertissements.
  {
    const s = new Scenario(
      "jeton-tardif-avertissements",
      "Clôture de la période 1 de référence ; l'ancre est incluse à 14:00:01 et le jeton de clôture part au principal (rang 1). EX-5.10 (complément du 2026-11-16) : sa réponse à 14:00:02 porte une précision qui met genTime + précision hors de la plage d'un instant : verification_T-7, permanente (« precision hors de la plage d'un instant (T-7) ») ; relève au secours (rang 2). La même réponse, rejouée à 14:00:03 pour le rang 1 désormais clos, est gardée comme pièce sans borne (EX-8.5, règle 2). Le secours répond trois fois plus de max_response_delay_s après l'envoi (EX-5.11) : les deux premières réponses sont tardives (rangs 2 et 3, reprises à k = 1 puis 2), la troisième (rang 4, status 1, genTime à plus de clock_tolerance_s de l'envoi) est promue avec les avertissements reponse_tardive et horloge_suspecte, dans l'ordre des étapes 7 et 8 ; le détail est « grantedWithMods ; T-1 a T-9 reussies ; avertissement reponse_tardive, horloge_suspecte » (EX-8.16) et les alertes horloge_suspecte puis reponse_tardive_promue sont levées.",
      configuration(),
      { jitter: [0, 0] },
    );
    s.demarrage("2026-11-03T13:59:00.000Z").cloture(ex, 1).inclusion("2026-11-03T14:00:01.000Z", AP1, 21087).ots("2026-11-03T14:00:01.500Z", OP1, { nom: "en attente periode 1" });
    s.granted("2026-11-03T14:00:02.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:02Z", nom: "precision hors plage", size: 3082, accuracy_s: 9000000000000 });
    s.granted("2026-11-03T14:00:03.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:02Z", nom: "precision hors plage", size: 3082, accuracy_s: 9000000000000 });
    s.granted("2026-11-03T14:01:03.000Z", PH1, 2, { gen_time: "2026-11-03T14:01:03Z", nom: "tardif 2", size: 3082 });
    s.tic("2026-11-03T14:01:08.000Z").granted("2026-11-03T14:02:09.000Z", PH1, 3, { gen_time: "2026-11-03T14:02:09Z", nom: "tardif 3", size: 3082 });
    s.tic("2026-11-03T14:02:19.000Z").granted("2026-11-03T14:03:20.000Z", PH1, 4, { gen_time: "2026-11-03T14:06:30Z", nom: "periode 1", size: 3082, pki_status: 1 }).arret("2026-11-03T14:04:00.000Z");
    ajouter(s, (t) => {
      const ph = dem(t, PH1);
      return [
        ["précision hors plage : verification_T-7 permanente, relève au secours", ph.attempts.find((a) => a.n === 1)?.error_code === "verification_T-7" && ph.attempts.find((a) => a.n === 1)?.detail === "precision hors de la plage d'un instant (T-7)" && actions(t, "releve").length === 1],
        ["pièce du rang 1 clos gardée sans borne", JSON.stringify(actions(t, "stocker", (a) => a.t === "2026-11-03T14:00:03.000Z").map((a) => a.detail.bound)) === "[null]"],
        ["deux réponses tardives, puis la troisième promue avec ses deux avertissements", JSON.stringify(ph.attempts.map((a) => [a.n, a.outcome, a.error_code])) === JSON.stringify([[1, "echec_permanente", "verification_T-7"], [2, "reponse_tardive", "reponse_tardive"], [3, "reponse_tardive", "reponse_tardive"], [4, "obtenue", null]]) && ph.attempts.at(-1).detail === "grantedWithMods ; T-1 a T-9 reussies ; avertissement reponse_tardive, horloge_suspecte"],
        ["alertes horloge_suspecte puis reponse_tardive_promue", JSON.stringify(actions(t, "alerter", (a) => a.request_id === PH1 && a.t === "2026-11-03T14:03:20.000Z").map((a) => a.detail.code)) === JSON.stringify(["horloge_suspecte", "reponse_tardive_promue"])],
      ];
    });
  }

  // 48. redemarrage-ordre-de-la-file (EX-8.12 ; complément du 2026-11-16) : au démarrage, une seule passe sur la file, dans
  // l'ordre de la file ; une ancre a_envoyer dont la clé a une ancre en vol attend le nonce à sa place dans la passe.
  {
    const avant = new Scenario("redemarrage-ordre-de-la-file-avant", "x", configuration(), { jitter: [] });
    avant.demarrage("2026-11-03T13:52:30.000Z").point("K2").granted("2026-11-03T13:53:06.000Z", JETON("K2"), 1, { gen_time: "2026-11-03T13:53:06Z", nom: "K2" });
    avant.cloture(ex, 1).arret("2026-11-03T14:00:01.000Z");
    avant.construire();
    const lus = A.lireFile(avant.lignes.map((l) => l + "\n").join(""));
    const etats = lus.demandes.map((d) => [d.id.split(":")[0], d.state]);
    exiger(!lus.truncated && lus.errors.length === 0 && JSON.stringify(etats) === JSON.stringify([["ancre_registre_point", "envoyee"], ["jeton_point", "obtenue"], ["ancre_registre_periode", "a_envoyer"], ["jeton_periode", "attente_registre"], ["ots_periode", "envoyee"]]), `redemarrage-ordre-de-la-file : file avant le redémarrage (${JSON.stringify(etats)})`);
    const s = new Scenario(
      "redemarrage-ordre-de-la-file",
      "Période 1 de référence, à partir de K2 (admis à 13:53) : son ancre reste sans reçu (renvois toutes les registry.inclusion_alert_s), son jeton est obtenu. À la clôture (14:00:00.250), l'ancre de la période attend le nonce (attente_nonce : la clé a l'ancre de K2 en vol), le jeton de clôture attend l'inclusion, la preuve OpenTimestamps est soumise. Le composant s'arrête à 14:00:01 et redémarre à 14:00:30. EX-8.12 (complément du 2026-11-16, ordre du démarrage) : une seule passe sur la file, dans l'ordre de la file (created_at puis id), chaque demande non finale traitée selon son état, a_envoyer comprise : l'ancre de K2 est renvoyée (anchor_retry de mode renvoi), l'ancre de la période, a_envoyer, attend le nonce à sa place (la clé a une ancre en vol), puis le jeton de clôture réexamine l'inclusion (programmer attente_registre) et la soumission OpenTimestamps est close redemarrage et reprise aussitôt ; les minuteries échues à l'instant du démarrage viennent après la passe. L'ancre de K2 est incluse à 14:00:31 : l'ancre de la période part alors (EX-9.4) ; incluse à 14:00:32, le jeton de clôture part et il est obtenu à 14:00:33 ; la preuve est en attente à 14:00:34.",
      configuration(),
      { queue_before: lus.demandes, jitter: [] },
    );
    s.demarrage("2026-11-03T14:00:30.000Z").inclusion("2026-11-03T14:00:31.000Z", ANCRE("K2"), 20660).inclusion("2026-11-03T14:00:32.000Z", AP1, 21087);
    s.granted("2026-11-03T14:00:33.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:33Z", nom: "periode 1", size: 3082 });
    s.ots("2026-11-03T14:00:34.000Z", OP1, { nom: "en attente periode 1" }).arret("2026-11-03T14:01:00.000Z");
    ajouter(s, (t) => {
      const demarrage = t.expected.filter((a) => a.t === "2026-11-03T14:00:30.000Z").map((a) => [a.action, a.request_id?.split(":")[0] ?? null, a.detail.event ?? a.detail.state ?? a.detail.reason ?? null]);
      return [
        ["au démarrage, la passe suit l'ordre de la file : l'ancre de la période attend le nonce entre le renvoi de l'ancre de K2 et le jeton de clôture", JSON.stringify(demarrage.slice(0, 7)) === JSON.stringify([["journaliser", null, "anchoring_started"], ["journaliser", "ancre_registre_point", "anchor_retry"], ["envoyer_registre", "ancre_registre_point", null], ["programmer", "ancre_registre_periode", "attente_nonce"], ["programmer", "jeton_periode", "attente_registre"], ["ecrire_file", "ots_periode", "a_reprendre"], ["programmer", "ots_periode", "immediat"]])],
        ["ancre de la période envoyée au reçu de celle de K2, jeton de clôture obtenu", JSON.stringify(actions(t, "envoyer_registre", (a) => a.request_id === AP1).map((a) => a.t)) === JSON.stringify(["2026-11-03T14:00:31.000Z"]) && dem(t, PH1).state === "obtenue" && dem(t, ANCRE("K2")).state === "obtenue"],
        ["preuve OpenTimestamps en attente", dem(t, OP1).state === "en_attente"],
      ];
    });
  }

  // 49. redemarrage-a-envoyer-cle-libre (EX-8.12, EX-9.4 ; complément du 2026-11-16) : arrêt entre la ligne obtenue d'une
  // ancre et le départ de la suivante ; au démarrage, les ancres a_envoyer partent après la passe : celle du point de la
  // période d'abord, celle de la période à son reçu (EX-9.4 ; la trace publiée faisait partir la période d'abord).
  {
    const avant = new Scenario("redemarrage-a-envoyer-cle-libre-avant", "x", configuration(), { jitter: [] });
    avant.demarrage("2026-11-03T13:41:00.000Z").point("K1").granted("2026-11-03T13:42:06.000Z", JETON("K1"), 1, { gen_time: "2026-11-03T13:42:06Z", nom: "K1" });
    avant.point("K2").granted("2026-11-03T13:53:06.000Z", JETON("K2"), 1, { gen_time: "2026-11-03T13:53:06Z", nom: "K2" });
    avant.cloture(ex, 1).inclusion("2026-11-03T14:00:01.000Z", ANCRE("K1"), 20001).arret("2026-11-03T14:00:02.000Z");
    avant.construire();
    const etat = (l) => JSON.parse(l);
    const iO = avant.lignes.findIndex((l) => etat(l).id === ANCRE("K1") && etat(l).state === "obtenue");
    // EX-9.4 (complément du 2026-11-16) : l'ancre suivante est celle de K2, le point de clôture ; celle de la période attend son reçu.
    exiger(iO >= 0 && etat(avant.lignes[iO + 1]).id === ANCRE("K2") && etat(avant.lignes[iO + 1]).state === "envoyee", "redemarrage-a-envoyer-cle-libre : lignes obtenue de l'ancre de K1 puis envoyee de l'ancre de K2 attendues consécutives");
    const lus = A.lireFile(avant.lignes.slice(0, iO + 1).map((l) => l + "\n").join(""));
    const etats = lus.demandes.map((d) => [d.id.split(":")[0], d.state]);
    exiger(!lus.truncated && lus.errors.length === 0 && JSON.stringify(etats) === JSON.stringify([["ancre_registre_point", "obtenue"], ["jeton_point", "obtenue"], ["ancre_registre_point", "a_envoyer"], ["jeton_point", "obtenue"], ["ancre_registre_periode", "a_envoyer"], ["jeton_periode", "attente_registre"], ["ots_periode", "envoyee"]]), `redemarrage-a-envoyer-cle-libre : file coupée (${JSON.stringify(etats)})`);
    const s = new Scenario(
      "redemarrage-a-envoyer-cle-libre",
      "Période 1 de référence : l'ancre de K1 reste sans reçu (renvois toutes les registry.inclusion_alert_s) ; l'ancre de K2 (13:53) et celle de la période (clôture, 14:00:00.250) attendent le nonce. Le reçu de l'ancre de K1 arrive à 14:00:01 ; le processus s'arrête entre la ligne obtenue de cette ancre et la ligne envoyee de l'ancre suivante, qu'EX-8.5, règle 1, fait écrire avant l'envoi. Au redémarrage à 14:00:30, la file porte deux ancres a_envoyer et aucune ancre en vol. EX-8.12 (complément du 2026-11-16, ordre du démarrage) : la passe, dans l'ordre de la file, ne fait rien partir ; une ancre a_envoyer n'attend le nonce que si une ancre de sa clé est en vol ; après la passe, les demandes à envoyer partent comme après toute entrée : l'ancre de K2 d'abord, celle de la période à son reçu (14:00:31). EX-9.4 (« l'ancre de la période ne part qu'après le reçu de l'ancre du point de clôture de la même clé ») : complément du 2026-11-16, cette trace change ; elle faisait partir l'ancre de la période la première, avant celle de K2, le point de clôture de sa période. La soumission OpenTimestamps envoyee est close redemarrage et rejouée aussitôt, à l'instant du démarrage, après ce départ (minuterie échue).",
      configuration(),
      { queue_before: lus.demandes, jitter: [] },
    );
    s.demarrage("2026-11-03T14:00:30.000Z").inclusion("2026-11-03T14:00:31.000Z", ANCRE("K2"), 20660).inclusion("2026-11-03T14:00:32.000Z", AP1, 21087);
    s.granted("2026-11-03T14:00:33.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:33Z", nom: "periode 1", size: 3082 }).ots("2026-11-03T14:00:34.000Z", OP1, { nom: "en attente periode 1" }).arret("2026-11-03T14:01:00.000Z");
    ajouter(s, (t) => {
      const demarrage = t.expected.filter((a) => a.t === "2026-11-03T14:00:30.000Z");
      return [
        ["aucune attente du nonce au démarrage (aucune ancre en vol)", demarrage.every((a) => a.detail.reason !== "attente_nonce")],
        ["l'ancre de K2 part la première, après la passe ; celle de la période au reçu de celle de K2 (EX-9.4)", JSON.stringify(actions(t, "envoyer_registre").map((a) => [a.t, a.request_id])) === JSON.stringify([["2026-11-03T14:00:30.000Z", ANCRE("K2")], ["2026-11-03T14:00:31.000Z", AP1]]) && demarrage.findIndex((a) => a.action === "envoyer_registre") > demarrage.findIndex((a) => a.action === "programmer" && a.request_id === OP1)],
        ["soumission rejouée après le départ de l'ancre ; jeton de clôture obtenu, preuve en attente", demarrage.findIndex((a) => a.action === "soumettre_ots") > demarrage.findIndex((a) => a.action === "envoyer_registre") && dem(t, PH1).state === "obtenue" && dem(t, OP1).state === "en_attente" && dem(t, ANCRE("K2")).state === "obtenue"],
      ];
    });
  }

  // 50. redemarrage-echeances-remplacees (EX-8.12, EX-4.4 ; complément du 2026-11-16) : les échéances d'une demande de point
  // remplacee relue restent closes ; elles ne sont pas closes une seconde fois au démarrage.
  {
    const avant = new Scenario("redemarrage-echeances-remplacees-avant", "x", configuration(), { jitter: [] });
    avant.demarrage("2026-11-03T13:41:00.000Z").point("K1").inclusion("2026-11-03T13:42:03.000Z", ANCRE("K1"), 20001);
    avant.point("K2").inclusion("2026-11-03T13:53:03.000Z", ANCRE("K2"), 20660).granted("2026-11-03T13:53:04.000Z", JETON("K2"), 1, { gen_time: "2026-11-03T13:53:04Z", nom: "K2" }).arret("2026-11-03T13:54:00.000Z");
    avant.construire();
    const lus = A.lireFile(avant.lignes.map((l) => l + "\n").join(""));
    const k1 = lus.demandes.find((d) => d.id === JETON("K1"));
    exiger(!lus.truncated && lus.errors.length === 0 && k1.state === "remplacee" && JSON.stringify(k1.deadlines) === "[1,2,3,4,5,6,7,8]" && lus.demandes.find((d) => d.id === JETON("K2")).state === "obtenue", "redemarrage-echeances-remplacees : file avant le redémarrage");
    const s = new Scenario(
      "redemarrage-echeances-remplacees",
      "Période 1 de référence, serveur interne pour les points : le jeton de K1 (D_1 à D_8) reste sans réponse ; celui de K2 (D_9, D_10), obtenu à 13:53:04, le remplace (EX-4.4 : D_1 à D_8 closes remplacee, checkpoint_anchor_late). Le composant s'arrête à 13:54 et redémarre à 13:55 sur cette file. EX-8.12 (complément du 2026-11-16) : les échéances d'une demande remplacee relue restent closes remplacee ; elles ne sont ni rouvertes ni closes une seconde fois (aucune action echeance au démarrage : la supervision ne les compte pas deux fois). K4 est admis à 14:00:00.250 (D_11) ; son jeton est obtenu.",
      configuration(),
      { queue_before: lus.demandes, jitter: [] },
    );
    s.demarrage("2026-11-03T13:55:00.000Z").point("K4").inclusion("2026-11-03T14:00:01.000Z", ANCRE("K4"), 21085);
    s.granted("2026-11-03T14:00:02.000Z", JETON("K4"), 1, { gen_time: "2026-11-03T14:00:02Z", nom: "K4" }).arret("2026-11-03T14:00:30.000Z");
    ajouter(s, (t) => [
      ["aucune action echeance au démarrage", actions(t, "echeance", (a) => a.t === "2026-11-03T13:55:00.000Z").length === 0],
      ["aucune échéance de D_1 à D_10 close de nouveau", actions(t, "echeance", (a) => a.detail.k <= 10 && a.detail.state !== "ouverte").length === 0],
      ["jeton de K4 obtenu (D_11)", dem(t, JETON("K4")).state === "obtenue" && JSON.stringify(dem(t, JETON("K4")).deadlines) === "[11]"],
    ]);
  }

  // 51. registre-inclusion-apres-attente (EX-8.10 ; complément du 2026-11-16) : le délai d'inclusion constaté au reçu
  // court depuis la création de l'ancre, attente du nonce comprise.
  {
    const s = new Scenario(
      "registre-inclusion-apres-attente",
      "Période 1 de référence. L'ancre de K1 (13:42) reste sans reçu : renvois toutes les registry.inclusion_alert_s (60 s), alerte inclusion_late. L'ancre de K2, admise à 13:53, attend le nonce (attente_nonce). Le reçu de l'ancre de K1 arrive à 13:54:30 : l'ancre de K2 part alors et elle est incluse à 13:54:40, dix secondes après son envoi mais cent secondes après sa création. EX-8.10 (complément du 2026-11-16) : le délai d'inclusion constaté au reçu court depuis la création de l'ancre (son admission), attente d'une autre ancre de la clé comprise, et non depuis son premier envoi : alerte inclusion_late mineure pour l'ancre de K2 (P-2).",
      configuration(),
      { jitter: [] },
    );
    s.demarrage("2026-11-03T13:41:00.000Z").point("K1").point("K2").inclusion("2026-11-03T13:54:30.000Z", ANCRE("K1"), 20001).inclusion("2026-11-03T13:54:40.000Z", ANCRE("K2"), 20661).arret("2026-11-03T13:55:00.000Z");
    ajouter(s, (t) => [
      ["ancre de K2 en attente du nonce à 13:53, envoyée à 13:54:30", actions(t, "programmer", (a) => a.request_id === ANCRE("K2") && a.detail.reason === "attente_nonce")[0]?.t === "2026-11-03T13:53:00.000Z" && JSON.stringify(actions(t, "envoyer_registre", (a) => a.request_id === ANCRE("K2")).map((a) => a.t)) === JSON.stringify(["2026-11-03T13:54:30.000Z"])],
      ["inclusion_late mineure au reçu de l'ancre de K2 (cent secondes depuis sa création)", JSON.stringify(actions(t, "alerter", (a) => a.request_id === ANCRE("K2")).map((a) => [a.t, a.detail.code, a.detail.severity])) === JSON.stringify([["2026-11-03T13:54:40.000Z", "inclusion_late", "mineure"]])],
      ["ancres de K1 et K2 obtenues", dem(t, ANCRE("K1")).state === "obtenue" && dem(t, ANCRE("K2")).state === "obtenue"],
    ]);
  }

  // 52. redemarrage-prestataires-epuises (EX-8.12, EX-8.8 ; complément du 2026-11-16) : la file est le seul état du
  // planificateur ; les prestataires épuisés d'une demande de jeton se relisent de ses tentatives echec_permanente.
  {
    const avant = new Scenario("redemarrage-prestataires-epuises-avant", "x", configuration(), { jitter: [] });
    avant.demarrage("2026-11-03T13:59:00.000Z").cloture(ex, 1).inclusion("2026-11-03T14:00:01.000Z", AP1, 21087).ots("2026-11-03T14:00:01.500Z", OP1, { nom: "en attente periode 1" });
    avant.echec("2026-11-03T14:00:02.000Z", PH1, 1, { pki_status: 2, failure_info: "unacceptedPolicy" }).arret("2026-11-03T14:00:03.000Z");
    avant.construire();
    const lus = A.lireFile(avant.lignes.map((l) => l + "\n").join(""));
    const ph = lus.demandes.find((d) => d.id === PH1);
    exiger(!lus.truncated && lus.errors.length === 0 && ph.state === "envoyee" && JSON.stringify(ph.attempts.map((a) => [a.n, a.provider, a.outcome])) === JSON.stringify([[1, "qtsa-principal", "echec_permanente"], [2, "qtsa-secours", "en_cours"]]), "redemarrage-prestataires-epuises : file avant le redémarrage");
    const s = new Scenario(
      "redemarrage-prestataires-epuises",
      "Clôture de la période 1 de référence ; ancre incluse à 14:00:01, preuve OpenTimestamps en attente. Le principal refuse le jeton de clôture (unacceptedPolicy, permanente, 14:00:02) : relève immédiate au secours (rang 2, EX-8.8). Le composant s'arrête à 14:00:03 et redémarre à 14:00:30 : la tentative du secours est close redemarrage et la demande repart au secours (rang 3, EX-8.12). Le secours refuse à son tour (14:00:31, permanente). EX-8.12 et EX-8.8 (complément du 2026-11-16) : la file est le seul état du planificateur ; le principal, épuisé avant l'arrêt, l'est encore après (tentative 1 echec_permanente) : les deux prestataires sont épuisés, alerte prestataires_epuises critique, la demande passe a_reprendre et sa reprise est programmée au pas retry.max_ms (14:05:31), en alternant ; le jeton de clôture n'est jamais abandonné (EX-4.5). Le principal répond à 14:05:32 avec un jeton promu.",
      configuration(),
      { queue_before: lus.demandes, jitter: [] },
    );
    s.demarrage("2026-11-03T14:00:30.000Z").echec("2026-11-03T14:00:31.000Z", PH1, 3, { pki_status: 2, failure_info: "unacceptedPolicy" }).tic("2026-11-03T14:05:31.000Z");
    s.granted("2026-11-03T14:05:32.000Z", PH1, 4, { gen_time: "2026-11-03T14:05:32Z", nom: "periode 1 apres epuisement", size: 3082 }).arret("2026-11-03T14:06:00.000Z");
    ajouter(s, (t) => {
      const ph2 = dem(t, PH1);
      return [
        ["au refus du secours : alerte prestataires_epuises critique, a_reprendre, reprise au pas retry.max_ms", JSON.stringify(t.expected.filter((a) => a.t === "2026-11-03T14:00:31.000Z" && a.request_id === PH1).map((a) => [a.action, a.detail.code ?? a.detail.state ?? a.detail.reason ?? a.detail.event ?? a.detail.error_code])) === JSON.stringify([["rejeter_reponse", "echec_unacceptedPolicy"], ["journaliser", "anchor_response_rejected"], ["alerter", "prestataires_epuises"], ["ecrire_file", "a_reprendre"], ["programmer", "backoff"]]) && actions(t, "programmer", (a) => a.t === "2026-11-03T14:00:31.000Z" && a.request_id === PH1)[0]?.detail.next_at === "2026-11-03T14:05:31.000Z"],
        ["reprise à 14:05:31 (rang 4), jeton obtenu", JSON.stringify(actions(t, "envoyer_rfc3161", (a) => a.request_id === PH1).map((a) => [a.t, a.detail.attempt])) === JSON.stringify([["2026-11-03T14:00:30.000Z", 3], ["2026-11-03T14:05:31.000Z", 4]]) && ph2.state === "obtenue"],
      ];
    });
  }

  // 53. registre-cle-par-journal (EX-9.4 ; complément du 2026-11-16) : le verrou de la clé de chaîne porte sur le journal
  // du sujet de l'ancre ; une ancre d'un autre journal n'attend pas.
  {
    const s = new Scenario(
      "registre-cle-par-journal",
      "Deux journaux de la même organisation dans la même file : le journal des vecteurs (journal-sinistres), dont le point de 09:13 est admis et ancré, et le journal de référence (journal-principal), dont la clôture de la période 1 est remise en retard, à 09:13:10, pendant que l'ancre de ce point attend son reçu. EX-9.4 (complément du 2026-11-16) : une seule transaction en vol par clé de chaîne, et la clé de chaîne d'une ancre, pour ce verrou, est celle du journal de son sujet (org_id, journal_id), une clé de chaîne ne servant qu'un journal. L'ancre de la période du journal de référence part donc aussitôt, sans attendre le nonce ; elle est incluse à 09:13:12 et le jeton de clôture part puis est obtenu ; l'ancre du point est incluse à 09:13:40.",
      configuration(),
      { jitter: [] },
    );
    const p0913 = pt(S1, "09:13");
    s.demarrage(jour("09:12:30")).pointSerie(p0913).entree(jour("09:13:10"), "periode_close", sujetPeriode(ex, 1)).inclusion(jour("09:13:12"), AP1, 30101);
    s.granted(jour("09:13:13"), PH1, 1, { gen_time: "2026-11-05T09:13:13Z", nom: "periode 1 remise en retard", size: 3082 }).inclusion(jour("09:13:40"), AS(p0913), 30113).arret(jour("09:13:50"));
    ajouter(s, (t) => [
      ["l'ancre de la période du journal de référence part à sa clôture, pendant que celle du point de 09:13 du journal des vecteurs attend son reçu", JSON.stringify(actions(t, "envoyer_registre").map((a) => [a.t, a.request_id])) === JSON.stringify([[jour("09:13:00"), AS(p0913)], [jour("09:13:10"), AP1]])],
      ["aucune attente du nonce", actions(t, "programmer", (a) => a.detail.reason === "attente_nonce").length === 0],
      ["les deux ancres et le jeton de clôture obtenus", [AP1, AS(p0913), PH1].every((id) => dem(t, id).state === "obtenue")],
    ]);
  }

  // 54. minuteries-deux-journaux (EX-8.16 ; complément du 2026-11-16) : minuteries de période de deux journaux d'une
  // même file, au même instant, déclenchées dans l'ordre où elles ont été armées, quel que soit leur journal.
  {
    const point1354 = { org_id: ORG_ID, journal_id: journalIdOf(SIN), period_start: PERIOD_START_1, tree_size: 3, checkpoint_hash: shaTexte("noortrace/vecteurs/ct5/minuteries-deux-journaux/point-13:54"), checkpoint_ts: "2026-11-03T13:54:00.000Z" };
    const s = new Scenario(
      "minuteries-deux-journaux",
      "Deux journaux de la même organisation dans la même file, période 1 de référence (13:00 à 14:00). Le point K2 du journal de référence (journal-principal) est admis à 13:53 : il ouvre la période de ce journal, dont l'échéance D_11 (13:55) est armée, puis arme la cadence de ce journal (alerte point_manquant à 13:55, 2 × checkpoint_interval_s après K2). Un point du journal des vecteurs (journal-sinistres, empreinte SHA-256(UTF-8(« noortrace/vecteurs/ct5/minuteries-deux-journaux/point-13:54 »)), tree_size 3) est admis à 13:54 : il ouvre la période de ce journal, dont l'échéance D_11 tombe aussi à 13:55, armée après la cadence du premier. EX-8.16 (complément du 2026-11-16) : les minuteries de période de même instant se déclenchent dans l'ordre où elles ont été armées, quel que soit leur journal : à 13:55, l'échéance du journal de référence, son alerte point_manquant, puis l'échéance du journal des vecteurs ; à 13:56, l'alerte point_manquant du journal des vecteurs. Aucune réponse : les deux ancres et les deux jetons sont encore en vol à l'arrêt.",
      configuration(),
      { jitter: [] },
    );
    s.demarrage("2026-11-03T13:52:30.000Z").point("K2").entree("2026-11-03T13:54:00.000Z", "point_produit", point1354);
    s.tic("2026-11-03T13:55:00.000Z").tic("2026-11-03T13:56:00.000Z").arret("2026-11-03T13:56:30.000Z");
    ajouter(s, (t) => {
      const periodiques = (instant) => t.expected.filter((a) => a.t === instant && a.request_id === null && (a.action === "echeance" || a.detail.event === "point_manquant" || a.detail.code === "point_manquant")).map((a) => [a.action, a.detail.k ?? a.detail.last_checkpoint_ts ?? a.detail.code]);
      return [
        ["à 13:55 : échéance D_11 du journal de référence, son alerte point_manquant, puis l'échéance D_11 du journal des vecteurs", JSON.stringify(periodiques("2026-11-03T13:55:00.000Z")) === JSON.stringify([["echeance", 11], ["journaliser", "2026-11-03T13:53:00.000Z"], ["alerter", "point_manquant"], ["echeance", 11]])],
        ["à 13:56 : alerte point_manquant du journal des vecteurs", JSON.stringify(periodiques("2026-11-03T13:56:00.000Z")) === JSON.stringify([["journaliser", "2026-11-03T13:54:00.000Z"], ["alerter", "point_manquant"]])],
        ["deux journaux dans la file", new Set(t.queue_after.map((d) => d.subject.journal_id)).size === 2],
      ];
    });
  }

  // 55. registre-refus-ancre-periode (EX-8.10, 8.9 ; complément du 2026-11-16) : le refus définitif de l'ancre d'une
  // période la reprend au pas retry.max_ms, sans gigue, avec l'alerte prestataires_epuises critique, une fois.
  {
    const s = new Scenario(
      "registre-refus-ancre-periode",
      "Clôture de la période 1 de référence : l'ancre de la période part à 14:00:00.250, le jeton de clôture attend son inclusion (attente_registre), la preuve OpenTimestamps est en attente à 14:00:01. Le registre refuse définitivement l'ancre (refus_emetteur_inconnu, 14:00:02). EX-8.10 (complément du 2026-11-16) : l'ancre d'une période n'est jamais abandonnée (EX-4.5) : tentative close echec_permanente, ligne anchor_retry de mode reprise, alerte prestataires_epuises critique (sans cette ancre, aucun jeton de clôture : un incident, comme un jeton de clôture refusé par ses deux prestataires, EX-8.8), puis a_reprendre au pas retry.max_ms (14:05:02), sans gigue. Renvoyée à 14:05:02, elle est refusée de nouveau à 14:05:03 : même reprise (14:10:03), sans seconde alerte. Renvoyée à 14:10:03, elle reçoit noeud_injoignable à 14:10:04 : échec transitoire, attente d'EX-8.9 (k = 3 tentatives en échec : 20 s) plus la première gigue de la trace (137 ms), que les refus n'ont pas consommée. Renvoyée à 14:10:24.137, elle est incluse à 14:10:30 ; le jeton de clôture part et il est obtenu. Entre-temps, l'attente du registre du jeton de clôture est réexaminée toutes les registry.inclusion_alert_s (registry_pending).",
      configuration(),
      { jitter: [137] },
    );
    s.demarrage("2026-11-03T13:59:00.000Z").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" });
    s.echecRegistre("2026-11-03T14:00:02.000Z", AP1, "refus_emetteur_inconnu").tic("2026-11-03T14:05:02.000Z").echecRegistre("2026-11-03T14:05:03.000Z", AP1, "refus_emetteur_inconnu");
    s.tic("2026-11-03T14:10:03.000Z").echecRegistre("2026-11-03T14:10:04.000Z", AP1, "noeud_injoignable").tic("2026-11-03T14:10:24.137Z").inclusion("2026-11-03T14:10:30.000Z", AP1, 21390);
    s.granted("2026-11-03T14:10:31.000Z", PH1, 1, { gen_time: "2026-11-03T14:10:31Z", nom: "periode 1 apres refus", size: 3082 }).arret("2026-11-03T14:11:00.000Z");
    ajouter(s, (t) => [
      ["une seule alerte prestataires_epuises, critique, au premier refus", JSON.stringify(actions(t, "alerter", (a) => a.request_id === AP1 && a.detail.code === "prestataires_epuises").map((a) => [a.t, a.detail.code, a.detail.severity])) === JSON.stringify([["2026-11-03T14:00:02.000Z", "prestataires_epuises", "critique"]])],
      ["au refus : anchor_retry de mode reprise, alerte, a_reprendre, reprise au pas retry.max_ms sans gigue", JSON.stringify(t.expected.filter((a) => a.t === "2026-11-03T14:00:02.000Z" && a.request_id === AP1).map((a) => [a.action, a.detail.event ?? a.detail.code ?? a.detail.state ?? a.detail.reason])) === JSON.stringify([["journaliser", "anchor_retry"], ["alerter", "prestataires_epuises"], ["ecrire_file", "a_reprendre"], ["programmer", "backoff"]]) && actions(t, "programmer", (a) => a.t === "2026-11-03T14:00:02.000Z" && a.request_id === AP1)[0]?.detail.next_at === "2026-11-03T14:05:02.000Z"],
      ["renvois à 14:05:02, 14:10:03 et 14:10:24.137 (gigue de 137 ms consommée par l'échec transitoire seul)", JSON.stringify(actions(t, "envoyer_registre", (a) => a.request_id === AP1).map((a) => a.t)) === JSON.stringify(["2026-11-03T14:00:00.250Z", "2026-11-03T14:05:02.000Z", "2026-11-03T14:10:03.000Z", "2026-11-03T14:10:24.137Z"])],
      ["tentatives : deux refus définitifs, un échec transitoire, l'inclusion", JSON.stringify(dem(t, AP1).attempts.map((a) => [a.outcome, a.error_code])) === JSON.stringify([["echec_permanente", "refus_emetteur_inconnu"], ["echec_permanente", "refus_emetteur_inconnu"], ["echec_transitoire", "noeud_injoignable"], ["obtenue", null]])],
      ["jeton de clôture envoyé après l'inclusion, obtenu", actions(t, "envoyer_rfc3161", (a) => a.request_id === PH1)[0]?.t === "2026-11-03T14:10:30.000Z" && dem(t, PH1).state === "obtenue"],
    ]);
  }

  // 56. registre-ordre-des-points (EX-9.4, EX-8.12 ; complément du 2026-11-16) : quand la clé se libère, l'ancre de
  // point qui part est celle du plus petit checkpoint_ts, non la première dans l'ordre de la file.
  {
    const avant = new Scenario("registre-ordre-des-points-avant", "x", configuration({ registry: { checkpoints: "tous" } }), { jitter: [] });
    avant.demarrage("2026-11-03T13:53:30.000Z").point("K3").arret("2026-11-03T13:54:10.000Z");
    avant.construire();
    const coupe = avant.lignes.findIndex((l) => { const d = JSON.parse(l); return d.id === ANCRE("K3") && d.state === "envoyee"; });
    exiger(coupe >= 0, "registre-ordre-des-points : ligne envoyee de l'ancre de K3");
    const lus = A.lireFile(avant.lignes.slice(0, coupe + 1).map((l) => l + "\n").join(""));
    exiger(!lus.truncated && lus.errors.length === 0 && lus.demandes.length === 1 && lus.demandes[0].state === "envoyee", "registre-ordre-des-points : file avant le redémarrage");
    const s = new Scenario(
      "registre-ordre-des-points",
      "Période 1 de référence, registry.checkpoints = tous. L'ancre de K3 part à 13:54 ; le composant s'arrête brutalement juste après sa ligne envoyee (EX-8.5, règle 1) : la file relue ne porte qu'elle. Au redémarrage à 14:01:30, l'ancre de K3 est renvoyée (anchor_retry de mode renvoi) ; l'enregistreur relit dans son stockage les points K1 à K4 de la période 1, dont le manifeste n'est pas relu, et K5 de la période 2, sans ancre obtenue (stockage_relu) : le dernier point de chaque période ouverte est admis (EX-8.12), K4 puis K5, au même instant ; leurs ancres attendent le nonce (la clé a l'ancre de K3 en vol). Dans l'ordre de la file (created_at, puis id), l'ancre de K5 précède celle de K4. EX-9.4 (complément du 2026-11-16, ordre des ancres d'une clé) : quand la clé se libère, part la première candidate de la clé, par period_start, puis, dans une même période, les ancres de points par checkpoint_ts avant l'ancre de la période, l'ordre de la file ne départageant que les égalités : au reçu de l'ancre de K3 (14:01:32), l'ancre de K4 part ; à son reçu (14:01:33), son jeton part, puis l'ancre de K5, incluse à 14:01:34. L'ordre d'inclusion des ancres des points d'un journal est ainsi celui de leurs checkpoint_ts (EX-10.7).",
      configuration({ registry: { checkpoints: "tous" } }),
      { queue_before: lus.demandes, jitter: [] },
    );
    s.demarrage("2026-11-03T14:01:30.000Z").stockage("2026-11-03T14:01:30.000Z", { checkpoints: ["K1", "K2", "K3", "K4", "K5"].map((n) => ({ org_id: ORG_ID, journal_id: JOURNAL_ID, period_start: POINTS[n].periode === 1 ? PERIOD_START_1 : PERIOD_START_2, tree_size: POINTS[n].tree_size, checkpoint_hash: POINTS[n].hash, checkpoint_ts: POINTS[n].ts })) });
    s.inclusion("2026-11-03T14:01:32.000Z", ANCRE("K3"), 21150).inclusion("2026-11-03T14:01:33.000Z", ANCRE("K4"), 21151).inclusion("2026-11-03T14:01:34.000Z", ANCRE("K5"), 21152);
    s.granted("2026-11-03T14:01:35.000Z", JETON("K4"), 1, { gen_time: "2026-11-03T14:01:34Z", nom: "K4 apres reconstruction" }).arret("2026-11-03T14:01:40.000Z");
    ajouter(s, (t) => {
      const file = [...t.queue_after].sort((a, b) => (a.created_at < b.created_at ? -1 : a.created_at > b.created_at ? 1 : a.id < b.id ? -1 : 1));
      const ancres = file.filter((d) => d.kind === "ancre_registre_point" && d.created_at === "2026-11-03T14:01:30.000Z").map((d) => d.id);
      return [
        ["les ancres de K4 et K5 créées au même instant, celle de K5 la première dans l'ordre de la file", JSON.stringify(ancres) === JSON.stringify([ANCRE("K5"), ANCRE("K4")])],
        ["les deux ancres attendent le nonce à 14:01:30", JSON.stringify(actions(t, "programmer", (a) => a.detail.reason === "attente_nonce").map((a) => [a.t, a.request_id])) === JSON.stringify([["2026-11-03T14:01:30.000Z", ANCRE("K4")], ["2026-11-03T14:01:30.000Z", ANCRE("K5")]])],
        ["envois : K3 renvoyée au démarrage, K4 au reçu de K3, K5 au reçu de K4 (checkpoint_ts croissants)", JSON.stringify(actions(t, "envoyer_registre").map((a) => [a.t, a.request_id])) === JSON.stringify([["2026-11-03T14:01:30.000Z", ANCRE("K3")], ["2026-11-03T14:01:32.000Z", ANCRE("K4")], ["2026-11-03T14:01:33.000Z", ANCRE("K5")]])],
        ["trois ancres obtenues, jeton de K4 obtenu", [ANCRE("K3"), ANCRE("K4"), ANCRE("K5"), JETON("K4")].every((id) => dem(t, id)?.state === "obtenue")],
      ];
    });
  }

  // 57. registre-periode-apres-point-de-cloture (EX-9.4 ; complément du 2026-11-16) : l'ancre du point de clôture attend
  // le nonce à la clôture ; l'ancre de la période ne part qu'après son reçu, même quand la clé se libère avant.
  {
    const s = new Scenario(
      "registre-periode-apres-point-de-cloture",
      "Période 1 de référence, registry.inclusion_alert_s porté à 600 s (aucun renvoi pendant la trace). L'ancre de K3 part à 13:54 et reste sans reçu ; son jeton part squat_wait_s plus tard (ordre_ancres_non_respecte). Aucun point n'est admis entre K3 et K4 : point_manquant à 13:56 (EX-4.1). K4, le point de clôture, est admis à 14:00:00.250 : son ancre attend le nonce (attente_nonce, la clé a l'ancre de K3 en vol) ; à la clôture, au même instant, l'ancre de la période attend aussi. EX-9.4 (complément du 2026-11-16 : « l'ancre de la période ne part qu'après le reçu de l'ancre du point de clôture de la même clé ») : au reçu de l'ancre de K3 (14:00:01), l'ancre de K4 part, non celle de la période (dans une même période, les ancres de ses points d'abord, la période ensuite). L'envoi de l'ancre de K4 échoue (noeud_injoignable, 14:00:02) : a_reprendre, reprise à l'attente d'EX-8.9 (k = 1 : 5 s, plus la gigue de 137 ms). La clé est libre, mais l'ancre de la période attend le reçu de celle de K4 : rien ne part. Le jeton de K4 part squat_wait_s après son admission (ordre_ancres_non_respecte) et il est obtenu ; le repli de clôture ne crée rien (le point de clôture a déjà sa demande). L'ancre de K4 repart à 14:00:07.137 ; à son reçu (14:00:08), l'ancre de la période part ; incluse à 14:00:09, le jeton de clôture part et il est obtenu. Les ancres de la période 1 sont ainsi incluses avant celle de la période (EX-10.7 : aucune ancre de point de la période 1 dans la fenêtre de la période 2). Auparavant, l'ancre de la période partait au reçu de celle de K3, puis à l'échec de celle de K4.",
      configuration({ registry: { inclusion_alert_s: 600 } }),
      { jitter: [137] },
    );
    s.demarrage("2026-11-03T13:53:30.000Z").point("K3").granted("2026-11-03T13:54:06.000Z", JETON("K3"), 1, { gen_time: "2026-11-03T13:54:06Z", nom: "K3 avant le point de cloture" });
    s.point("K4").cloture(ex, 1).inclusion("2026-11-03T14:00:01.000Z", ANCRE("K3"), 21080).echecRegistre("2026-11-03T14:00:02.000Z", ANCRE("K4"), "noeud_injoignable");
    s.ots("2026-11-03T14:00:03.000Z", OP1, { nom: "en attente periode 1" }).granted("2026-11-03T14:00:06.000Z", JETON("K4"), 1, { gen_time: "2026-11-03T14:00:06Z", nom: "K4 point de cloture" });
    s.tic("2026-11-03T14:00:07.137Z").inclusion("2026-11-03T14:00:08.000Z", ANCRE("K4"), 21082).inclusion("2026-11-03T14:00:09.000Z", AP1, 21083);
    s.granted("2026-11-03T14:00:10.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:10Z", nom: "periode 1 apres le point de cloture", size: 3082 }).arret("2026-11-03T14:00:30.000Z");
    ajouter(s, (t) => [
      ["à la clôture, l'ancre de K4 puis celle de la période attendent le nonce", JSON.stringify(actions(t, "programmer", (a) => a.detail.reason === "attente_nonce").map((a) => [a.t, a.request_id])) === JSON.stringify([["2026-11-03T14:00:00.250Z", ANCRE("K4")], ["2026-11-03T14:00:00.250Z", AP1]])],
      ["envois : K3, K4 au reçu de K3, K4 de nouveau à sa reprise, la période au reçu de K4 seulement", JSON.stringify(actions(t, "envoyer_registre").map((a) => [a.t, a.request_id])) === JSON.stringify([["2026-11-03T13:54:00.000Z", ANCRE("K3")], ["2026-11-03T14:00:01.000Z", ANCRE("K4")], ["2026-11-03T14:00:07.137Z", ANCRE("K4")], ["2026-11-03T14:00:08.000Z", AP1]])],
      ["aucun envoi au registre à l'échec de l'ancre de K4 (la clé est libre, la période attend son reçu)", actions(t, "envoyer_registre", (a) => a.t === "2026-11-03T14:00:02.000Z").length === 0 && dem(t, ANCRE("K4")).attempts.map((a) => a.error_code).join(",") === "noeud_injoignable,"],
      ["ancres de K3, K4 et de la période obtenues ; jetons de K3, K4 et de la clôture obtenus", [ANCRE("K3"), ANCRE("K4"), AP1, JETON("K3"), JETON("K4"), PH1].every((id) => dem(t, id)?.state === "obtenue")],
    ]);
  }

  // 58. redemarrage-ots-abandon-origine (EX-8.11, EX-8.12 ; complément du 2026-11-16) : l'âge d'abandon d'une preuve
  // OpenTimestamps en attente court depuis created_at de la demande, que la soumission reprise au démarrage ne déplace pas.
  {
    const cfg = configuration({ upgrade: { first_after_s: 60, interval_s: 1800, give_up_after_s: 3600 } });
    const avant = new Scenario("redemarrage-ots-abandon-origine-avant", "x", cfg, { jitter: [] });
    avant.demarrage("2026-11-03T13:59:00.000Z").cloture(ex, 1).inclusion("2026-11-03T14:00:01.000Z", AP1, 21087);
    avant.granted("2026-11-03T14:00:02.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:02Z", nom: "periode 1", size: 3082 }).arret("2026-11-03T14:00:03.000Z");
    avant.construire();
    const lus = A.lireFile(avant.lignes.map((l) => l + "\n").join(""));
    const etats = lus.demandes.map((d) => [d.id.split(":")[0], d.state]);
    exiger(!lus.truncated && lus.errors.length === 0 && JSON.stringify(etats) === JSON.stringify([["ancre_registre_periode", "obtenue"], ["jeton_periode", "obtenue"], ["ots_periode", "envoyee"]]), `redemarrage-ots-abandon-origine : file avant le redémarrage (${JSON.stringify(etats)})`);
    const s = new Scenario(
      "redemarrage-ots-abandon-origine",
      "Clôture de la période 1 de référence, cadence de mise à niveau raccourcie (upgrade.first_after_s 60 s, interval_s 1 800 s, give_up_after_s 3 600 s, le minimum). La file relue porte l'ancre et le jeton de la période obtenus et la soumission OpenTimestamps envoyee à la clôture (created_at 14:00:00.250), sans réponse : le composant s'est arrêté à 14:00:03. Au redémarrage, à 14:30:00, la soumission est close redemarrage et repart aussitôt (EX-8.12) ; la preuve est en attente à 14:30:01. Mises à niveau à 14:31:01 puis à 15:01:02, sans attestation Bitcoin (404). EX-8.11 (complément du 2026-11-16) : l'âge d'abandon court depuis created_at de la demande, écrit à sa création et porté par chaque ligne : à la réponse de 15:01:03, il dépasse give_up_after_s (3 602,75 s) ; l'alerte ots_give_up est levée et la mise à niveau suivante part un jour plus tard. Compté depuis la soumission reprise (14:30:00) ou depuis la preuve en attente (14:30:01), comme le faisaient la référence et le composant d'ancrage, il repartait à chaque redémarrage pendant la soumission, et l'alerte attendait 15:31.",
      cfg,
      { queue_before: lus.demandes, jitter: [] },
    );
    s.demarrage("2026-11-03T14:30:00.000Z").ots("2026-11-03T14:30:01.000Z", OP1, { nom: "en attente periode 1 apres redemarrage" });
    s.ots("2026-11-03T14:31:02.000Z", OP1, { attestation: "en_attente", calendars_answered: 1 }).ots("2026-11-03T15:01:03.000Z", OP1, { attestation: "en_attente", calendars_answered: 1 }).arret("2026-11-03T15:02:00.000Z");
    ajouter(s, (t) => [
      ["soumission reprise au démarrage, au rang 2 ; preuve en attente à 14:30:01", JSON.stringify(actions(t, "soumettre_ots").map((a) => a.t)) === JSON.stringify(["2026-11-03T14:30:00.000Z"]) && dem(t, OP1).result?.obtained_at === "2026-11-03T14:30:01.000Z" && dem(t, OP1).created_at === "2026-11-03T14:00:00.250Z"],
      ["mises à niveau à 14:31:01 et 15:01:02", JSON.stringify(actions(t, "mettre_a_niveau_ots").map((a) => a.t)) === JSON.stringify(["2026-11-03T14:31:01.000Z", "2026-11-03T15:01:02.000Z"])],
      ["ots_give_up levée à 15:01:03, depuis created_at ; mise à niveau suivante un jour plus tard", JSON.stringify(actions(t, "alerter", (a) => a.request_id === OP1).map((a) => [a.t, a.detail.code, a.detail.severity])) === JSON.stringify([["2026-11-03T15:01:03.000Z", "ots_give_up", "majeure"]]) && dem(t, OP1).due_at === "2026-11-04T15:01:03.000Z" && dem(t, OP1).state === "en_attente"],
    ]);
  }

  // 59. registre-periode-retient-la-cle (EX-9.4, EX-10.7 ; complément du 2026-11-16) : une ancre de période qui n'a pas
  // son reçu retient sa clé ; aucune ancre d'une période postérieure de la même clé ne part avant elle.
  {
    const cfg = configuration({ registry: { checkpoints: "tous", inclusion_alert_s: 3600 }, retry: { initial_ms: 600000, factor: 10, max_ms: 86400000 } });
    const s = new Scenario(
      "registre-periode-retient-la-cle",
      "Période 1 de référence, registry.checkpoints = tous, registry.inclusion_alert_s 3 600 s ; attente de reprise allongée (retry.initial_ms 600 000, factor 10, max_ms 86 400 000 : 10 min, puis 100 min, plus la gigue). L'ancre de K4, point de clôture, part à 14:00:00.250 ; à la clôture, l'ancre de la période attend son reçu (EX-9.4), puis part à 14:00:01. K5, premier point de la période 2, est admis à 14:01 : son ancre attend le nonce (l'ancre de la période 1 est en vol). L'envoi de l'ancre de la période 1 échoue (noeud_injoignable, 14:01:01) : a_reprendre, reprise à 14:11:01.137. La clé n'a plus d'ancre en vol, mais EX-9.4 (complément du 2026-11-16 : une ancre de période qui attend retient sa clé) : aucune ancre d'une période postérieure ne part tant que l'ancre de la période 1 n'a ni son reçu ni un autre état final ; l'ancre de K5 ne part pas. La reprise de 14:11:01.137 échoue de nouveau (14:11:02 ; reprise à 15:51:02.041). K6, point de clôture de la période 2, est admis à 15:00:00.112 : son ancre remplace celle de K5 (EX-9.5) et attend, la clé n'ayant pourtant aucune ancre en vol ; la clôture de la période 2 arrive à 15:00:02 : son ancre attend celle de K6 et celle de la période 1. À 15:51:02.041, l'ancre de la période 1 repart ; à son reçu (15:51:03), le jeton de clôture de la période 1 part, puis l'ancre de K6 ; à son reçu (15:51:04), l'ancre de la période 2. Les ancres sont ainsi incluses dans l'ordre des périodes, et la fenêtre de blocs de la période 2 (EX-10.7) commence après l'ancre de la période 1. Auparavant, l'ancre de K5 partait à l'échec de 14:01:01 et, si son reçu précédait la clôture de la période 2, l'ancre de celle-ci partait avant celle de la période 1.",
      cfg,
      { jitter: [137, 41] },
    );
    s.demarrage("2026-11-03T13:59:00.000Z").point("K4").cloture(ex, 1).inclusion("2026-11-03T14:00:01.000Z", ANCRE("K4"), 21500);
    s.point("K5").echecRegistre("2026-11-03T14:01:01.000Z", AP1, "noeud_injoignable").tic("2026-11-03T14:11:01.137Z").echecRegistre("2026-11-03T14:11:02.000Z", AP1, "noeud_injoignable");
    s.point("K6").entree("2026-11-03T15:00:02.000Z", "periode_close", sujetPeriode(ex, 2));
    s.tic("2026-11-03T15:51:02.041Z").inclusion("2026-11-03T15:51:03.000Z", AP1, 21900).inclusion("2026-11-03T15:51:04.000Z", ANCRE("K6"), 21901).inclusion("2026-11-03T15:51:05.000Z", AP2, 21902).arret("2026-11-03T15:52:00.000Z");
    ajouter(s, (t) => [
      ["envois : K4, la période 1 et ses deux reprises, K6 au reçu de la période 1, la période 2 au reçu de K6", JSON.stringify(actions(t, "envoyer_registre").map((a) => [a.t, a.request_id])) === JSON.stringify([["2026-11-03T14:00:00.250Z", ANCRE("K4")], ["2026-11-03T14:00:01.000Z", AP1], ["2026-11-03T14:11:01.137Z", AP1], ["2026-11-03T15:51:02.041Z", AP1], ["2026-11-03T15:51:03.000Z", ANCRE("K6")], ["2026-11-03T15:51:04.000Z", AP2]])],
      ["attentes du nonce : la période 1 à sa clôture, K5, K6 et la période 2 à leur création", JSON.stringify(actions(t, "programmer", (a) => a.detail.reason === "attente_nonce").map((a) => [a.t, a.request_id])) === JSON.stringify([["2026-11-03T14:00:00.250Z", AP1], ["2026-11-03T14:01:00.000Z", ANCRE("K5")], ["2026-11-03T15:00:00.112Z", ANCRE("K6")], ["2026-11-03T15:00:02.000Z", AP2]])],
      ["aucun envoi au registre à l'échec de 14:01:01 (la clé est libre d'ancre en vol, la période 1 la retient)", actions(t, "envoyer_registre", (a) => a.t === "2026-11-03T14:01:01.000Z").length === 0],
      ["K5 remplacée par K6 ; ancres de K4, K6, des périodes 1 et 2 obtenues", dem(t, ANCRE("K5")).state === "remplacee" && [ANCRE("K4"), ANCRE("K6"), AP1, AP2].every((id) => dem(t, id)?.state === "obtenue")],
    ]);
  }

  // 60. redemarrage-ots-abandon-soumission-tardive (EX-8.11, EX-8.12 ; complément du 2026-11-16) : une soumission qui
  // aboutit au-delà de give_up_after_s après created_at lève ots_give_up dès la preuve en attente ; la première mise à
  // niveau reste à first_after_s, puis une fois par jour.
  {
    const cfg = configuration({ upgrade: { first_after_s: 60, interval_s: 1800, give_up_after_s: 3600 } });
    const avant = new Scenario("redemarrage-ots-abandon-soumission-tardive-avant", "x", cfg, { jitter: [] });
    avant.demarrage("2026-11-03T13:59:00.000Z").cloture(ex, 1).inclusion("2026-11-03T14:00:01.000Z", AP1, 21087);
    avant.granted("2026-11-03T14:00:02.000Z", PH1, 1, { gen_time: "2026-11-03T14:00:02Z", nom: "periode 1", size: 3082 }).arret("2026-11-03T14:00:03.000Z");
    avant.construire();
    const lus = A.lireFile(avant.lignes.map((l) => l + "\n").join(""));
    const etats = lus.demandes.map((d) => [d.id.split(":")[0], d.state]);
    exiger(!lus.truncated && lus.errors.length === 0 && JSON.stringify(etats) === JSON.stringify([["ancre_registre_periode", "obtenue"], ["jeton_periode", "obtenue"], ["ots_periode", "envoyee"]]), `redemarrage-ots-abandon-soumission-tardive : file avant le redémarrage (${JSON.stringify(etats)})`);
    const s = new Scenario(
      "redemarrage-ots-abandon-soumission-tardive",
      "Clôture de la période 1 de référence, cadence de mise à niveau raccourcie (upgrade.first_after_s 60 s, interval_s 1 800 s, give_up_after_s 3 600 s, le minimum). La file relue porte l'ancre et le jeton de la période obtenus et la soumission OpenTimestamps envoyee à la clôture (created_at 14:00:00.250), sans réponse : le composant s'est arrêté à 14:00:03 et ne redémarre qu'à 15:30:00, au-delà de give_up_after_s (horloge avancée). La soumission est close redemarrage et repart aussitôt (EX-8.12) ; la preuve est en attente à 15:30:01, 5 400,75 s après created_at. EX-8.11 (complément du 2026-11-16) : l'alerte ots_give_up est levée dès ce passage en_attente, comme la jauge noortrace_anchoring_ots_pending_age_s, de même origine, le signale ; la première mise à niveau reste à first_after_s (15:31:01) : la preuve vient d'être soumise aux calendriers ; à sa réponse sans attestation Bitcoin (404, 15:31:02), la mise à niveau suivante part un jour plus tard, sans nouvelle alerte. Auparavant, la référence et le composant d'ancrage ne levaient l'alerte qu'à cette réponse.",
      cfg,
      { queue_before: lus.demandes, jitter: [] },
    );
    s.demarrage("2026-11-03T15:30:00.000Z").ots("2026-11-03T15:30:01.000Z", OP1, { nom: "en attente periode 1 apres un long arret" });
    s.ots("2026-11-03T15:31:02.000Z", OP1, { attestation: "en_attente", calendars_answered: 1 }).arret("2026-11-03T15:32:00.000Z");
    ajouter(s, (t) => [
      ["soumission reprise au démarrage ; preuve en attente à 15:30:01 ; created_at inchangé", JSON.stringify(actions(t, "soumettre_ots").map((a) => a.t)) === JSON.stringify(["2026-11-03T15:30:00.000Z"]) && dem(t, OP1).result?.obtained_at === "2026-11-03T15:30:01.000Z" && dem(t, OP1).created_at === "2026-11-03T14:00:00.250Z"],
      ["ots_give_up levée une fois, à 15:30:01, avant l'écriture en_attente", JSON.stringify(actions(t, "alerter", (a) => a.request_id === OP1).map((a) => [a.t, a.detail.code, a.detail.severity])) === JSON.stringify([["2026-11-03T15:30:01.000Z", "ots_give_up", "majeure"]]) && JSON.stringify(t.expected.filter((a) => a.t === "2026-11-03T15:30:01.000Z" && a.request_id === OP1).map((a) => a.action)) === JSON.stringify(["stocker", "alerter", "ecrire_file", "programmer"])],
      ["première mise à niveau à first_after_s (15:31:01), la suivante un jour plus tard", JSON.stringify(actions(t, "mettre_a_niveau_ots").map((a) => a.t)) === JSON.stringify(["2026-11-03T15:31:01.000Z"]) && dem(t, OP1).due_at === "2026-11-04T15:31:02.000Z" && dem(t, OP1).state === "en_attente"],
    ]);
  }

  // 61. registre-refus-ancre-periode-redemarrage (EX-8.10, EX-8.12 ; complément du 2026-11-16) : l'alerte du refus
  // définitif de l'ancre d'une période est levée une fois par ancre depuis le dernier démarrage : de nouveau après un
  // redémarrage, puis plus.
  {
    const avant = new Scenario("registre-refus-ancre-periode-redemarrage-avant", "x", configuration(), { jitter: [] });
    avant.demarrage("2026-11-03T13:59:00.000Z").cloture(ex, 1).ots("2026-11-03T14:00:01.000Z", OP1, { nom: "en attente periode 1" });
    avant.echecRegistre("2026-11-03T14:00:02.000Z", AP1, "refus_emetteur_inconnu").arret("2026-11-03T14:00:03.000Z");
    const a = avant.construire();
    exiger(JSON.stringify(actions(a, "alerter", (x) => x.request_id === AP1).map((x) => [x.t, x.detail.code, x.detail.severity])) === JSON.stringify([["2026-11-03T14:00:02.000Z", "prestataires_epuises", "critique"]]), "registre-refus-ancre-periode-redemarrage : alerte du premier refus avant l'arrêt");
    exiger(dem(a, AP1)?.state === "a_reprendre" && dem(a, AP1)?.due_at === "2026-11-03T14:05:02.000Z", "registre-refus-ancre-periode-redemarrage : file avant le redémarrage");
    const s = new Scenario(
      "registre-refus-ancre-periode-redemarrage",
      "Suite de la trace registre-refus-ancre-periode après un redémarrage. Avant l'arrêt (14:00:03), le registre a refusé définitivement l'ancre de la période 1 (refus_emetteur_inconnu, 14:00:02) et l'alerte prestataires_epuises critique a été levée ; la file relue porte l'ancre a_reprendre (due_at 14:05:02, exactement retry.max_ms après le refus), le jeton de clôture attente_registre et la preuve OpenTimestamps en attente. Au redémarrage (14:01:00), l'ancre garde son due_at (EX-8.12) ; elle repart à 14:05:02 et le registre la refuse de nouveau (14:05:03). EX-8.10 : l'alerte est levée une fois par ancre depuis le dernier démarrage : la marque de l'alerte d'avant l'arrêt n'est pas dans la file, et ce premier refus après le redémarrage la lève de nouveau ; le refus suivant (14:10:04) ne la lève pas. L'ancre repart à 14:15:04, au pas retry.max_ms sans gigue, et elle est incluse à 14:15:05 ; le jeton de clôture part alors et il est obtenu.",
      configuration(),
      { queue_before: a.queue_after, jitter: [] },
    );
    s.demarrage("2026-11-03T14:01:00.000Z").tic("2026-11-03T14:05:02.000Z").echecRegistre("2026-11-03T14:05:03.000Z", AP1, "refus_emetteur_inconnu");
    s.tic("2026-11-03T14:10:03.000Z").echecRegistre("2026-11-03T14:10:04.000Z", AP1, "refus_emetteur_inconnu").tic("2026-11-03T14:15:04.000Z").inclusion("2026-11-03T14:15:05.000Z", AP1, 21400);
    s.granted("2026-11-03T14:15:06.000Z", PH1, 1, { gen_time: "2026-11-03T14:15:06Z", nom: "periode 1 apres refus et redemarrage", size: 3082 }).arret("2026-11-03T14:16:00.000Z");
    ajouter(s, (t) => [
      ["une alerte prestataires_epuises critique, au premier refus après le redémarrage seulement", JSON.stringify(actions(t, "alerter", (x) => x.request_id === AP1 && x.detail.code === "prestataires_epuises").map((x) => [x.t, x.detail.severity])) === JSON.stringify([["2026-11-03T14:05:03.000Z", "critique"]])],
      ["renvois à 14:05:02, 14:10:03 et 14:15:04 (retry.max_ms, sans gigue)", JSON.stringify(actions(t, "envoyer_registre", (x) => x.request_id === AP1).map((x) => x.t)) === JSON.stringify(["2026-11-03T14:05:02.000Z", "2026-11-03T14:10:03.000Z", "2026-11-03T14:15:04.000Z"])],
      ["ancre et jeton de clôture obtenus", dem(t, AP1)?.state === "obtenue" && dem(t, PH1)?.state === "obtenue"],
    ]);
  }

  // 62. registre-points-en-reprise (EX-9.5, EX-9.4, EX-10.7 ; complément du 2026-11-16) : l'ancre d'un point en reprise
  // quand le point suivant de sa période est admis : remplacée si aucune de ses tentatives n'a pu être admise par un
  // nœud, attendue sinon.
  {
    const cfg = configuration({ registry: { checkpoints: "tous", inclusion_alert_s: 3600 }, retry: { initial_ms: 600000, max_ms: 3600000 } });
    const s = new Scenario(
      "registre-points-en-reprise",
      "Période 1 de référence, registry.checkpoints = tous, registry.inclusion_alert_s 3 600 s ; attente de reprise allongée (retry.initial_ms 600 000, max_ms 3 600 000 : 10 min, plus la gigue). L'ancre de K2 part à 13:53:00 ; le registre signale son échec à 13:53:01 (noeud_injoignable : aucun point n'a répondu, rien n'est parti) : a_reprendre, reprise à 14:03:01.137. K3 est admis à 13:54:00, pendant cette reprise. EX-9.5 (complément du 2026-11-16) : une ancre a_reprendre dont aucune tentative n'a pu être admise par un nœud est encore à envoyer ; l'ancre de K3 la remplace et part aussitôt, la clé n'ayant aucune ancre en vol. Le registre signale l'échec de l'ancre de K3 à 13:54:01, cette fois recu_absent : la transaction est partie et peut encore être incluse ; a_reprendre, reprise à 14:04:01.041. K4, point de clôture, est admis à 14:00:00.250, puis la période se clôt : l'ancre de K3 n'est ni remplacée (EX-9.5 : une ancre qui a pu partir n'est jamais abandonnée) ni dépassée : EX-9.4 (complément du 2026-11-16) : l'ancre d'un point ne part pas tant que celle d'un point antérieur de sa période n'a ni son reçu ni un autre état final ; l'ancre de K4 attend le nonce, la clé n'ayant pourtant aucune ancre en vol, et l'ancre de la période attend celle de K4. L'ancre de K3 repart à 14:04:01.041 ; à son reçu (14:04:02), l'ancre de K4 part ; à son reçu (14:04:03), l'ancre de la période ; incluse à 14:04:04, le jeton de clôture part. Les ancres des points sont incluses dans l'ordre de leurs checkpoint_ts (EX-10.7). Auparavant, la référence renvoyait l'ancre de K2 après celle de K3 (le composant d'ancrage la remplaçait), et les deux faisaient partir l'ancre de K4 à 14:00:00.250, avant le renvoi de celle de K3 : incluses dans cet ordre, la série était hors_ordre.",
      cfg,
      { jitter: [137, 41] },
    );
    s.demarrage("2026-11-03T13:52:30.000Z").point("K2").echecRegistre("2026-11-03T13:53:01.000Z", ANCRE("K2"), "noeud_injoignable");
    s.point("K3").echecRegistre("2026-11-03T13:54:01.000Z", ANCRE("K3"), "recu_absent").point("K4").cloture(ex, 1);
    s.tic("2026-11-03T14:04:01.041Z").inclusion("2026-11-03T14:04:02.000Z", ANCRE("K3"), 21500).inclusion("2026-11-03T14:04:03.000Z", ANCRE("K4"), 21501).inclusion("2026-11-03T14:04:04.000Z", AP1, 21502).arret("2026-11-03T14:05:00.000Z");
    ajouter(s, (t) => [
      ["envois : K2, K3 qui la remplace, K3 à sa reprise, K4 au reçu de K3, la période au reçu de K4", JSON.stringify(actions(t, "envoyer_registre").map((a) => [a.t, a.request_id])) === JSON.stringify([["2026-11-03T13:53:00.000Z", ANCRE("K2")], ["2026-11-03T13:54:00.000Z", ANCRE("K3")], ["2026-11-03T14:04:01.041Z", ANCRE("K3")], ["2026-11-03T14:04:02.000Z", ANCRE("K4")], ["2026-11-03T14:04:03.000Z", AP1]])],
      ["K2 remplacée par K3 à 13:54:00", JSON.stringify(actions(t, "remplacer").map((a) => [a.t, a.request_id, a.detail.replaced_by])) === JSON.stringify([["2026-11-03T13:54:00.000Z", ANCRE("K2"), ANCRE("K3")]]) && dem(t, ANCRE("K2")).state === "remplacee"],
      ["attentes du nonce : K4 à sa création, la clé libre, et la période", JSON.stringify(actions(t, "programmer", (a) => a.detail.reason === "attente_nonce").map((a) => [a.t, a.request_id])) === JSON.stringify([["2026-11-03T14:00:00.250Z", ANCRE("K4")], ["2026-11-03T14:00:00.250Z", AP1]])],
      ["ancres de K3, K4 et de la période obtenues ; jeton de clôture envoyé à 14:04:04", [ANCRE("K3"), ANCRE("K4"), AP1].every((id) => dem(t, id)?.state === "obtenue") && actions(t, "envoyer_rfc3161", (a) => a.request_id === PH1).map((a) => a.t)[0] === "2026-11-03T14:04:04.000Z"],
    ]);
  }

  exiger(liste.length === 62, "soixante-deux traces attendues");
  return liste;
}

/** La trace empreinte-squattee (menace MN-58), rejouée par la bibliothèque de référence, sans rien écrire. */
export function traceEmpreinteSquattee() {
  const { trace } = traces(exempleCT1()).find((x) => x.trace.id === "empreinte-squattee") ?? { trace: null };
  exiger(trace !== null, "trace empreinte-squattee attendue");
  return trace;
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
  // Revue de l'étape 8 (CT-5 EX-5.10) : un PKIStatus hors de 0 à 5 suivi d'un jeton valable (octet du statut réécrit : la référence refuse de le construire) ; placé en fin de famille pour laisser les numéros de série des cas antérieurs inchangés.
  const statut6 = Buffer.from(A.construireReponseTsa({ status: 0, token: jetonBase() }));
  const iStatut = statut6.indexOf(Buffer.from("3003020100", "hex"));
  exiger(iStatut >= 2 && iStatut <= 4, "statut-6 : PKIStatusInfo 30 03 02 01 00 attendu en tête de la réponse");
  statut6[iStatut + 4] = 6;
  ajouter("statut-6", "PKIStatus 6, hors de 0 à 5, suivi d'un jeton par ailleurs valable : statut_6, permanente, le jeton n'est pas lu ni promu (EX-5.10, étape 2 : « toute autre valeur : erreur » ; revue de l'étape 8).", { requete: base, reponse: statut6, ...t0, attendu: { outcome: "echec_permanente", error_code: "statut_6" } });
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
// Famille configuration (AN-1, EX-4.9 ; complément du 2026-11-16)
// ---------------------------------------------------------------------------

/**
 * Cas de la configuration ancrage-v0 (AN-1 : schéma, puis les règles hors schéma d'EX-4.9), tirés de l'exemple d'EX-4.8 :
 * règle 4 (prestataire interne jamais qualifié, identifiant dans l'url, source d'en-têtes en production, authentification
 * et secret cohérents, serveur interne comme principal hors production seulement), 4 bis (forme de crl_hosts) et 9 (OID
 * de politique encodables). Attendu : `valide` et la liste triée des règles violées (`schema`, `1` à `9`), calculés par
 * verifierConfiguration de la référence et contrôlés ici contre l'attendu écrit à la main.
 */
export function familleConfiguration() {
  // L'adresse locale du serveur interne est écrite `localhost` (même règle 4) : aucune adresse IP dans les vecteurs (EX-A.6).
  const exemple = () => JSON.parse(JSON.stringify(blocsSpec(SPEC_CT5, "ancrage")[0]).replaceAll("http://127.0.0.1:", "http://localhost:"));
  const de = (doc, role) => doc.rfc3161.providers.find((p) => p.role === role);
  const cases = [];
  const ajouter = (id, description, profil, modifier, regles) => {
    const document = exemple();
    modifier(document);
    const r = A.verifierConfiguration(document, { profil, checkpoint_interval_s: 60 });
    const obtenues = [...new Set(r.violations.map((v) => String(v.rule)))].sort();
    exiger(JSON.stringify(obtenues) === JSON.stringify([...regles].sort()), `configuration ${id} : règles ${JSON.stringify(obtenues)}, attendu ${JSON.stringify(regles)} (${JSON.stringify(r.violations.slice(0, 3))})`);
    cases.push({ id, description, input: { document, profil, checkpoint_interval_s: 60 }, expected: { valide: obtenues.length === 0, regles: obtenues } });
  };
  const rien = () => {};
  const qualifie = (doc) => JSON.parse(JSON.stringify(de(doc, "principal").qualified));
  ajouter("exemple-production", "L'exemple d'EX-4.8 en production, avec la valeur checkpoint_interval_s de l'enregistreur : aucune règle violée.", "production", rien, []);
  ajouter("exemple-developpement", "L'exemple d'EX-4.8 en développement : aucune règle violée.", "developpement", rien, []);
  ajouter("interne-qualifie", "Règle 4 (révision 0.10) : le prestataire de rôle interne déclaré qualified, dans tout profil (EX-5.6, EX-7.2).", "developpement", (d) => { de(d, "interne").qualified = qualifie(d); }, ["4"]);
  ajouter("interne-qualifie-production", "Règle 4 : le même document en production.", "production", (d) => { de(d, "interne").qualified = qualifie(d); }, ["4"]);
  ajouter("url-avec-identifiant", "Règle 4 et EX-4.8 (AN-54) : url du principal portant un identifiant et un mot de passe ; le schéma la refuse (motif de url).", "developpement", (d) => { de(d, "principal").url = "https://compte:secret@horodatage-principal.example/tsa"; }, ["schema"]);
  ajouter("source-entetes-nulle-production", "Règle 4 (révision 0.10 ; EX-6.6, EX-6.9) : opentimestamps.headers_source nul en production.", "production", (d) => { d.opentimestamps.headers_source = null; }, ["4"]);
  ajouter("source-entetes-nulle-developpement", "Règle 4 : opentimestamps.headers_source nul hors production : admis.", "developpement", (d) => { d.opentimestamps.headers_source = null; }, []);
  ajouter("basic-sans-secret", "Règle 4 (révision 0.10) : principal en basic sans secret, dans tout profil.", "developpement", (d) => { de(d, "principal").auth.secret = null; }, ["4"]);
  ajouter("aucune-avec-secret", "Règle 4 (révision 0.10) : prestataire interne sans authentification portant un secret.", "developpement", (d) => { de(d, "interne").auth.secret = { env: "NOORTRACE_TSA_ESSAI" }; }, ["4"]);
  const principalInterne = (d) => {
    const p = de(d, "principal");
    p.url = "http://localhost:2020/";
    p.auth = { method: "aucune", secret: null };
    p.qualified = null;
  };
  ajouter("principal-interne-developpement", "Règle 4 (révision 0.9) : hors production, le principal peut être le serveur RFC 3161 interne (http:// local, sans authentification, qualified nul).", "developpement", principalInterne, []);
  ajouter("principal-interne-production", "Règle 4 : le même principal en production est refusé (sans qualified, http://, sans authentification).", "production", principalInterne, ["4"]);
  ajouter("crl-hotes-donnes", "Règle 4 bis (révision 0.10) : crl_hosts donnée pour le principal, noms d'hôte en minuscules : admise dans tout profil.", "production", (d) => { de(d, "principal").crl_hosts = ["crl.horodatage-principal.example", "ocsp.horodatage-principal.example"]; }, []);
  ajouter("crl-hotes-vide", "Règle 4 bis : crl_hosts vide ; le schéma exige au moins un nom (null pour aucune liste).", "production", (d) => { de(d, "principal").crl_hosts = []; }, ["schema"]);
  ajouter("crl-hotes-majuscules", "Règle 4 bis : un nom de crl_hosts hors du motif des noms d'hôte (majuscules) ; refusé par le schéma.", "production", (d) => { de(d, "principal").crl_hosts = ["CRL.Horodatage-Principal.example"]; }, ["schema"]);
  ajouter("oid-second-arc-40", "Règle 9 (révision 0.10) : policy_oid du serveur interne 1.40.5, second arc supérieur à 39 sous le premier arc 1 : non encodable dans la requête d'EX-5.1.", "developpement", (d) => { de(d, "interne").policy_oid = "1.40.5"; }, ["9"]);
  ajouter("oid-arc-2-128", "Règle 9 : un OID d'accepted_policies dont un arc vaut 2^128, au-delà des 128 bits admis.", "developpement", (d) => { de(d, "interne").accepted_policies = ["1.3.6.1.4.1.99999.1.1", "2.25.340282366920938463463374607431768211456"]; }, ["9"]);
  ajouter("oid-arc-2-128-moins-1", "Règle 9 : le même OID dont l'arc vaut 2^128 - 1 : encodable, admis.", "developpement", (d) => { de(d, "interne").accepted_policies = ["1.3.6.1.4.1.99999.1.1", "2.25.340282366920938463463374607431768211455"]; }, []);
  ajouter("oid-der-trop-long", "Règle 9 : policy_oid de deux cents arcs (DER de plus de 127 octets) ; la chaîne tient dans maxLength.", "developpement", (d) => { de(d, "interne").policy_oid = `1.3${".1".repeat(198)}`; }, ["9"]);
  // Complément du 2026-11-16 : les 127 octets de la règle 9 comptent l'OBJECT IDENTIFIER entier (étiquette 06, longueur,
  // contenu) ; 1.3 suivi de n arcs 1 a un contenu de n + 1 octets.
  ajouter("oid-der-127-octets", "Règle 9 (complément du 2026-11-16) : policy_oid 1.3 suivi de 124 arcs 1 : contenu de 125 octets, DER de 127 octets étiquette et longueur comprises : admis.", "developpement", (d) => { de(d, "interne").policy_oid = `1.3${".1".repeat(124)}`; }, []);
  ajouter("oid-der-128-octets", "Règle 9 (complément du 2026-11-16) : policy_oid 1.3 suivi de 125 arcs 1 : contenu de 126 octets, DER de 128 octets étiquette et longueur comprises : refusé (un compte du seul contenu l'admettrait).", "developpement", (d) => { de(d, "interne").policy_oid = `1.3${".1".repeat(125)}`; }, ["9"]);
  // Complément du 2026-11-16 : règles d'adresse et d'authentification du rôle interne lui-même, dans tout profil.
  ajouter("interne-https-sans-authentification", "Règle 4 (complément du 2026-11-16) : prestataire interne en https:// vers localhost, auth.method aucune : refusé (https:// exige basic ou certificat_client ; AN-27).", "developpement", (d) => { de(d, "interne").url = "https://localhost:2020/"; }, ["4"]);
  ajouter("interne-http-local-basic", "Règle 4 (complément du 2026-11-16) : prestataire interne en http:// vers localhost avec basic et un secret : refusé (http:// local va sans authentification ; basic seulement sur TLS, EX-5.5).", "developpement", (d) => { de(d, "interne").auth = { method: "basic", secret: { env: "NOORTRACE_TSA_INTERNE" } }; }, ["4"]);
  ajouter("interne-https-basic", "Règle 4 (complément du 2026-11-16) : prestataire interne en https:// avec basic et un secret : admis dans tout profil (ici en production).", "production", (d) => { const p = de(d, "interne"); p.url = "https://horodatage-interne.example/tsa"; p.auth = { method: "basic", secret: { env: "NOORTRACE_TSA_INTERNE" } }; }, []);
  // Complément du 2026-11-16 : règle 8, certificat dont le DER s'arrête avant la fin de sa structure (lecteur DER borné, EX-9.4 de CT-6).
  const tronque = (pem) => {
    const der = Buffer.from(pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, ""), "base64");
    const b64 = der.subarray(0, der.length - 3).toString("base64");
    return `-----BEGIN CERTIFICATE-----\n${b64.match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;
  };
  ajouter("certificat-tronque", "Règle 8 (complément du 2026-11-16) : le certificat d'ancre du serveur interne privé de ses trois derniers octets (PEM canonique) : son DER s'arrête avant la fin de la SEQUENCE Certificate : illisible par le lecteur DER borné de CT-6 §9.3.", "developpement", (d) => { const p = de(d, "interne"); p.anchor_certificates = [tronque(p.anchor_certificates[0])]; }, ["8"]);
  ajouter("regles-4-et-9","Règles 4 et 9 ensemble : prestataire interne qualified et policy_oid non encodable ; la liste porte les deux règles.", "developpement", (d) => { de(d, "interne").qualified = qualifie(d); de(d, "interne").policy_oid = "0.40"; }, ["4", "9"]);
  return { version: 0, family: "configuration", description: "Configuration ancrage-v0 (AN-1, EX-4.9 ; complément du 2026-11-16) : pour un document, un profil de CT-2 §15 et la valeur checkpoint_interval_s de l'enregistreur, le verdict et la liste triée des règles violées (schema, puis 1 à 9). Documents tirés de l'exemple d'EX-4.8, l'adresse locale du serveur interne écrite localhost (EX-A.6).", cases };
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

function index({ constantes: c, requetes, reponses, ots, traces: tr, cout, reprise, configuration: conf }) {
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
  L.push("cd spec/vecteurs/ct-5/verificateur-independant && go run . ..   # vérificateur Go de cohérence, non indépendant (A.5)");
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
  L.push("Révision 0.6 de CT-5 : chaque ligne de file écrite par le planificateur (`queue_after`, fichiers de `reprise/`) porte au plus 32 tentatives et `attempts_total` (EX-8.5, règle 7) ; une demande relue d'une file écrite avant la révision et que la trace ne réécrit pas garde sa ligne sans `attempts_total` (`redemarrage-reprise`). Chaque ligne `checkpoint_countersigned` porte `d_admission_s` (instant d'admission du point moins `checkpoint_ts`, tronqués à la seconde depuis `D_k`) et `d_attente_s` compté depuis l'admission (EX-3.5, 8.9) : 0 quand l'entrée `point_produit` a `t = checkpoint_ts`. Les lignes `anchor_retry`, `anchor_fallback` et `anchor_response_rejected` d'une tentative portent son rang (`attempt`) et son `attempt_id` (EX-8.15). Le compactage de la file (EX-8.5, règle 5) n'est pas une action de trace : il ne change ni `expected` ni `queue_after`.");
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
    "refus-puis-preuve-de-vie": "EX-4.3 (countersign_idle), EX-5.12, EX-8.3, EX-8.8",
    "refus-puis-preuve-de-vie-redemarrage": "EX-4.3 (countersign_idle), EX-8.5, EX-8.12 (AN-33)",
    "file-perdue": "EX-8.12 (reconstruction, file_perdue), EX-4.1 (point_manquant depuis le checkpoint_ts du point relu)",
    "bascule-epoque": "EX-8.5 règle 6 (fichiers d'époque), EX-8.12",
    "bascule-epoque-fichier-perdu": "EX-8.5 règle 6, EX-8.12 (reconstruction)",
    "registre-indisponible-cloture": "EX-4.2 (repli de clôture), EX-8.4, EX-8.10, EX-9.4 (au retour du registre, l'ancre du point de clôture avant celle de la période ; complément du 2026-11-16 ; trace changée, EX-9.4 : « l'ancre de la période ne part qu'après le reçu de l'ancre du point de clôture de la même clé »)",
    "mi-periode-impair": "EX-6.1 (mi_periode, n_T impair)",
    "reponse-hors-profil": "EX-5.10, EX-5.12 (réponse hors profil, permanente)",
    "point-manquant": "EX-4.1, EX-4.3, 8.9 (point_manquant, AN-2)",
    "point-manquant-saut-horloge": "EX-4.1, 8.9 (point_manquant après un saut d'horloge : délai compté depuis le checkpoint_ts du dernier point admis ; révision 0.4), EX-4.3",
    "file-fenetre-32": "EX-8.5 règle 7 (fenêtre de 32 tentatives, attempts_total, réponse à une tentative sortie de la fenêtre), EX-8.9, EX-8.15 (révision 0.6)",
    "file-fenetre-32-redemarrage": "EX-8.5 règle 7, EX-8.12 (reprise au rang attempts_total + 1 ; révision 0.6)",
    "releve-pendant-reprise": "EX-8.8 (relève pendant l'attente de reprise, séries parallèles), EX-8.9 (AN-38 ; revue de l'étape 8)",
    "redemarrage-releve": "EX-8.8, EX-8.12 (minuterie de relève reposée au démarrage ; revue de l'étape 8)",
    "redemarrage-echeance-remplacee": "EX-4.4, EX-8.12 (EX-4.4 appliquée aux demandes de points relues ; revue de l'étape 8)",
    "file-lignes-illisibles": "EX-8.5 règle 3, EX-8.12 (ligne mal formée ou fragment ignorés et consignés, reprise quel que soit l'état de la file ; revue de l'étape 8)",
    "empreinte-squattee": "EX-4.7, EX-8.4, EX-8.10, EX-9.7 ; CT-4 EX-8.4, EX-8.6 (ancre de période refusée sur empreinte_squattee, sans nouvel essai ; jeton de clôture en attente_registre, période signalée registry_pending ; AN-36, AN-40 ; décision du porteur du 2026-11-16)",
    "empreinte-squattee-repli": "EX-4.2, EX-8.4 règle 2, EX-9.7 (repli de clôture après le refus empreinte_squattee de l'ancre de la période : le jeton du point de clôture date la tête ; AN-36, AN-40 ; complément du 2026-11-16)",
    "registre-saut-horloge": "EX-8.10 (au plus quatre rejeux par minuterie, par demande et par passe ; missed_deadlines sur la ligne anchor_retry du quatrième renvoi), EX-8.4 règle 2 (registry_pending ; complément du 2026-11-16)",
    "redemarrage-due-at-borne": "EX-4.13 (au démarrage, due_at d'une demande a_reprendre ramené à l'instant courant plus retry.max_ms ; complément du 2026-11-16), EX-8.12",
    "redemarrage-jeton-sans-acquisition": "EX-5.8 (demande de jeton obtenue sans enregistrement obtenue promu de même token_sha256 rouverte au démarrage, file_perdue ; complément du 2026-11-16), EX-8.12",
    "file-perdue-jeton-point-obtenu": "EX-8.12 (demande de jeton de point recréée obtenue depuis acquisitions.ndjson, sans requête ; complément du 2026-11-16), EX-4.3",
    "file-perdue-jeton-periode-obtenu": "EX-8.12 (demande de jeton de clôture recréée obtenue depuis acquisitions.ndjson, sans requête ; complément du 2026-11-16), EX-8.4 règle 2",
    "redemarrage-jeton-recree-couvrant": "EX-8.12, EX-4.4, EX-8.4 règle 1 (demande de jeton recréée obtenue appliquée comme à sa promotion : demande de point relue antérieure close remplacee ; complément du 2026-11-16)",
    "redemarrage-ancres-a-reprendre": "EX-8.10 (échec transitoire du registre : ancre a_reprendre), EX-8.11, EX-8.12 et EX-4.13 (ancre au registre et soumission OpenTimestamps a_reprendre gardent due_at au démarrage ; complément du 2026-11-16)",
    "repli-ancre-incluse-jeton-retenu": "EX-8.4 règle 2, EX-4.2, EX-8.7 (repli de clôture lu à la lettre : jeton_periode encore attente_registre, ancre incluse, jeton retenu par min_interval_ms ; complément du 2026-11-16)",
    "ots-reponses-insuffisantes": "EX-8.11, EX-6.2 point 4, EX-8.9 (soumission OpenTimestamps à moins de min_responses réponses valables, attestation Bitcoin comprise : reponses_insuffisantes, rejeter_reponse et anchor_response_rejected comme une réponse RFC 3161 en échec transitoire ; complément du 2026-11-16)",
    "redemarrage-ots-soumission-envoyee": "EX-8.12, EX-8.9, EX-8.11 (soumission OpenTimestamps envoyee au démarrage close redemarrage et rejouée aussitôt avec le même engagement ; la tentative redemarrage interrompt la série ; complément du 2026-11-16)",
    "ots-preuve-absente": "EX-8.11, EX-8.5 règle 2, 8.9 (réponse des calendriers sans preuve écrite jamais promue : preuve_absente à la soumission, en attente à la mise à niveau ; réponses qui ne s'appliquent pas : tentative_close, demande_close, demande_inconnue ; complément du 2026-11-16)",
    "redemarrage-ots-a-reprendre-en-cours": "EX-8.12, EX-8.16 (ligne a_reprendre d'une version antérieure portant une soumission en_cours, reprise comme une soumission envoyee ; détail « soumission a <n> calendriers » ; complément du 2026-11-16)",
    "reponses-hors-tentative": "EX-8.5 règles 1 et 2, EX-5.10 étape 2, EX-5.12, EX-8.10, 8.9, EX-8.16 (demande_inconnue, tentative_inconnue, tentative_close ; jeton absent, PKIFailureInfo hors liste ; borne d'une pièce ; événements du registre qui ne s'appliquent pas ; détails des tentatives closes ; complément du 2026-11-16)",
    "registre-renvois": "EX-8.10, EX-8.16, CT-4 EX-8.16 (renvoi des mêmes octets puis remplacement au même nonce ; reçu et échec sans transaction en vol ignorés ; due_at d'une ancre renvoyée et d'une ancre en attente du nonce ; complément du 2026-11-16)",
    "redemarrage-releve-deux-series": "EX-8.12, EX-8.8, EX-8.5 (une action programmer immediat par demande ; séries reprises dans l'ordre des tentatives closes par le démarrage ; erreur permanente d'une série pendant que l'autre est en vol écrite ; complément du 2026-11-16)",
    "minuteries-simultanees": "EX-8.16, EX-8.10, EX-8.4 règle 2 (deux minuteries de même échéance : ordre de la file, puis ordre d'armement ; complément du 2026-11-16)",
    "redemarrage-ordre-de-la-file": "EX-8.12 (ordre du démarrage : une seule passe sur la file, dans l'ordre de la file ; une ancre a_envoyer dont la clé a une ancre en vol attend le nonce à sa place ; complément du 2026-11-16), EX-9.4",
    "redemarrage-a-envoyer-cle-libre": "EX-8.12, EX-9.4, EX-8.5 règle 1 (arrêt entre une ligne obtenue et l'envoi suivant : ancres a_envoyer parties après la passe, celle du point de la période d'abord, celle de la période à son reçu ; complément du 2026-11-16 ; trace changée, EX-9.4 : « l'ancre de la période ne part qu'après le reçu de l'ancre du point de clôture de la même clé »)",
    "redemarrage-echeances-remplacees": "EX-8.12, EX-4.4 (échéances d'une demande remplacee relue gardées closes, aucune action echeance au démarrage ; complément du 2026-11-16)",
    "registre-inclusion-apres-attente": "EX-8.10, P-2 (délai d'inclusion compté depuis la création de l'ancre, attente du nonce comprise : inclusion_late au reçu ; complément du 2026-11-16)",
    "redemarrage-prestataires-epuises": "EX-8.12, EX-8.8, EX-4.5 (prestataires épuisés relus des tentatives echec_permanente de la file : après le redémarrage, l'erreur permanente de l'autre prestataire épuise la demande, alerte et reprise au pas retry.max_ms ; complément du 2026-11-16)",
    "registre-cle-par-journal": "EX-9.4 (une transaction en vol par clé de chaîne, c'est-à-dire par journal du sujet de l'ancre : l'ancre de la période d'un autre journal part aussitôt, sans attendre le nonce ; complément du 2026-11-16)",
    "minuteries-deux-journaux": "EX-8.16, EX-4.1, 8.9 (minuteries de période de deux journaux au même instant : échéances et cadences dans l'ordre où elles ont été armées, quel que soit le journal ; complément du 2026-11-16)",
    "jeton-tardif-avertissements": "EX-5.10 étapes 6 à 8, EX-5.11, EX-8.5 règle 2, EX-8.16 (précision hors de la plage d'un instant : verification_T-7 ; pièce sans borne ; troisième réponse tardive promue avec reponse_tardive et horloge_suspecte, détail et alertes ; complément du 2026-11-16)",
    "registre-refus-ancre-periode": "EX-8.10, 8.9, EX-4.5 (refus définitif de l'ancre d'une période : reprise au pas retry.max_ms sans gigue, alerte prestataires_epuises critique une fois ; complément du 2026-11-16)",
    "registre-ordre-des-points": "EX-9.4, EX-8.12, EX-10.7 (ordre des ancres d'une clé : par period_start, puis, dans une période, les points par checkpoint_ts avant la période, l'ordre de la file aux égalités ; ancres créées au même instant par une reconstruction ; complément du 2026-11-16)",
    "registre-periode-apres-point-de-cloture": "EX-9.4, EX-8.10, EX-10.7 (ancre du point de clôture en attente du nonce à la clôture : elle part avant l'ancre de la période, qui attend son reçu, même après un échec transitoire qui libère la clé ; complément du 2026-11-16)",
    "redemarrage-ots-abandon-origine": "EX-8.11, EX-8.12 (âge d'abandon d'une preuve OpenTimestamps en attente compté depuis created_at de la demande, au démarrage comme en marche : la soumission reprise au redémarrage ne le déplace pas ; complément du 2026-11-16)",
    "registre-periode-retient-la-cle": "EX-9.4, EX-9.5, EX-10.7 (une ancre de période sans reçu retient sa clé : ni l'ancre d'un point de la période suivante ni celle de cette période ne part avant elle, même quand la clé n'a aucune ancre en vol ; complément du 2026-11-16)",
    "redemarrage-ots-abandon-soumission-tardive": "EX-8.11, EX-8.12 (soumission OpenTimestamps aboutie au-delà de give_up_after_s après created_at : ots_give_up dès la preuve en attente, première mise à niveau à first_after_s, puis une fois par jour ; complément du 2026-11-16)",
    "registre-refus-ancre-periode-redemarrage": "EX-8.10, EX-8.12 (alerte du refus définitif de l'ancre d'une période levée une fois par ancre depuis le dernier démarrage : de nouveau au premier refus après un redémarrage ; complément du 2026-11-16)",
    "registre-points-en-reprise": "EX-9.5, EX-9.4, EX-10.7 (ancre d'un point en reprise quand le point suivant de sa période est admis : remplacée si aucune de ses tentatives n'a pu être admise par un nœud, noeud_injoignable ; attendue sinon, recu_absent : le point suivant ne part qu'à son reçu ; complément du 2026-11-16)",
  };
  for (const { trace: t } of tr) L.push(`| \`${t.id}.json\` | ${t.inputs.length} | ${t.expected.length} | ${t.queue_before.length} | ${t.queue_after.length} | ${regles[t.id]} |`);
  L.push("");
  for (const { trace: t } of tr) L.push(`- \`${t.id}\` : ${t.description}`);
  L.push("");
  L.push("## reprise/ (EX-8.12, AN-33)");
  L.push("");
  L.push("Files NDJSON (une demande par ligne, JCS intégral) avant et après le `demarrage` des traces qui partent d'une file non vide : une seule demande par `id`, la dernière ligne fait foi.");
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
  L.push("## configuration/ (EX-4.9, AN-1 ; complément du 2026-11-16)");
  L.push("");
  L.push("`configuration.json` (`#/$defs/fichier_vecteurs`, `#/$defs/cas_configuration`) : un document `ancrage-v0` tiré de l'exemple d'EX-4.8, un profil et la valeur `checkpoint_interval_s` de l'enregistreur ; attendu : `valide` et la liste triée des règles violées (`schema`, puis `1` à `9`), que `verifierConfiguration` de la référence et `validerConfiguration` du composant d'ancrage rendent à l'identique.");
  L.push("");
  L.push("| Cas | Profil | Valide | Règles violées |");
  L.push("|---|---|---|---|");
  for (const x of conf.cases) L.push(`| \`${x.id}\` | ${x.input.profil} | ${x.expected.valide ? "oui" : "non"} | ${x.expected.regles.length ? x.expected.regles.join(", ") : "—"} |`);
  L.push("");
  for (const x of conf.cases) L.push(`- \`${x.id}\` : ${x.description}`);
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
  const configurationCas = familleConfiguration();
  const liste = traces(ex);
  validerTraces(liste, schema);
  confronterReference(liste[0].trace);
  for (const f of [requetes.fichier, cout, completude, configurationCas]) {
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
  fs.mkdirSync(path.join(racine, "configuration"));
  fs.writeFileSync(path.join(racine, "configuration", "configuration.json"), texteJSON(configurationCas));
  fs.writeFileSync(path.join(racine, "INDEX.md"), index({ constantes: c, requetes, reponses, ots, traces: liste, cout, reprise, configuration: configurationCas }));
  return { constantes: c, requetes, reponses, ots, traces: liste, cout, reprise, configuration: configurationCas };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) {
  const i = process.argv.indexOf("--sortie");
  if (i !== -1 && (!process.argv[i + 1] || process.argv[i + 1].startsWith("--"))) {
    process.stderr.write("generer-ct5 : --sortie attend un répertoire\n");
    process.exit(2);
  }
  const racine = i !== -1 ? path.resolve(process.argv[i + 1]) : REPERTOIRE_CT5;
  const r = genererCt5({ racine });
  process.stdout.write(`ct-5 : ${r.requetes.fichier.cases.length} requêtes, ${r.reponses.fichier.cases.length} réponses, ${r.ots.fichier.cases.length} preuves, ${r.traces.length} traces, ${r.cout.cases.length} cas de coût sous ${racine}\n`);
}
