// Famille supervision/ des vecteurs de CT-8 (§10.3 à §10.7, EX-10.11 SV-5 et
// SV-6 ; annexe A.6, A.9) : spec/vecteurs/ct-8/supervision/.
//
//   journaux/<source>/…        au moins une ligne par ligne de la table de
//                              10.3 (noms du code, écarts E-C1 et E-C2 de
//                              scripts/lib/supervision.mjs), des lignes
//                              illisibles, une fin de fichier sans LF (non
//                              lue), des procès-verbaux valides et un refusé
//                              par PV-1 ;
//   attendu.prom               sortie de l'extracteur rejoué sur journaux/ (SV-5) ;
//   configuration-modifiee.json
//                              configuration du modèle de production avec
//                              pending_max_ms, warn_skew_ms,
//                              lock_audit_interval_days, min_free_bytes et
//                              storage.root changés ;
//   ancrage-modifie.json       extrait d'un document ancrage-v0 :
//                              queue.anchor_pending_alert_s,
//                              registry.inclusion_alert_s,
//                              opentimestamps.upgrade.give_up_after_s ;
//   regles-attendues.yml       regles.mjs --configuration configuration-modifiee.json
//                              --ancrage ancrage-modifie.json (SV-6).
//
// Dates fixes, aucune horloge lue : deux exécutions donnent les mêmes octets
// (EX-A.1). Les procès-verbaux sont lus dans la famille proces-verbaux/ de
// la même génération.

import fs from "node:fs";
import path from "node:path";
import * as D from "../../lib/deploiement.mjs";
import * as E from "../../lib/exploitation.mjs";
import * as S from "../../lib/supervision.mjs";

const RACINE = D.RACINE;
const texteJSON = D.texteJSON;
const ORG = "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab";
const JOURNAL = "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164";

function repertoireNeuf(rep) {
  fs.rmSync(rep, { recursive: true, force: true });
  fs.mkdirSync(rep, { recursive: true });
}
function ecrire(rep, rel, contenu) {
  const p = path.join(rep, ...rel.split("/"));
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, contenu);
}

/** Ligne du journal d'exploitation (CT-2 EX-9.5), clés dans l'ordre du code. */
function ligneExploitation(ts, level, component, event, data, seq = null) {
  return JSON.stringify({ ts, level, component, event, org_id: ORG, journal_id: JOURNAL, seq, host: null, request_id: null, data });
}

/** Lignes du journal d'exploitation : [ts, niveau, composant, event, data]. */
const EXPLOITATION = [
  ["2026-11-05T08:00:00.000Z", "info", "worm", "worm_lock_config_check", { verdict: "conforme", mode: "COMPLIANCE", days: 3653, years: null }],
  ["2026-11-05T08:00:01.000Z", "error", "worm", "worm_lock_config_check", { verdict: "non_conforme", mode: null, days: null, years: null, statut: 403 }],
  ["2026-11-05T08:10:00.000Z", "info", "worm", "worm_lock_check", { key: "noortrace/seg-1", version_id: "v1", verdict: "conforme", reasons: [], notes: [], when: "copie" }],
  ["2026-11-05T08:10:01.000Z", "error", "worm", "worm_lock_check", { key: "noortrace/seg-2", version_id: "v1", verdict: "non_conforme", reasons: ["echeance_courte"], notes: [], when: "copie" }],
  ["2026-11-05T08:10:02.000Z", "error", "worm", "worm_lock_check", { key: "noortrace/seg-3", version_id: "v1", verdict: "non_conforme", reasons: ["gel_absent"], notes: [], when: "registre_gels", gel_id: "gel-0001" }],
  ["2026-11-05T08:20:00.000Z", "info", "worm", "worm_legal_hold_observed", { gel_id: "gel-0001", n: 1, kind: "pose", record_sha256: "0x" + "11".repeat(32), garde: "respectee" }],
  ["2026-11-05T08:20:01.000Z", "error", "worm", "worm_legal_hold_observed", { gel_id: "gel-0001", n: 4, kind: "levee", record_sha256: "0x" + "22".repeat(32), garde: "meme_identite" }],
  ["2026-11-05T08:20:02.000Z", "info", "worm", "worm_legal_hold_observed", { gel_id: "gel-0002", n: 4, kind: "levee", record_sha256: "0x" + "33".repeat(32), garde: "respectee" }],
  ["2026-11-05T08:30:00.000Z", "info", "ancrage", "anchoring_queue_rebuilt", { request_id: null, at: "2026-11-05T08:30:00.000Z", recreated: 2, periods: 1, checkpoints: 1 }],
  ["2026-11-05T08:30:01.000Z", "info", "ancrage", "anchoring_queue_rebuilt", { request_id: null, at: "2026-11-05T08:30:01.000Z", recreated: 0, periods: 0, checkpoints: 0 }],
  ["2026-11-05T08:31:00.000Z", "error", "ancrage", "anchor_refused", { request_id: "ancre_registre_point:0x01", at: "2026-11-05T08:31:00.000Z", error_code: "empreinte_squattee" }],
  ["2026-11-05T08:31:01.000Z", "error", "ancrage", "anchor_refused", { request_id: "jeton_point:0x02", at: "2026-11-05T08:31:01.000Z", error_code: "refus_politique", provider: "tsa-principal" }],
  ["2026-11-05T08:32:00.000Z", "warning", "ancrage", "checkpoint_anchor_late", { request_id: "jeton_point:0x03", at: "2026-11-05T08:32:00.000Z", tree_size: 12, deadlines: [3], replaced_by: "jeton_point:0x04", window_s: 900 }],
  ["2026-11-05T08:32:00.000Z", "warning", "ancrage", "alerte_checkpoint_anchor_late", { request_id: "jeton_point:0x03", at: "2026-11-05T08:32:00.000Z", severity: "majeure" }],
  ["2026-11-05T08:32:01.000Z", "warning", "ancrage", "alerte_checkpoint_anchor_late", { request_id: "jeton_point:0x05", at: "2026-11-05T08:32:01.000Z", severity: "mineure" }],
  ["2026-11-05T08:33:00.000Z", "warning", "ancrage", "alerte_jeton_anterieur_au_point", { request_id: "jeton_point:0x06", at: "2026-11-05T08:33:00.000Z", severity: "majeure" }],
  ["2026-11-05T08:33:01.000Z", "warning", "ancrage", "alerte_contresignature_tardive", { request_id: "jeton_point:0x07", at: "2026-11-05T08:33:01.000Z", severity: "mineure" }],
  ["2026-11-05T08:34:00.000Z", "warning", "ancrage", "point_manquant", { request_id: null, at: "2026-11-05T08:34:00.000Z", last_checkpoint_ts: "2026-11-05T08:00:00.000Z", gap_s: 2040 }],
  ["2026-11-05T08:35:00.000Z", "error", "ancrage", "anchor_queue_full", { request_id: null, at: "2026-11-05T08:35:00.000Z", tree_size: 40, active: 4096, max_pending: 4096 }],
  ["2026-11-05T08:36:00.000Z", "warning", "ancrage", "registry_pending", { request_id: "ancre_registre_periode:1", at: "2026-11-05T08:36:00.000Z", age_s: 3700 }],
  ["2026-11-05T08:37:00.000Z", "warning", "ancrage", "ordre_ancres_non_respecte", { request_id: "ancre_registre_point:0x08", at: "2026-11-05T08:37:00.000Z", tree_size: 41, squat_wait_s: 600 }],
  ["2026-11-05T08:40:00.000Z", "error", "noyau", "dossier_export_refused", { raison: "lecture_impossible", selection: "seq", seq: 3, ticket: null, destination: null, exports_dir: "/var/lib/noortrace-exports", period_start: null, decision: null, member: null, at: null, detail: "segment" }],
  ["2026-11-05T08:40:01.000Z", "error", "noyau", "dossier_export_refused", { raison: "exports_indisponible", selection: "seq", seq: 3, ticket: null, destination: null, exports_dir: "/var/lib/noortrace-exports", period_start: null, decision: null, member: null, at: null, detail: null }],
  ["2026-11-05T08:41:00.000Z", "warning", "politique", "approval_service_unavailable", { message: "charger", code: "politique_invalide" }],
  ["2026-11-05T08:41:01.000Z", "warning", "politique", "approval_service_unavailable", { code: "indisponible" }],
  ["2026-11-05T08:42:00.000Z", "error", "stockage", "journal_fork", { fichier: "seg-0000000000000001-00000000000000000001.ndjson", octets_avant: 10086, octets: 10200 }],
  ["2026-11-05T08:43:00.000Z", "error", "noyau", "relay_mac_key_mismatch", {}],
  ["2026-11-05T08:44:00.000Z", "error", "stockage", "disk_low", { free_bytes: 900000000, min_free_bytes: 1073741824 }],
  ["2026-11-05T08:45:00.000Z", "error", "noyau", "pending_pieces_lost", { events: 1, seqs: [9], pieces: 1 }],
  ["2026-11-05T08:46:00.000Z", "warning", "cloture", "anchor_pending", { period_start: 1793865600, age_s: 7300 }],
];

/** Lignes plus anciennes, dans le fichier tourné exploitation.ndjson.1. */
const EXPLOITATION_TOURNE = [
  ["2026-11-04T23:00:00.000Z", "info", "noyau", "startup", { version: "0.1.0" }],
  ["2026-11-04T23:00:01.000Z", "error", "noyau", "dossier_export_refused", { raison: "lecture_impossible", selection: "seq", seq: 1, ticket: null, destination: null, exports_dir: "/var/lib/noortrace-exports", period_start: null, decision: null, member: null, at: null, detail: "manifeste" }],
];

function acquisition(n, champs) {
  return JSON.stringify({
    attempt_id: `0x${String(n).padStart(2, "0")}${"ab".repeat(15)}`,
    attempt: 1,
    org_id: ORG,
    journal_id: JOURNAL,
    period_start: 1793865600,
    object: "jeton_periode",
    object_name: `periode-1793865600-${n}`,
    provider_id: "tsa-principal",
    provider_role: "principal",
    sent_at: `2026-11-05T09:0${n}:00.000Z`,
    received_at: `2026-11-05T09:0${n}:00.250Z`,
    outcome: "obtenue",
    error_code: null,
    freshness: "nonce",
    warnings: [],
    promoted: true,
    revoked: false,
    ...champs,
  });
}

function sortieRegistre(command, champs) {
  return texteJSON({ version: 0, command, result: "reussi", exit_code: 0, checks: [], error: null, outputs: {}, ...champs });
}

function consultation(n, ts, action, role) {
  return JSON.stringify({ action, collected_at: ts.replace(/\.000Z$/, ".500Z"), motif: "AUDIT-2026-07", n, object: { journal_id: JOURNAL, org_id: ORG, path: "dossier seq 3", version_id: null }, outcome: "reussi", prev_sha256: null, principal: `principal-${n}`, role, source: "journal-acces-support", ts, version: 0 });
}

/** Fichiers de journaux/ : chemin relatif → contenu. */
export function journauxSupervision(repProcesVerbaux) {
  const f = new Map();
  const ndjson = (lignes) => lignes.join("\n") + "\n";
  f.set("exploitation/exploitation.ndjson", ndjson([
    ...EXPLOITATION.map(([ts, l, c, e, d]) => ligneExploitation(ts, l, c, e, d)),
    '{"ts":"2026-11-05T08:50:00.000Z","level":"info","event":"startup","event":"shutdown","data":{}}',
    '{"ts":"2026-11-05T08:50:01.000Z","level":"info","event":',
    ligneExploitation("2026-11-05T08:51:00.000Z", "info", "noyau", "Évènement hors motif", {}),
    "[1,2,3]",
  ]) + ligneExploitation("2026-11-05T08:59:00.000Z", "error", "stockage", "journal_fork", {}));
  f.set("exploitation/exploitation.ndjson.1", ndjson(EXPLOITATION_TOURNE.map(([ts, l, c, e, d]) => ligneExploitation(ts, l, c, e, d))));
  f.set("gel/gel.ndjson", ndjson([
    ligneExploitation("2026-11-05T07:00:00.000Z", "info", "worm", "worm_legal_hold_set", { gel_id: "gel-0001", n: 2, kind: "pose_resultat", record_sha256: "0x" + "44".repeat(32) }),
    ligneExploitation("2026-11-05T07:30:00.000Z", "info", "worm", "worm_legal_hold_set", { gel_id: "gel-0002", n: 2, kind: "pose_resultat", record_sha256: "0x" + "55".repeat(32) }),
  ]));
  f.set("acquisitions/1793865600/acquisitions.ndjson", ndjson([
    acquisition(1, {}),
    acquisition(2, { warnings: ["horloge_suspecte"] }),
    acquisition(3, { freshness: "reponse_tardive", warnings: ["reponse_tardive"], promoted: true }),
    acquisition(4, { revoked: true }),
    acquisition(5, { outcome: "echec_transitoire", error_code: "reseau", freshness: null, promoted: false }),
    '{"attempt_id":"0x06","outcome":"obtenue"',
  ]));
  f.set("registre/2026-11-05T09-10-ancrer.json", sortieRegistre("ancrer", { result: "refuse", exit_code: 1, error: { code: "examen_requis", check: "OP-11", message: "examen requis" } }));
  f.set("registre/2026-11-05T09-20-capturer.json", sortieRegistre("capturer", { outputs: { retention: { retention_heights: 300000, margin_heights: 1200, alert: true } } }));
  f.set("registre/2026-11-05T09-30-inscrire-cle.json", sortieRegistre("inscrire-cle", { outputs: { retention: { retention_heights: 300000, margin_heights: 299988, alert: false } } }));
  f.set("registre/2026-11-05T09-40-illisible.json", '{"version":0,"command":"etat"\n');
  f.set("consultations/consultations-2026-11-05.ndjson", ndjson([
    consultation(1, "2026-11-05T10:01:00.000Z", "export", "exportateur"),
    consultation(2, "2026-11-05T10:02:00.000Z", "lecture", "lecteur"),
    consultation(3, "2026-11-05T10:03:00.000Z", "lecture", "inconnu"),
  ]));
  f.set("approbation/journal-service.ndjson", ndjson([
    JSON.stringify({ ts: "2026-11-05T11:00:00.000Z", type: "vote_inscrit", ticket: "apr-3001" }),
    JSON.stringify({ ts: "2026-11-05T11:01:00.000Z", type: "notification_echec", id: "n-1", kind: "ouverture", attempt: 1, status: null, cause: "reseau" }),
    JSON.stringify({ ts: "2026-11-05T11:02:00.000Z", type: "notification_echec", id: "n-1", kind: "ouverture", attempt: 2, status: 503, cause: "statut" }),
    JSON.stringify({ ts: "2026-11-05T11:03:00.000Z", type: "notification_abandonnee", id: "n-2", kind: "ouverture", attempts: 1, cause: "file_pleine" }),
    JSON.stringify({ ts: "2026-11-05T11:04:00.000Z", type: "notification_sans_destinataire", kind: "ouverture", ticket: "apr-3002" }),
  ]));
  for (const [nom, src] of [["sauvegarde.json", "valides/sauvegarde.json"], ["passage-mode.json", "valides/passage-mode.json"], ["pv-1-refuse.json", "invalides/pv-1-cle-en-double.json"]]) {
    f.set(`proces-verbaux/${nom}`, fs.readFileSync(path.join(repProcesVerbaux, ...src.split("/"))));
  }
  return new Map([...f.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

/** Exposition attendue : extracteur de la bibliothèque, PV-1 par verifierProcesVerbal. */
export function attenduSupervision(fichiers) {
  const sources = {};
  for (const [rel, contenu] of fichiers) {
    const s = rel.split("/")[0];
    if (s === "proces-verbaux") {
      const texte = Buffer.from(contenu).toString("utf8");
      let document = null;
      try {
        document = S.analyserJSONStrict(texte);
      } catch {
        continue;
      }
      const valide = E.verifierProcesVerbal(texte, {}).checks.find((c) => c.id === "PV-1").status === "reussi";
      (sources.proces_verbaux ??= []).push({ document, valide });
      continue;
    }
    (sources[s] ??= []).push(contenu);
  }
  return S.extraireJournaux(sources);
}

/**
 * Configuration modifiée (SV-6) : modèle de production, cinq réglages changés.
 * Les serveurs d'outils du modèle autres que `fichiers` prennent un nom neutre
 * (`outils-1`, …), avec leurs outils, leur secret et leur adresse : les règles
 * d'alerte n'en dépendent pas, et le vecteur ne recopie aucun nom de serveur
 * de l'exemple.
 */
export function configurationModifiee() {
  const brut = fs.readFileSync(path.join(RACINE, "deploiement", "config", "modele-production", "configuration.json"), "utf8");
  let texte = brut;
  Object.keys(JSON.parse(brut).policy.servers).filter((a) => a !== "fichiers").forEach((a, i) => {
    const n = `outils-${i + 1}`;
    texte = texte.split(`"${a}"`).join(`"${n}"`).split(`"${a}__`).join(`"${n}__`).split(`identifiant-outil-${a}"`).join(`identifiant-outil-${n}"`).split(`//${a}-`).join(`//${n}-`);
    texte = texte.split(`"${a.toUpperCase()}"`).join(`"Systeme-${i + 1}"`);
  });
  const c = JSON.parse(texte);
  for (const a of Object.keys(JSON.parse(brut).policy.servers).filter((x) => x !== "fichiers")) if (new RegExp(`\\b${a}\\b`, "i").test(texte)) throw new Error("configuration-modifiee : nom de serveur resté");
  c.policy.failure.pending_max_ms = 120000;
  c.clock.warn_skew_ms = 500;
  c.storage.seal.worm.lock_audit_interval_days = 7;
  c.storage.min_free_bytes = 4294967296;
  c.storage.root = "/srv/noortrace";
  return c;
}

/** Extrait d'un document ancrage-v0 aux trois réglages lus par regles.mjs changés. */
export function ancrageModifie() {
  return { queue: { anchor_pending_alert_s: 3600 }, registry: { inclusion_alert_s: 120 }, opentimestamps: { upgrade: { give_up_after_s: 604800 } } };
}

export function genererSupervision(rep) {
  repertoireNeuf(rep);
  const fichiers = journauxSupervision(path.join(rep, "..", "proces-verbaux"));
  for (const [rel, contenu] of fichiers) ecrire(rep, `journaux/${rel}`, contenu);
  const attendu = attenduSupervision(fichiers);
  ecrire(rep, "attendu.prom", attendu);
  const configuration = configurationModifiee();
  const ancrage = ancrageModifie();
  ecrire(rep, "configuration-modifiee.json", texteJSON(configuration));
  ecrire(rep, "ancrage-modifie.json", texteJSON(ancrage));
  const regles = S.genererRegles({ configuration, ancrage });
  ecrire(rep, "regles-attendues.yml", regles);
  return { fichiers: [...fichiers.keys()], series: attendu.split("\n").filter((l) => l && !l.startsWith("#")).length };
}

export function sectionSupervision({ fichiers, series }) {
  const L = ["## supervision", ""];
  L.push("Supervision de CT-8 §10 : extracteur des journaux (10.3, SV-5) et règles");
  L.push("régénérées (EX-10.6, SV-6). Les noms de lignes et de membres sont ceux du");
  L.push("code des paquets (écarts E-C1 à E-C5 de `scripts/lib/supervision.mjs`).");
  L.push("");
  L.push("```bash");
  L.push("node scripts/deploiement/extraire-journaux.mjs --repertoire spec/vecteurs/ct-8/supervision/journaux   # = attendu.prom");
  L.push("node scripts/deploiement/regles.mjs   # = deploiement/observabilite/regles-noortrace.yml");
  L.push("node scripts/deploiement/regles.mjs --configuration spec/vecteurs/ct-8/supervision/configuration-modifiee.json \\");
  L.push("  --ancrage spec/vecteurs/ct-8/supervision/ancrage-modifie.json   # = regles-attendues.yml");
  L.push("```");
  L.push("");
  L.push("| Fichier | Contenu | Résultat attendu |");
  L.push("|---|---|---|");
  L.push(`| \`journaux/\` | ${fichiers.length} fichiers : ${fichiers.map((f) => `\`${f}\``).join(", ")} | \`attendu.prom\`, ${series} séries |`);
  L.push("| `configuration-modifiee.json` | modèle de production : `pending_max_ms` 120 000, `warn_skew_ms` 500, `lock_audit_interval_days` 7, `min_free_bytes` 4 Gio, `storage.root` `/srv/noortrace` | `regles-attendues.yml` |");
  L.push("| `ancrage-modifie.json` | `anchor_pending_alert_s` 3 600, `inclusion_alert_s` 120, `give_up_after_s` 604 800 | `regles-attendues.yml` |");
  return L.join("\n");
}
