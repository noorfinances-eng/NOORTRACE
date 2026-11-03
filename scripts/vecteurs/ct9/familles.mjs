// Familles mesures/, consignations/, acceptation-*/ et extraits/ des vecteurs
// de CT-9 (spec/CT-9-plan-de-tests.md, annexe A.7, A.8, A.9 ; EX-A.14 à
// EX-A.16 ; sections 11.3, 12.1, 12.2, 14, 15). Chaque fonction rend des
// objets ou des textes ; le générateur (generer-ct9.mjs) les écrit. Rien
// n'est lu hors du dépôt ; les seules lectures sont le segment de la
// démonstration de CT-2 (tailles de ligne recalculées, EX-A.14), le texte de
// CT-9 (section 14 et table des niveaux pour la grille de la porte 2,
// EX-15.2) et les spécifications dont les extraits sont tirés (EX-12.2).
//
// Les valeurs fixes (machine de rédaction, instants, commit éprouvé) sont
// celles imprimées par CT-9 §11.3 ; un rapport de campagne réel est écrit par
// l'ingénieur de la campagne, jamais ici (EX-11.11).

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

/** Commit éprouvé de la version 0.1 (CT-9 §11.3, rapport imprimé). */
export const COMMIT = "3a8e9619205e3928610990479121ffa4c0ace1d5";
export const DATE = "2026-11-01";

const sha256 = (o) => crypto.createHash("sha256").update(o).digest("hex");
const arrondi = (x) => Math.round(x * 100) / 100;

// ---------------------------------------------------------------------------
// Famille mesures/ (EX-11.13, EX-A.14)
// ---------------------------------------------------------------------------

/** Machine de rédaction de la version 0.1 (CT-9 §11.3), hors système de
 * référence. */
const SYSTEME_REDACTION = Object.freeze({
  reference: false, cpu: "Intel(R) Xeon(R) Processor @ 2.80GHz", cores: 4, memory_bytes: 16872808448,
  disk: { type: "virtuel", fsync: null }, os: "Ubuntu 24.04.5 LTS", kernel: "6.18.44-fc-v185",
  node: "v22.22.0", go: "go1.24.7", python: "3.13.16", cpu_scaling: "inconnu", aslr: "inconnu", load_avg_1m: null, virtualized: true,
});

/**
 * Délais, en secondes, entre chaque événement de `ct-1/journal-valide/
 * evenements.json` et le premier point de `ct-1/points-de-controle/
 * periode-*.json` qui l'engage (`last_seq ≥ seq`, `checkpoint_ts ≥ ts`), dans
 * l'ordre des événements (TM-10, ligne `p1_cadence_vecteurs`).
 */
export function delaisPoints(racine) {
  const base = path.join(racine, "spec", "vecteurs", "ct-1");
  const evenements = JSON.parse(fs.readFileSync(path.join(base, "journal-valide", "evenements.json"), "utf8"));
  const rep = path.join(base, "points-de-controle");
  const points = fs.readdirSync(rep).filter((f) => /^periode-[0-9]+\.json$/.test(f)).sort().flatMap((f) => JSON.parse(fs.readFileSync(path.join(rep, f), "utf8")));
  const delais = evenements.map((e) => {
    const t = Date.parse(e.ts);
    const candidats = points.filter((p) => p.last_seq !== null && p.last_seq >= e.seq && Date.parse(p.checkpoint_ts) >= t).map((p) => Date.parse(p.checkpoint_ts));
    if (!candidats.length) throw new Error(`TM-10 : aucun point n'engage l'événement seq ${e.seq}`);
    return Math.round((Math.min(...candidats) - t)) / 1000;
  });
  return { delais, max: Math.max(...delais) };
}

/** Ligne de résultat vide (EX-11.11 : une valeur absente est null, jamais
 * omise). */
const ligneVide = (name, test_id, unit, target) => ({
  name, test_id, unit, n: null, connections: null, samples: null, samples_sha256: null,
  value: null, p50: null, p95: null, p99: null, min: null, max: null, mean: null, text_value: null,
  target, met: null, conditions: [], excluded_reason: null,
});

/**
 * Rapports de mesure de la version 0.1 et cas de mesures/cas/ : le rapport
 * vide (chaque ligne porte sa cible et null partout ailleurs) et le rapport
 * sur les vecteurs (tailles de ligne du segment de la démonstration de CT-2
 * recalculées à la génération, ligne de l'annexe A de 2 465 octets, constat
 * de cadence). Rend { rapports: { nom: objet }, cas: { nom: objet }, casJson }.
 */
export function construireMesures(racine) {
  const cheminSegment = "spec/vecteurs/ct-2/evenements/journal-demo/segment.ndjson";
  const segment = fs.readFileSync(path.join(racine, cheminSegment));
  const lignes = segment.toString("utf8").split("\n").filter((l) => l.length > 0).map((l) => Buffer.byteLength(l, "utf8") + 1);
  const somme = lignes.reduce((a, b) => a + b, 0);
  const cadence = delaisPoints(racine);
  const rapportVide = {
    version: 0, kind: "rapport-mesure", date: DATE, measured_at: `${DATE}T00:00:00Z`, commit: COMMIT, spec_version: "0.1",
    system: { ...SYSTEME_REDACTION, reference: true, disk: { type: "nvme", fsync: true }, cpu: "a nommer a la porte 2", cpu_scaling: "inactif", aslr: "actif" },
    method: { warmup: 2000, repetitions: 20000, percentile_method: "plus_proche_rang", clock: "monotone", pair_with_without: false, samples_published: false },
    configuration_sha256: null, counts_for_targets: true,
    results: [
      ligneVide("latence_appel_relaye", "TM-1", "ms", { p50: 5, p99: 50 }),
      ligneVide("latence_premier_octet_sse", "TM-2", "ms", 10),
      ligneVide("debit", "TM-3", "evenements_par_s", 500),
      ligneVide("latence_echange_modele", "TM-4", "ms", { p50: 5, p99: 50 }),
      ligneVide("reprise", "TM-8", "ms", 2000),
    ],
    notes: "Rapport vide de la version 0.1 : aucune mesure de la porte 2 n'existe ; les lignes portent leur cible et `null` partout ailleurs. Le membre `system.cpu` est à remplacer par le modèle exact de la machine de référence.",
  };
  const rapportVecteurs = {
    version: 0, kind: "rapport-mesure", date: DATE, measured_at: `${DATE}T18:40:00Z`, commit: COMMIT, spec_version: "0.1",
    system: { ...SYSTEME_REDACTION },
    method: { warmup: 0, repetitions: 1, percentile_method: "plus_proche_rang", clock: "sans_objet", pair_with_without: false, samples_published: true },
    configuration_sha256: null, counts_for_targets: false,
    results: [
      { ...ligneVide("octets_par_evenement", "TM-6", "octets", null), n: lignes.length, samples: lignes,
        min: Math.min(...lignes), max: Math.max(...lignes), mean: arrondi(somme / lignes.length),
        conditions: [`${cheminSegment}, saut de ligne compris`, `SHA-256 du segment : ${sha256(segment)}`],
        excluded_reason: "vecteurs_seulement" },
      { ...ligneVide("octets_ligne_annexe_a", "TM-6", "octets", null), n: 1, samples: [2465], value: 2465,
        conditions: ["ligne de segment de seq 4 de l'annexe A de CT-2, rescellée par test/enregistreur.test.js"], excluded_reason: "vecteurs_seulement" },
      { ...ligneVide("p1_cadence_vecteurs", "TM-10", "s", 61), n: cadence.delais.length, samples: cadence.delais, min: Math.min(...cadence.delais), max: Math.max(...cadence.delais),
        text_value: "aucun écart de cadence sur la série publiée ; 3 540 s sur la série creuse",
        conditions: ["spec/vecteurs/ct-1/points-de-controle/periode-*.json et journal-valide/evenements.json, c_K = 60 s : délai en s de ts(i) au checkpoint_ts du premier point dont last_seq ≥ i et checkpoint_ts ≥ ts(i), recalculé à la génération", "constaterCadence (AN-2)"], excluded_reason: "vecteurs_seulement" },
    ],
    notes: "Mesures sur les vecteurs publiés, pas sur l'enregistreur : le rapport ne compte pour aucune cible (`counts_for_targets` faux, `excluded_reason` `vecteurs_seulement`). La machine n'est pas le système de référence.",
  };
  const cas = {
    "valide-vide": rapportVide,
    "valide-vecteurs": rapportVecteurs,
    "invalide-met-sans-valeur": { ...rapportVide, results: [{ ...ligneVide("latence_appel_relaye", "TM-1", "ms", { p50: 5, p99: 50 }), met: true }] },
    "invalide-compte-hors-reference": { ...rapportVide, system: { ...rapportVide.system, reference: false }, counts_for_targets: true },
    "invalide-fsync-desactive-compte": { ...rapportVide, system: { ...rapportVide.system, disk: { type: "nvme", fsync: false } }, counts_for_targets: true },
    "invalide-disque-memoire-compte": { ...rapportVide, system: { ...rapportVide.system, disk: { type: "memoire", fsync: true } }, counts_for_targets: true },
    "invalide-met-sans-compter": { ...rapportVecteurs, results: [{ ...rapportVecteurs.results[1], met: true, excluded_reason: null }] },
    "invalide-unite-inconnue": { ...rapportVide, results: [{ ...rapportVide.results[0], unit: "secondes" }] },
    "invalide-percentile-autre-methode": { ...rapportVide, method: { ...rapportVide.method, percentile_method: "interpolation" } },
    "invalide-machine-incomplete": { ...rapportVide, system: (({ kernel, ...s }) => s)(rapportVide.system) },
    "invalide-test-id-autre-famille": { ...rapportVide, results: [{ ...rapportVide.results[0], test_id: "TU-1" }] },
  };
  const casJson = {
    version: 0, family: "ct-9/mesures/cas",
    description: "Cas valides et invalides du rapport de mesure (plan-de-tests-v0, #/$defs/rapport_mesure) ; `expected` est le verdict d'ajv (`valid` ou `invalid`) et `reason` ce que le cas éprouve (CT-9 EX-11.11, EX-A.14).",
    cases: Object.keys(cas).map((n) => ({ file: `${n}.json`, def: "rapport_mesure", expected: n.startsWith("valide") ? "valid" : "invalid", reason: RAISONS_MESURES[n] })),
  };
  return { rapports: { [`rapport-${DATE}-vide.json`]: rapportVide, [`rapport-${DATE}-vecteurs.json`]: rapportVecteurs }, cas, casJson, segment: { lignes, somme, moyenne: arrondi(somme / lignes.length) } };
}

const RAISONS_MESURES = Object.freeze({
  "valide-vide": "Rapport vide de la version 0.1 : cibles présentes, null partout ailleurs, `counts_for_targets` vrai sur le système de référence.",
  "valide-vecteurs": "Relevés sur les vecteurs publiés : hors système de référence, `counts_for_targets` faux, chaque ligne exclue par `vecteurs_seulement`.",
  "invalide-met-sans-valeur": "`met` booléen sans aucune valeur (`value`, `p50`, `p99`, `max`, `text_value`) : refusé.",
  "invalide-compte-hors-reference": "`system.reference` faux avec `counts_for_targets` vrai : une mesure hors du système de référence ne compte pas pour les cibles.",
  "invalide-fsync-desactive-compte": "`disk.fsync` faux avec `counts_for_targets` vrai : refusé (CT-2 EX-16.3).",
  "invalide-disque-memoire-compte": "`disk.type` `memoire` avec `counts_for_targets` vrai : refusé.",
  "invalide-met-sans-compter": "Rapport qui ne compte pas pour les cibles avec une ligne `met` booléenne et sans `excluded_reason` : refusé.",
  "invalide-unite-inconnue": "Unité hors de l'énumération (`secondes` au lieu de `s`) : aucune conversion dans un rapport.",
  "invalide-percentile-autre-methode": "`percentile_method` autre que `plus_proche_rang` : refusé (EX-11.3).",
  "invalide-machine-incomplete": "Membre `kernel` absent de `system` : la machine est décrite en entier ou le rapport est refusé.",
  "invalide-test-id-autre-famille": "`test_id` d'une autre famille (TU-1) : une ligne de mesure se rattache à un TM-.",
});

// ---------------------------------------------------------------------------
// Famille consignations/ (EX-12.4, EX-A.15)
// ---------------------------------------------------------------------------

/** Gabarit de consignation (TR-10) et six cas ; rend { gabarit, cas,
 * casJson }. */
export function construireConsignations() {
  const gabarit = {
    version: 0, kind: "consignation-rejeu", test_id: "TR-10", date: "2027-01-15", commit: COMMIT,
    participant: { pseudonym: "P-01", role: "reviseur externe", external: true },
    judge: { pseudonym: "J-01", independent: true },
    material: [
      { item: "CT-8 section 13 (extrait)", sha256: "0".repeat(64) },
      { item: "paquet.tar (cas valide-empreinte)", sha256: "0".repeat(64) },
      { item: "paquet.tar (cas tiré au sort : fichier-altere)", sha256: "0".repeat(64) },
      { item: "répertoire verificateur/ d'un paquet complet construit par la CI", sha256: null },
    ],
    forbidden_sections: ["CT-8 hors section 13", "le dépôt", "spec/vecteurs/ct-8/paquets/cas.json", "toute personne à interroger"],
    grid: "spec/vecteurs/ct-8/paquets/cas.json", duration_s: null, information_requests: 0,
    verdict: {
      status: "reussi", disqualifying_statement: false,
      elements: [
        { element: "valide-empreinte : code 0, intact, commande avec --empreinte", present: true },
        { element: "fichier-altere : code 4, non_conforme, PR- en échec de cas.json", present: true },
        { element: "sortie jointe : SHA-256 égal à celle de l'outil sur ce paquet", present: true },
        { element: "phrase : ni auteur, ni complétude, ni ancres du réviseur", present: true },
      ],
    },
    output_sha256: null,
    notes: "Gabarit : les SHA-256 à zéro et `duration_s` null sont des valeurs de gabarit ; une consignation réelle les remplit (EX-12.4). Aucune épreuve n'a été conduite en version 0.1.",
  };
  const cas = {
    "valide-gabarit": gabarit,
    "invalide-reussi-element-absent": { ...gabarit, verdict: { ...gabarit.verdict, elements: [...gabarit.verdict.elements.slice(0, 3), { element: "phrase : ni auteur, ni complétude, ni ancres du réviseur", present: false }] } },
    "invalide-reussi-disqualifiant": { ...gabarit, verdict: { ...gabarit.verdict, disqualifying_statement: true } },
    "invalide-juge-non-independant": { ...gabarit, judge: { pseudonym: "J-01", independent: false } },
    "invalide-nom-de-personne": { ...gabarit, participant: { pseudonym: "Jean Dupont", role: "reviseur externe", external: true } },
    "invalide-sans-materiel": { ...gabarit, material: [] },
  };
  const raisons = {
    "valide-gabarit": "Gabarit de TR-10 : pseudonymes, juge indépendant, matériel avec SHA-256 de gabarit, verdict réussi avec chaque élément présent.",
    "invalide-reussi-element-absent": "Verdict `reussi` avec un élément de grille absent : refusé (EX-12.6).",
    "invalide-reussi-disqualifiant": "Verdict `reussi` avec une affirmation disqualifiante : refusé (EX-12.6).",
    "invalide-juge-non-independant": "Juge qui a aidé le participant (`independent` faux) : refusé (EX-12.5).",
    "invalide-nom-de-personne": "Participant désigné par un nom au lieu d'un pseudonyme `P-nn` : refusé (EX-12.1).",
    "invalide-sans-materiel": "Aucun matériel remis consigné : refusé (EX-12.2).",
  };
  const casJson = {
    version: 0, family: "ct-9/consignations/cas",
    description: "Cas valides et invalides de la consignation d'une épreuve à l'aveugle (plan-de-tests-v0, #/$defs/consignation_rejeu) ; `expected` est le verdict d'ajv (`valid` ou `invalid`) et `reason` ce que le cas éprouve (CT-9 EX-12.4, EX-A.15).",
    cases: Object.keys(cas).map((n) => ({ file: `${n}.json`, def: "consignation_rejeu", expected: n.startsWith("valide") ? "valid" : "invalid", reason: raisons[n] })),
  };
  return { gabarit, cas, casJson };
}

// ---------------------------------------------------------------------------
// Grilles et consignes des épreuves (EX-12.7, EX-15.2, EX-15.4, EX-A.16)
// ---------------------------------------------------------------------------

const grille = (test_id, description, questions, disqualifying) => ({ version: 0, kind: "grille-acceptation", test_id, description, questions, disqualifying });
const q = (id, question, elements) => ({ id, question, elements: elements.map(([element, ...rules]) => ({ element, rules })) });

/** Grille de TR-4 (CT-5 §1, épreuve d'acceptation) : éléments cités dans
 * les étapes de l'entrée. */
export function grilleAncrage() {
  return grille("TR-4", "Grille de l'épreuve d'acceptation de CT-5 (TR-4) : les éléments que chaque réponse doit contenir, chacun avec la règle qui le fonde ; jamais remise au participant.", [
    q("q1", "Quelle est la cadence des points de contrôle, des échéances de contresignature et des clôtures ?", [
      ["un point de contrôle du journal toutes les 60 s (c_K)", "CT-5 §4.1", "CT-5 EX-3.3"],
      ["une échéance de contresignature RFC 3161 toutes les 300 s (c_T)", "CT-5 §4.2", "CT-5 EX-3.3"],
      ["une clôture de période toutes les heures (3 600 s), avec jeton qualifié et preuve OpenTimestamps", "CT-5 §4.1", "CT-5 §4.5"],
    ]),
    q("q2", "Pour chacune des quatre ancres d'un point, que prouve-t-elle quand sa vérification réussit, et que ne prouve-t-elle pas ?", [
      ["jeton RFC 3161 : l'empreinte existait au plus tard à genTime augmenté de la précision, selon l'autorité qui l'a signé ; ni une borne « pas avant », ni la date de l'événement (ts déclaratif)", "CT-5 §3.2", "CT-6 EX-9.20"],
      ["ancre au registre : l'ordre entre les blocs et l'unicité de l'empreinte sur la chaîne (H6, H7) ; aucune date", "CT-5 §3.2", "CT-4 §3.4"],
      ["attestation Bitcoin (OpenTimestamps) : l'empreinte existait avant la création d'un bloc Bitcoin sous k confirmations, sans autorité ; rien avant l'inclusion", "CT-5 §3.2", "CT-6 §10"],
      ["signature du point par l'enregistreur : une attribution à la clé key_id ; rien contre qui détient cette clé", "CT-5 §3.2", "CT-1 §10.9"],
    ]),
    q("q3", "Quelle fenêtre de réécriture la conception laisse-t-elle, avec les points de contrôle en service et avec les seules ancres horaires ?", [
      ["W_date ≤ 300 s + d_jeton pour la date (premier point contresigné après l'échéance)", "CT-5 §3.3", "CT-5 EX-3.3"],
      ["W_ordre ≤ 60 s + d_registre pour l'ordre : durée de conception, pas une borne de réécriture qu'un dossier prouve", "CT-5 §3.3", "CT-5 EX-3.3"],
      ["3 600 s + d_clôture + d_jeton avec les seules ancres horaires (sans points)", "CT-5 §3.3", "CT-6 §3.4"],
    ]),
    q("q4", "Pour les prix unitaires symboliques donnés dans la consigne, quel est le coût annuel d'ancrage d'un journal dans le cas nommé ?", [
      ["C_j = 28 032 p pour le cas defaut-second-rang-a1 : 8 760 jetons qualifiés × 1 p + 96 360 jetons de second rang × 0,2 p", "CT-5 §12.2", "spec/vecteurs/ct-5/cout/cout.json"],
    ]),
    q("q5", "Que fait le composant d'ancrage quand le prestataire d'horodatage est injoignable, et que voit le réviseur ?", [
      ["les demandes restent dans la file durable et sont reprises au redémarrage ; rien ne bloque l'enregistreur", "CT-5 §8.5", "CT-5 §4.7"],
      ["l'attente est plafonnée (squat_wait_s pour le registre, fallback_after_s pour la relève)", "CT-5 EX-4.7", "CT-5 §8.6"],
      ["le prestataire de secours relève le principal pour la clôture après fallback_after_s (300 s pour le manifeste)", "CT-5 §5.3", "CT-5 §4.4"],
      ["pour les points, rfc3161.checkpoints.fallback_after_s vaut 120 s par défaut", "CT-5 §4.4", "CT-5 EX-5.7"],
      ["aucune bascule automatique vers le serveur interne non qualifié", "CT-5 §7.3", "CT-5 §5.3"],
      ["une alerte prestataire_injoignable est levée au bout de 15 min", "CT-5 §3.3", "CT-5 §8.9"],
      ["le réviseur voit la fenêtre dégradée 3 600 s + d sur les événements dont le point n'a pas été contresigné", "CT-5 §3.3", "CT-6 §7.9"],
    ]),
  ], [
    "affirme qu'une date portée par un objet ancré (ts, generated_at, checkpoint_ts) est prouvée par le composant d'ancrage (CT-5 EX-3.2)",
  ]);
}

/** Grille de TR-5 (CT-6 §7.9, verdict avec un point de contrôle) : éléments
 * cités dans les étapes de l'entrée. */
export function grilleVerdictPoint() {
  return grille("TR-5", "Grille de l'épreuve de lecture de CT-6 §7 révisée (TR-5) : les éléments que chaque réponse doit contenir, chacun avec la règle qui le fonde ; jamais remise au participant.", [
    q("q1", "Qu'engage le point de contrôle que porte le dossier ?", [
      ["les tree_size premiers événements du journal de la période (racine des tree_size premières feuilles)", "CT-6 §7.9", "CT-1 §10.5"],
      ["un préfixe prouvé de l'arbre du manifeste (preuve de cohérence, K-5)", "CT-6 §7.9", "CT-6 EX-6.16"],
    ]),
    q("q2", "Que prouve la clause jeton du point, et qu'est-ce que rewrite_window_ms ?", [
      ["l'empreinte du point existait au plus tard à rewrite_window_end (jeton du point, K-7), selon l'autorité du fichier d'ancres", "CT-6 §7.9", "CT-6 EX-6.17"],
      ["rewrite_window_ms est une valeur rapportée, calculée depuis le ts déclaré de l'événement ; ce n'est pas une preuve", "CT-6 §7.9", "CT-5 §3.3"],
    ]),
    q("q3", "Que changerait une réécriture postérieure au point, et qui la détecte ?", [
      ["une réécriture changerait la racine engagée : l'événement réécrit ne serait plus couvert par le point contresigné, ou le point ne serait plus un préfixe du manifeste", "CT-6 §7.9", "CT-6 §3.4"],
      ["la détecte quiconque détient ce dossier et le vérifie ; personne ne veille", "CT-6 §7.9", "CT-6 §7.8"],
    ]),
    q("q4", "Que ne prouve pas la signature du point, et que reste-t-il sans la clause jeton (K-7) ?", [
      ["la signature du point ne prouve rien contre qui détient la clé de l'enregistreur", "CT-5 §3.2", "CT-6 §7.9"],
      ["sans K-7 réussie, rien de daté : le verdict n'énonce aucun instant pour le point (EX-7.2)", "CT-6 EX-7.2", "CT-6 §7.9"],
    ]),
  ], [
    "présente rewrite_window_ms comme prouvé",
    "présente la détection d'une réécriture comme active (quelqu'un veille)",
  ]);
}

/** Tables Markdown d'un texte entre deux titres : [{ entete, lignes:
 * [[cellules]] }]. */
function tablesEntre(texte, debutRe, finRe) {
  const d = texte.search(debutRe);
  if (d === -1) throw new Error(`section introuvable : ${debutRe}`);
  const reste = texte.slice(d);
  const f = reste.slice(1).search(finRe);
  const bloc = f === -1 ? reste : reste.slice(0, f + 1);
  const tables = [];
  let courante = null;
  for (const l of bloc.split("\n")) {
    if (l.startsWith("|")) {
      const cellules = l.split(/(?<!\\)\|/).slice(1, -1).map((c) => c.trim());
      if (!courante) { courante = { entete: cellules, lignes: [] }; tables.push(courante); }
      else if (!/^-+$/.test(cellules[0])) courante.lignes.push(cellules);
    } else courante = null;
  }
  return { tables, bloc };
}

/**
 * Grille de TR-14 (épreuve (b) de CT-9), produite depuis la section 14 du
 * texte de CT-9 (critères « continuer si » et « arrêter ou reprendre si »,
 * entrées, verdict calculable ; EX-14.2) et la table des niveaux du
 * catalogue (EX-15.2).
 */
export function grillePorte2(texteCT9, catalogue) {
  const { tables, bloc } = tablesEntre(texteCT9, /^## 14\. /m, /^## 15\. /m);
  if (tables.length !== 2) throw new Error(`section 14 : ${tables.length} tables lues, 2 attendues`);
  const [continuer, arreter] = tables;
  const ex142 = /\*\*EX-14\.2\*\* Ce que la porte 2 ne mesure pas, et le dit : ([\s\S]*?)\n\n/.exec(bloc);
  if (!ex142) throw new Error("EX-14.2 introuvable dans la section 14");
  const nonMesure = ex142[1].replace(/\s+/g, " ").replace(/\.$/, "").split(" ; ").map((s) => s.trim());
  const q1 = continuer.lignes.map(([critere, entrees, verdict]) => [`${critere} : ${verdict}`, `CT-9 §14 (entrées : ${entrees})`, "CT-9 EX-14.1"]);
  const q2 = nonMesure.map((s) => [s, "CT-9 EX-14.2"]);
  const q3 = catalogue.levels.map((n) => {
    const re = new RegExp(`\\b${n.id}-[0-9]+`);
    const sert = continuer.lignes.filter(([, e]) => re.test(e)).map(([c]) => c);
    const arret = arreter.lignes.filter(([, e]) => re.test(e)).map(([c]) => c);
    const texte = [sert.length ? `continuer si : ${sert.join(" ; ")}` : null, arret.length ? `arrêter ou reprendre si : ${arret.join(" ; ")}` : null].filter(Boolean).join(" — ");
    return [`${n.id}- (${n.name}) : ${texte || "aucun critère de la porte 2 (exigences des spécifications)"}`, "CT-9 §3.1", "CT-9 §14"];
  });
  return grille("TR-14", "Grille de l'épreuve (b) de CT-9 (TR-14), produite depuis la section 14 (critères, entrées, verdict calculable, ce que la porte 2 ne mesure pas) et la table des niveaux ; jamais remise au participant.", [
    q("q1", "Que prouve le passage de la porte 2 ? Pour chaque critère « continuer si », les entrées qui le servent et le verdict calculable.", q1),
    q("q2", "Que ne mesure pas la porte 2 ?", q2),
    q("q3", "Quel critère du plan chaque famille de tests TU- à TQ- sert-elle ?", q3),
  ], [
    "dit que la porte 2 prouve la conformité d'un client à un texte",
    "dit que la porte 2 prouve le périmètre de capture",
    "dit que la porte 2 prouve la robustesse face à un attaquant hors du modèle de menace de CT-7 §3.4",
  ]);
}

/** Dossier des vecteurs ct-6 à partie points-de-controle.json dont le
 * rapport est remis au participant de TR-5. */
export const DOSSIER_TR5 = "spec/vecteurs/ct-6/dossiers/valide-point-de-controle-complet";

const EN_TETE_CONSIGNE = (titre, test_id, grille = ["réponse. La grille du juge est un fichier à part qui ne lui est pas remis."]) => [`# ${titre}`, "", `Consigne de l'épreuve ${test_id} de CT-9 (section 12, protocole commun ;`, "table 12.2). Produite par `scripts/vecteurs/generer-ct9.mjs` ; ne pas", "l'éditer à la main. Le participant reçoit ce fichier et le matériel nommé", "ci-dessous, rien d'autre ; il répond par écrit, seul, sans interroger", "personne ; la durée court de la remise du matériel à la remise de la", ...grille, ""];

/** Consignes remises aux participants (EX-A.16, EX-15.4) : { chemin relatif
 * à ct-9 : texte }. */
export function consignes() {
  const c = {};
  c["acceptation-ancrage/consigne.md"] = [...EN_TETE_CONSIGNE("Épreuve d'acceptation de CT-5 : ancrage, cadence, fenêtre, coût, panne", "TR-4"),
    "## Matériel remis", "",
    "- `spec/CT-5-ancrage.md` en entier ;", "- `spec/CT-1-journal.md`, sections 9 à 11 ;",
    "- cette consigne.", "",
    "Ne sont pas remis : CT-6, CT-8, CT-9, le code du dépôt, la grille", "`acceptation-ancrage-attendu.json`.", "",
    "## Données de la question 4", "",
    "Prix unitaires symboliques : `p_q` = 1 p par jeton d'une autorité qualifiée,", "`p_s` = 0,2 p par jeton d'une autorité de second rang ; le registre et", "OpenTimestamps ne sont pas facturés dans ce calcul. Cas à traiter : le cas", "nommé `defaut-second-rang-a1` de la section de CT-5 sur le coût (points", "contresignés par une autorité de second rang, `a` = 1), pour un journal sur", "une année. Donnez le détail du calcul et le total.", "",
    "## Questions", "",
    "1. À quelle cadence l'enregistreur produit-il ses points de contrôle, à", "   quelle cadence le composant d'ancrage les fait-il contresigner, et à", "   quelle cadence les périodes sont-elles closes ? Nommez les paramètres.",
    "2. Pour chacune des ancres qu'un point peut recevoir, dites ce que sa", "   vérification réussie prouve et ce qu'elle ne prouve pas.",
    "3. Quelle fenêtre de réécriture la conception laisse-t-elle à qui détient", "   la clé de l'enregistreur, pour la date et pour l'ordre, avec les points", "   en service ; et quelle fenêtre restait-il avec les seules ancres", "   horaires ?",
    "4. Avec les données ci-dessus, quel est le coût annuel d'ancrage d'un", "   journal dans le cas nommé ?",
    "5. Le prestataire d'horodatage principal ne répond plus pendant une heure.", "   Que fait le composant d'ancrage, que fait l'enregistreur, qu'est-ce qui", "   est alerté et quand, et que verra le réviseur d'un dossier exporté", "   pendant cette heure ?", "",
    "## Forme de la réponse", "",
    "Un texte par question, numéroté ; citez la section de CT-5 ou de CT-1 qui", "fonde chaque affirmation. Ne recopiez pas la spécification : dites ce", "qu'elle établit.", ""].join("\n");
  c["acceptation-verdict-point/consigne.md"] = [...EN_TETE_CONSIGNE("Épreuve de lecture de CT-6 §7 révisée : le verdict avec un point de contrôle", "TR-5"),
    "## Matériel remis", "",
    "- `spec/CT-6-verificateur.md`, section 7 entière (7.1 à 7.10) ;",
    "- le rapport de vérification d'un dossier des vecteurs qui porte la partie", "  `points-de-controle.json` ; le dossier est :", "", "  ```text", `  ${DOSSIER_TR5}`, "  ```", "", "  Son énoncé est le membre `statement` de son fichier `attendu.json` ; le", "  rapport complet se produit, avec les fichiers d'ancres et d'en-têtes que ce", "  même `attendu.json` nomme (`anchors`, `bitcoin_headers`), par :", "", "  ```bash", "  node scripts/verify/dossier.mjs <dossier> --ancres <ancres> \\", "    --entetes-bitcoin <chaîne> --json", "  ```", "",
    "- cette consigne.", "",
    "Ne sont pas remis : les autres sections de CT-6, CT-5, CT-9, la grille", "`acceptation-verdict-point-attendu.json`.", "",
    "## Questions", "",
    "1. Qu'engage exactement le point de contrôle que porte ce dossier, par", "   rapport au journal et par rapport au manifeste de la période ?",
    "2. Que prouve la clause du rapport qui porte sur le jeton du point, et que", "   représente le membre `facts.checkpoint.rewrite_window_ms` du rapport :", "   une preuve ou autre chose ?",
    "3. Si l'enregistreur réécrivait cet événement après ce point, qu'est-ce qui", "   changerait dans la vérification, et qui s'en apercevrait ?",
    "4. Que ne prouve pas la signature du point par l'enregistreur, et que", "   resterait-il du verdict si la vérification du jeton du point n'avait pas", "   été exécutée ou avait échoué ?", "",
    "## Forme de la réponse", "",
    "Un texte par question, numéroté ; citez le passage de la section 7 qui", "fonde chaque affirmation.", ""].join("\n");
  c["acceptation-plan/consigne.md"] = [...EN_TETE_CONSIGNE("Épreuves (a) et (c) de CT-9 : écrire un test, ajouter une entrée", "TR-13 et TR-15", ["réponse. Pour (a), la grille du juge est l'entrée du catalogue elle-même et", "les exigences qu'elle cite (exception écrite d'EX-12.3) ; pour (c), le", "verdict de l'outil de couverture."]),
    "## Épreuve (a), testeur (TR-13)", "",
    "Matériel : `spec/CT-9-plan-de-tests.md` sans sa section 15 (extrait", "`extraits/CT-9-sans-15.md`), le catalogue `catalogue.json`, les identifiants des", "cinq entrées que le juge a tirées au sort parmi les entrées `a_ecrire` autres", "que TR-13, TR-14 et TR-15 (le juge remet ces identifiants, non une règle de", "tirage ; ils sont consignés) et, pour chacune, les spécifications qu'elle vise :", "celles de son membre `specs` et, de toute autre spécification que ses", "préconditions, ses pas, son oracle ou son bloc propre nomment, les sections", "citées ; les lire n'est pas un écart. Ne sont pas remis : la section 15 de CT-9,", "les fichiers `test/*.test.js` du dépôt.", "",
    "Pour chaque entrée tirée, écrivez un fichier de test, en mocha ou en", "pseudo-code structuré, qui reprend ses préconditions (ce qui doit être vrai", "avant), ses étapes (dans l'ordre) et son oracle (ce qui est comparé à", "quoi), avec pour chacun une contrepartie exécutable : une entrée concrète,", "une comparaison, une valeur ou un fichier. Chaque assertion cite", "l'identifiant de la règle qu'elle vérifie. Une réponse qui recopie le texte", "de l'entrée sans entrée concrète ni comparaison exécutable échoue. Rendez", "cinq fichiers, un par entrée, nommés par l'identifiant de l'entrée.", "",
    "## Épreuve (c), développeur (TR-15)", "",
    "Matériel : `spec/CT-9-plan-de-tests.md` sans sa section 15, le dépôt au commit", "éprouvé, et une exigence EX- d'une des spécifications CT-1 à CT-8, désignée par", "le juge et consignée. Aucun auteur de CT-9 ne peut être interrogé. Si l'exigence", "désignée n'existe pas dans la spécification nommée, consignez-le et", "arrêtez-vous, sans lui substituer une autre exigence.", "",
    "Ajoutez au catalogue une entrée qui teste cette exigence, en suivant les", "seules règles de CT-9 (sections 3 et 4 : niveau, famille d'identifiant,", "membres d'une entrée, états) et la procédure d'EX-4.6 : l'entrée s'écrit", "dans la source de données du générateur (`scripts/vecteurs/ct9/donnees/`),", "le catalogue se régénère par `npm run vecteurs:ct9`, les tables du texte", "se réimpriment par `node scripts/vecteurs/generer-ct9.mjs --tables", "<fichier hors de spec/vecteurs/ct-9/>` et vous collez les blocs", "`<!-- table X -->` régénérés dans `spec/CT-9-plan-de-tests.md` (vous", "mettez aussi à jour les chiffres de la section 5.5 si votre entrée les", "change, et, s'ils changent, ceux des sections 10.8 et 16, que l'outil ne", "relit pas), puis vous lancez `node scripts/tests/couverture.mjs`, sans puis", "avec `--strict`. Rendez le diff de votre ajout (source de données et", "texte) et la sortie de l'outil. Si votre entrée est `executable`, écrivez", "aussi le test qu'elle cite dans `test/*.test.js` : son diff fait alors", "partie de votre réponse.", "",
    "## Forme de la réponse", "",
    "Les fichiers rendus et, pour (c), le diff et la sortie de l'outil ; aucune", "autre explication n'est demandée.", ""].join("\n");
  c["acceptation-porte-2/consigne.md"] = [...EN_TETE_CONSIGNE("Épreuve (b) de CT-9 : relecture de la porte 2", "TR-14"),
    "## Matériel remis", "",
    "- `spec/CT-9-plan-de-tests.md` sans sa section 15 (extrait", "  `extraits/CT-9-sans-15.md`) ;", "- cette consigne.", "",
    "Ne sont pas remis : la section 15 de CT-9, la grille", "`acceptation-porte-2-attendu.json`, le plan de projet interne.", "",
    "## Questions", "",
    "1. Que prouve le passage de la porte 2 ? Pour chaque critère que CT-9", "   rattache à la porte, dites quelles entrées du catalogue le servent et", "   comment son verdict se calcule.",
    "2. Que ne prouve pas, et que ne mesure pas, le passage de la porte 2 ?",
    "3. Pour chacune des huit familles de tests de CT-9, dites quel critère de", "   la porte elle sert, ou qu'elle n'en sert aucun directement.", "",
    "## Forme de la réponse", "",
    "Un texte par question, numéroté ; citez la section de CT-9 qui fonde chaque", "affirmation.", ""].join("\n");
  return c;
}

// ---------------------------------------------------------------------------
// Extraits des spécifications remis aux participants (EX-12.2, EX-A.16)
// ---------------------------------------------------------------------------

/**
 * Extrait d'une spécification par sections de niveau 2 (`## n.`, `## Annexe
 * X`) et de niveau 3 (`### A.n`), hors blocs de code : `garder` liste les
 * sections de niveau 2 conservées (toutes si null), `retirer` celles de
 * niveau 2 ou 3 retirées. L'en-tête (avant le premier titre de niveau 2)
 * est conservé quand `garder` est null. Le texte n'est pas modifié autrement.
 */
export function extraire(texte, { garder = null, retirer = [] } = {}) {
  const out = [];
  let code = false;
  let h2 = null;
  let h3 = null;
  for (const l of texte.split("\n")) {
    if (l.startsWith("```")) code = !code;
    if (!code) {
      const m2 = /^## (?:([0-9]+)\.|Annexe ([A-Z]))/.exec(l);
      const m3 = /^### ([A-Z]\.[0-9]+)\b/.exec(l);
      if (m2) { h2 = m2[1] ?? `Annexe ${m2[2]}`; h3 = null; } else if (m3) h3 = m3[1];
    }
    const dedans = garder === null ? true : h2 !== null && garder.includes(h2);
    const retire = (h2 !== null && retirer.includes(h2)) || (h3 !== null && retirer.includes(h3));
    if (dedans && !retire) out.push(l);
  }
  return out.join("\n");
}

/** Les six extraits d'EX-A.16 et leur SHA256SUMS : { nom : texte }. */
export function construireExtraits(racine) {
  const lire = (f) => fs.readFileSync(path.join(racine, "spec", f), "utf8");
  const ct7 = lire("CT-7-securite-et-conformite.md");
  const ct8 = lire("CT-8-deploiement-et-exploitation.md");
  const ct9 = lire("CT-9-plan-de-tests.md");
  const extraits = {
    "CT-7-sans-9-A15.md": extraire(ct7, { retirer: ["9", "A.15"] }),
    "CT-8-sans-14-A.md": extraire(ct8, { retirer: ["14", "Annexe A"] }),
    "CT-8-13.md": extraire(ct8, { garder: ["13"] }),
    "CT-8-12.md": extraire(ct8, { garder: ["12"] }),
    "CT-7-7.md": extraire(ct7, { garder: ["7"] }),
    "CT-9-sans-15.md": extraire(ct9, { retirer: ["15"] }),
  };
  for (const [n, t] of Object.entries(extraits)) if (!t.trim()) throw new Error(`extrait ${n} vide`);
  extraits.SHA256SUMS = Object.keys(extraits).sort().map((n) => `${sha256(Buffer.from(extraits[n], "utf8"))}  ${n}\n`).join("");
  return extraits;
}

/** Correspondance TR- → épreuve → extrait remis (EX-12.2), pour INDEX.md et
 * les tests. */
export const EXTRAITS_PAR_EPREUVE = Object.freeze({
  "CT-7-sans-9-A15.md": ["TR-6", "TR-7"],
  "CT-8-sans-14-A.md": ["TR-9"],
  "CT-8-13.md": ["TR-10"],
  "CT-8-12.md": ["TR-11"],
  "CT-7-7.md": ["TR-8"],
  "CT-9-sans-15.md": ["TR-13", "TR-14", "TR-15"],
});
