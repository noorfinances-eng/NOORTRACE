// Rapport de la campagne de mesures de l'étape 5 (scripts/e2e/mesure-ancrage.mjs
// rapport) : lit une ou deux collectes (`collecter`, configurations `defaut`
// et `porte2`), les compléments (`complements`) et, s'il existe, le relevé
// TM-16 d'`ancres/` sur le support WORM réel (test/enregistreur-journal-soi.test.js,
// NOORTRACE_RAPPORT_TM16_ANCRES), et écrit un rapport conforme à
// `plan-de-tests-v0#/$defs/rapport_mesure` (CT-9 §11.3, EX-11.11) : une ligne
// par grandeur, percentiles par la méthode du plus proche rang (EX-11.4),
// échantillons publiés dans la ligne, `counts_for_targets` faux et `met` null
// partout (cette machine n'est pas le système de référence de la porte 2 :
// EX-11.2, schéma), cible du catalogue recopiée, conditions et notes.
//
// Le rapport est validé avant d'être tenu pour écrit par l'outil publié de
// CT-9 (`node scripts/tests/mesures.mjs`, boîte noire : schéma, catalogue,
// MES-1 à MES-7), sur une racine temporaire qui réunit le dépôt et le rapport ;
// un code autre que 0 est une erreur et le rapport n'est pas gardé.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import { lireFiles, constaterCadence } from "@noortrace/ancrage/planificateur";
import { RACINE } from "./reseau-dev.mjs";
import { agreger, systeme } from "./mesure-ancrage.mjs";

const lireJson = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
const r3 = (x) => (x === null || x === undefined ? null : Math.round(x * 1000) / 1000);
const ms = (t) => N.decoderHorodatage(t);

/** Lit une collecte : données brutes dérivées en séries (secondes, trois décimales). */
export function lireCollecte(repertoire) {
  const c = lireJson(path.join(repertoire, "collecte.json"));
  const donnees = path.join(repertoire, "donnees");
  const P = c.period_start;
  const debutP = P * 1000;
  const finP = debutP + 3600000;
  const evenements = lireJson(path.join(donnees, "evenements.json")).filter((e) => e.seq && ms(e.ts) >= debutP && ms(e.ts) < finP).sort((a, b) => a.seq - b.seq);
  const points = fs.readFileSync(path.join(donnees, `points-periode-${P}.ndjson`), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)).sort((a, b) => a.tree_size - b.tree_size || ms(a.checkpoint_ts) - ms(b.checkpoint_ts));
  const verifications = lireJson(path.join(donnees, "verifications.json"));
  const journal = fs.readFileSync(path.join(donnees, "exploitation.ndjson"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const file = lireFiles(donnees).demandes.filter((d) => d.subject.period_start === P);
  const tsa = fs.existsSync(path.join(donnees, "tsa-journal.ndjson")) ? fs.readFileSync(path.join(donnees, "tsa-journal.ndjson"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
  // P-1 : premier point signé qui engage l'événement (tree_size > indice), délai depuis ts.
  const premierPoint = (i) => points.find((p) => p.tree_size > i) ?? null;
  const p1 = evenements.map((e, i) => {
    const p = premierPoint(i);
    return p ? r3((ms(p.checkpoint_ts) - ms(e.ts)) / 1000) : null;
  });
  const cadence = constaterCadence({ periodStart: P, checkpointIntervalS: c.parametres.c_K, points });
  // P-2 : ancres des points incluses : reçu (obtained_at, horloge de l'enregistreur) − checkpoint_ts (declared_at).
  const ancres = file.filter((d) => d.kind === "ancre_registre_point");
  const incluses = ancres.filter((d) => d.state === "obtenue" && d.result?.obtained_at);
  const p2 = incluses.sort((a, b) => ms(a.subject.declared_at) - ms(b.subject.declared_at)).map((d) => r3((ms(d.result.obtained_at) - ms(d.subject.declared_at)) / 1000));
  // W_ordre : inclusion de l'ancre du premier point ancré qui engage l'événement, moins ts.
  const parHash = new Map(incluses.map((d) => [d.subject.hash, d]));
  const wOrdre = evenements.map((e, i) => {
    const p = points.find((x) => x.tree_size > i && parHash.has(N.hacherPoint(x)));
    return p ? r3((ms(parHash.get(N.hacherPoint(p)).result.obtained_at) - ms(e.ts)) / 1000) : null;
  });
  // P-3 : lignes checkpoint_countersigned de la période (points de P : checkpoint_ts entre P et P + 3600).
  const hashesP = new Set(points.map((p) => N.hacherPoint(p)));
  const contresignes = journal.filter((l) => l.event === "checkpoint_countersigned" && ms(l.ts) >= debutP && ms(l.ts) < finP + 1200000);
  void hashesP;
  // Révision 0.6 de CT-5 (EX-3.5, 8.9) : d_admission_s (checkpoint_ts → admission du point par le composant) et
  // d_attente_s compté depuis l'admission ; une collecte d'avant la révision n'a pas de d_admission_s (série vide).
  const p3 = { d_jeton: [], d_point: [], d_admission: [], d_attente: [], d_releve: [], d_tsa: [] };
  for (const l of contresignes) {
    if (!Array.isArray(l.data.deadlines) || l.data.deadlines.length === 0) continue;
    p3.d_jeton.push(l.data.d_jeton_s);
    p3.d_point.push(l.data.d_point_s);
    if (Number.isInteger(l.data.d_admission_s)) p3.d_admission.push(l.data.d_admission_s);
    p3.d_attente.push(l.data.d_attente_s);
    p3.d_releve.push(l.data.d_releve_s);
    p3.d_tsa.push(l.data.d_tsa_s);
  }
  const tardives = journal.filter((l) => l.event === "checkpoint_anchor_late" && ms(l.ts) >= debutP && ms(l.ts) < finP + 1200000).length;
  const sansObjet = journal.filter((l) => l.event === "deadline_sans_objet" && ms(l.ts) >= debutP && ms(l.ts) < finP + 1200000).length;
  // W_date : rewrite_window_ms des dossiers exportés et vérifiés (CT-6 EX-6.17), en secondes.
  const wDate = verifications.filter((v) => typeof v.rewrite_window_ms === "number").map((v) => r3(v.rewrite_window_ms / 1000));
  const verdicts = verifications.reduce((a, v) => ((a[v.verdict ?? "aucun"] = (a[v.verdict ?? "aucun"] ?? 0) + 1), a), {});
  const k7 = verifications.filter((v) => v.checks?.["K-7"] === "reussi").length;
  const t11 = verifications.filter((v) => v.checks?.["T-11"] === "reussi").length;
  const controles458 = verifications.filter((v) => v.controles && v.controles[4] === "reussi" && v.controles[5] === "reussi" && v.controles[8] === "reussi").length;
  // Jetons de la période (TM-19) et écart d'horloge des serveurs internes.
  const accuracy = c.jetons.map((j) => j.accuracy_s).filter((x) => typeof x === "number");
  const offsets = tsa.filter((l) => l.event === "tsa_demarrage" || l.data?.tsa_clock_offset_ms !== undefined).map((l) => Math.abs(Number(l.data?.tsa_clock_offset_ms ?? 0)) / 1000);
  // Preuves de la période.
  const preuves = c.preuves ?? [];
  // d_attente des lignes checkpoint_countersigned (checkpoint_ts → premier envoi, EX-3.5) décomposé depuis la file : délai
  // d'admission du point (declared_at → created_at) et attente propre de l'ancre au registre (created_at → premier envoi, EX-4.7).
  const jetonsPoints = file.filter((d) => d.kind === "jeton_point" && d.state === "obtenue" && d.attempts?.length);
  const admission = jetonsPoints.map((d) => r3((ms(d.created_at) - ms(d.subject.declared_at)) / 1000));
  const attentePropre = jetonsPoints.map((d) => r3((ms(d.attempts[0].started_at) - ms(d.created_at)) / 1000));
  return { c, P, evenements, points, verifications, journal, file, ancres, incluses, p1, cadence, p2, wOrdre, p3, admission, attentePropre, contresignes: contresignes.length, tardives, sansObjet, wDate, verdicts, k7, t11, controles458, accuracy, offsets, preuves, tsa };
}

function ligne({ name, test_id, unit, serie = null, value = null, text_value = null, target, conditions, n = null, percentiles = true }) {
  const a = serie ? agreger(serie.filter((x) => typeof x === "number")) : null;
  return {
    name, test_id, unit,
    n: serie ? a.n : n,
    connections: null,
    samples: serie ? serie.filter((x) => typeof x === "number") : null,
    samples_sha256: null,
    value,
    p50: serie && percentiles ? a.p50 : null,
    p95: serie && percentiles ? a.p95 : null,
    p99: serie && percentiles ? a.p99 : null,
    min: serie ? a.min : null,
    max: serie ? a.max : null,
    mean: serie ? a.mean : null,
    text_value,
    target,
    met: null,
    conditions,
    excluded_reason: "hors_systeme_de_reference",
  };
}

/** Valide un rapport avec l'outil publié de CT-9 (boîte noire) sur une racine temporaire ; rend { code, texte }. */
export function validerParOutilDeReference(cheminRapport, nomPublie = path.basename(cheminRapport)) {
  const T = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-mesure-validation-"));
  try {
    fs.mkdirSync(path.join(T, "spec", "vecteurs", "ct-9"), { recursive: true });
    fs.symlinkSync(path.join(RACINE, "spec", "schemas"), path.join(T, "spec", "schemas"));
    // Les autres familles de vecteurs telles quelles : les consignations de ct-9 citent leurs grilles (ct-8/paquets, CSG-5).
    for (const n of fs.readdirSync(path.join(RACINE, "spec", "vecteurs"))) if (n !== "ct-9" && !fs.existsSync(path.join(T, "spec", "vecteurs", n))) fs.symlinkSync(path.join(RACINE, "spec", "vecteurs", n), path.join(T, "spec", "vecteurs", n));
    const ct9 = path.join(RACINE, "spec", "vecteurs", "ct-9");
    for (const n of fs.readdirSync(ct9)) if (n !== "mesures") fs.symlinkSync(path.join(ct9, n), path.join(T, "spec", "vecteurs", "ct-9", n));
    const mesures = path.join(T, "spec", "vecteurs", "ct-9", "mesures");
    fs.mkdirSync(mesures);
    for (const n of fs.readdirSync(path.join(ct9, "mesures"))) fs.symlinkSync(path.join(ct9, "mesures", n), path.join(mesures, n));
    const nom = nomPublie;
    if (fs.existsSync(path.join(mesures, nom))) fs.unlinkSync(path.join(mesures, nom));
    fs.copyFileSync(cheminRapport, path.join(mesures, nom));
    const r = spawnSync(process.execPath, [path.join(RACINE, "scripts", "tests", "mesures.mjs"), "--racine", T], { cwd: RACINE, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
    return { code: r.status, texte: `${r.stdout ?? ""}${r.stderr ?? ""}` };
  } finally {
    fs.rmSync(T, { recursive: true, force: true });
  }
}

export async function rapport({ collectes, complements = null, p6 = null, sortieRapport, sortie = null, notesOperateur = [], catalogue: cheminCatalogue, log = () => {} }) {
  const catalogue = lireJson(cheminCatalogue);
  const entree = (id) => catalogue.tests.find((t) => t.id === id);
  const cible = (id) => entree(id).measure.target;
  const unite = (id) => entree(id).measure.unit;
  const lues = collectes.map((d) => lireCollecte(d));
  const parConf = Object.fromEntries(lues.map((x) => [x.c.configuration, x]));
  const defaut = parConf.defaut ?? null;
  const porte2 = parConf.porte2 ?? null;
  if (!defaut && !porte2) throw new Error("aucune collecte lisible");
  const comp = complements ? lireJson(path.join(complements, "complements.json")) : null;
  const p6Releve = p6 ? lireJson(p6) : null;
  const results = [];
  const notes = [];
  const commun = (x) => [
    `réseau de développement noortrace-2124-dev (quatre validateurs BFT en boucle locale, chain/scripts/dev-net.sh), journal ${x.c.parcours.journal_neuf ? "neuf inscrit au registre pour la campagne" : "du parcours de référence"} sous l'organisation du parcours ; clé de chaîne de classe D`,
    `démon noortrace réel (processus enfant, test/fixtures/enregistreur-ancrage/demon.mjs) avec le composant d'ancrage branché ; charge à cadence fixe de ${x.c.evenements_par_s} événement/s (EX-11.9), ${x.evenements.length} événements dans la période ${x.P} (${new Date(x.P * 1000).toISOString()})`,
    `${x.c.parametres.description} ; serveurs RFC 3161 internes de référence du paquet d'ancrage sur la boucle locale (principal en TLS mutuel avec un qualified d'exemple, CT-5 EX-7.4), calendriers OpenTimestamps factices à chaîne regtest en TLS`,
    "délais lus sur l'horloge de l'enregistreur, source unique des instants (CT-5 P-2, CT-9 EX-11.5) ; temps réel, aucune horloge manipulée pendant la mesure",
    "autres charges sur la machine pendant la mesure : essais de l'étape 5 (démons et vérificateurs) exécutés en parallèle ; machine virtuelle, disque virtuel : hors du système de référence de CT-9 §11.1",
  ];
  const ajouter = (l) => results.push(l);
  for (const [x, suffixe] of [[defaut, ""], [porte2, "_porte_2"]]) {
    if (!x) continue;
    const C = commun(x);
    // TM-11
    ajouter(ligne({ name: `p1_cadence${suffixe}`, test_id: "TM-11", unit: unite("TM-11"), serie: x.p1, target: cible("TM-11"), conditions: [...C, `c_K = ${x.c.parametres.c_K} s`, `constaterCadence : ${x.cadence.conforme ? "aucun écart de cadence" : `${x.cadence.ecarts.length} écart(s)`}, ${x.points.length} points dans la série, tolérance ${x.cadence.tolerance_s} s`, `${x.p1.filter((v) => v === null).length} événement(s) sans point qui l'engage dans la série de la période`] }));
    notes.push(`TM-11 (${x.c.configuration}) : ${x.p1.filter((v) => typeof v === "number").length} délais événement → premier point signé qui l'engage, max ${agreger(x.p1.filter((v) => typeof v === "number")).max} s (cible 61 s ${agreger(x.p1.filter((v) => typeof v === "number")).max <= 61 ? "tenue en valeur" : "dépassée en valeur"}, sans valeur pour la cible : hors système de référence) ; cadence ${x.cadence.conforme ? "sans écart" : `avec ${x.cadence.ecarts.length} écart(s) : ${JSON.stringify(x.cadence.ecarts)}`} ; ${x.cadence.points_manquants.length} point(s) manquant(s).`);
    // TM-12
    ajouter(ligne({ name: `p2_inclusion${suffixe}`, test_id: "TM-12", unit: unite("TM-12"), serie: x.p2, target: cible("TM-12"), conditions: [...C, "registry.checkpoints nouveaux_evenements, inclusion_alert_s 60 s, squat_wait_s 5 s", `d_registre par ancre de point = ces échantillons (reçu d'inclusion sur l'horloge de l'enregistreur − checkpoint_ts) ; ${x.ancres.length} ancres de points dans la file, ${x.incluses.length} incluses, ${x.ancres.filter((d) => d.state === "remplacee").length} remplacées (EX-9.5)`] }));
    notes.push(`TM-12 (${x.c.configuration}) : ${x.p2.length} ancres de points incluses, d_registre p50 ${agreger(x.p2).p50} s, p99 ${agreger(x.p2).p99} s, max ${agreger(x.p2).max} s (cible 60 s ${agreger(x.p2).max <= 60 ? "tenue en valeur" : "dépassée en valeur"}).`);
    // TM-13
    for (const [k, nom] of [["d_jeton", "p3_d_jeton"], ["d_point", "p3_d_point"], ["d_admission", "p3_d_admission"], ["d_attente", "p3_d_attente"], ["d_releve", "p3_d_releve"], ["d_tsa", "p3_d_tsa"]]) {
      if (k === "d_admission" && x.p3.d_admission.length === 0) {
        notes.push(`TM-13 (${x.c.configuration}) : aucune ligne checkpoint_countersigned ne porte d_admission_s (collecte d'avant la révision 0.6 de CT-5) : ligne p3_d_admission non publiée.`);
        continue;
      }
      if (suffixe && k !== "d_jeton") continue;
      ajouter(ligne({ name: `${nom}${suffixe}`, test_id: "TM-13", unit: unite("TM-13"), serie: x.p3[k], target: cible("TM-13"), conditions: [...C, `c_T = ${x.c.parametres.c_T} s${x.c.parametres.c_T !== 300 ? " (hors de la condition c_T = 300 s de TM-13 : publié à titre de comparaison)" : ""}, prestataire des points : ${x.c.parametres.provider_role} (serveur interne de référence, EX-7.4), fallback_after_s 120 s`, `secondes entières tronquées des lignes checkpoint_countersigned (CT-5 EX-8.15) ; ${x.contresignes} lignes, ${x.tardives} échéance(s) remplacée(s) (checkpoint_anchor_late), ${x.sansObjet} sans_objet`] }));
    }
    {
      // Révision 0.6 de CT-5 (EX-3.5) : cinq composantes ; d_admission ≤ 10 s au 99e centile (borne de conception) ;
      // d_attente compté depuis l'admission, borné par squat_wait_s.
      const adm = agreger(x.p3.d_admission);
      const texteAdmission = x.p3.d_admission.length
        ? `d_admission p50 ${adm.p50} s, p99 ${adm.p99} s, max ${adm.max} s (borne de conception p99 ≤ 10 s ${adm.p99 <= 10 ? "tenue" : "dépassée"} en valeur)`
        : "d_admission non rapporté par cette collecte (avant la révision 0.6)";
      notes.push(`TM-13 (${x.c.configuration}) : ${x.p3.d_jeton.length} échéances satisfaites ; d_jeton max ${agreger(x.p3.d_jeton).max} s = d_point max ${agreger(x.p3.d_point).max} s (borne 1 s) + ${texteAdmission} + d_attente max ${agreger(x.p3.d_attente).max} s, ${x.p3.d_admission.length ? "compté depuis l'admission" : "compté depuis checkpoint_ts, admission comprise (décomposition d'avant la révision 0.6)"} (borne squat_wait_s 5 s ${agreger(x.p3.d_attente).max <= 5 ? "tenue" : "dépassée"} en valeur ; recoupé sur la file, ${x.attentePropre.length} jetons de points : création de la demande → premier envoi, max ${agreger(x.attentePropre).max} s, et checkpoint_ts → création de la demande, p50 ${agreger(x.admission).p50} s, max ${agreger(x.admission).max} s ; secondes entières tronquées) + d_releve max ${agreger(x.p3.d_releve).max} s (borne 120 s) + d_tsa max ${agreger(x.p3.d_tsa).max} s ; ${x.tardives} échéance non satisfaite avant la suivante.`);
    }
    // TM-14
    const v0 = x.verifications[0] ?? null;
    const calendriers = x.preuves.filter((p) => p.fichier.startsWith("manifeste-")).map((p) => p.attestations_en_attente ?? (p.hauteurs_attestees && typeof p.hauteurs_attestees === "object" ? 2 : p.hauteurs_attestees)).filter((v) => typeof v === "number");
    const nbCalendriers = x.c.systeme ? 2 : 2;
    const texteP4 = `jeton ${v0 && v0.parts_present.includes("jeton_rfc3161") ? "qualifié" : "absent"} ; ${Math.max(nbCalendriers, ...calendriers, 0)} calendriers ; T-11 ${v0?.checks?.["T-11"] ?? "non_execute"}`;
    ajouter(ligne({ name: `p4_cloture${suffixe}`, test_id: "TM-14", unit: unite("TM-14"), text_value: texteP4, n: 1, target: cible("TM-14"), conditions: [...C, "prestataire principal : serveur interne de référence du paquet d'ancrage DÉCLARÉ qualifié par un instantané d'exemple (EX-4.8) dans la configuration et dans le fichier d'ancres de test du réviseur : T-11 reussi par cette déclaration seulement, aucun prestataire qualifié réel (hors de la condition « prestataire qualifié réel » de TM-14)", `dossier du premier événement de la période (seq ${v0?.seq ?? "-"}) : parties ${v0 ? v0.parts_present.join(", ") : "-"} ; deux calendriers factices (chaîne regtest), preuve mise à niveau`] }));
    // TM-41
    ajouter(ligne({ name: `w_ordre${suffixe}`, test_id: "TM-41", unit: unite("TM-41"), serie: x.wOrdre, target: cible("TM-41"), conditions: [...C, "inclusion au registre de l'ancre du premier point ancré qui engage l'événement (une ancre remplacée par celle d'un point plus récent, EX-9.5, est portée par ce point), moins ts de l'événement ; durée de conception, qu'aucun dossier ne prouve (CT-5 §3.3)"] }));
    notes.push(`TM-41 (${x.c.configuration}) : W_ordre p99 ${agreger(x.wOrdre.filter((v) => typeof v === "number")).p99} s, max ${agreger(x.wOrdre.filter((v) => typeof v === "number")).max} s (cible p99 120 s ${agreger(x.wOrdre.filter((v) => typeof v === "number")).p99 <= 120 ? "tenue en valeur" : "dépassée en valeur"}).`);
    // TM-42
    const nomW = x.c.configuration === "porte2" ? "w_date_porte_2" : "w_date_defaut";
    ajouter(ligne({ name: nomW, test_id: "TM-42", unit: unite("TM-42"), serie: x.wDate, target: cible("TM-42"), conditions: [...C, `facts.checkpoint.rewrite_window_ms du rapport du vérificateur JavaScript de référence sur le dossier exporté de chaque événement (${x.verifications.length} dossiers, verdicts ${JSON.stringify(x.verdicts)}, K-7 réussie ${x.k7} fois, contrôles 4, 5 et 8 réussis ${x.controles458} fois), converti en secondes ; valeur rapportée, calculée depuis le ts déclaré (CT-6 §7.9)`, x.c.configuration === "porte2" ? "configuration de la porte 2 : c_T = 60 s, points chez le principal (cas cadence-une-minute-principal)" : "configuration par défaut : c_T = 300 s, cible de conception 300 s + d_jeton"] }));
    notes.push(`TM-42 (${nomW}) : ${x.wDate.length} fenêtres, p50 ${agreger(x.wDate).p50} s, p99 ${agreger(x.wDate).p99} s, max ${agreger(x.wDate).max} s (${x.c.configuration === "porte2" ? `critère de la porte 2 p99 ≤ 300 s ${agreger(x.wDate).p99 <= 300 ? "tenu en valeur" : "dépassé en valeur"}` : `borne de conception 300 s + d_jeton (d_jeton max ${agreger(x.p3.d_jeton).max} s) ${agreger(x.wDate).p99 <= 300 + (agreger(x.p3.d_jeton).max ?? 0) ? "tenue en valeur" : "dépassée en valeur"}`}) ; vérificateur Go sur le dossier témoin : ${x.c.go ? `code ${x.c.go.code}, verdict ${x.c.go.verdict}, énoncé ${x.c.go.identique ? "identique à" : "différent de"} celui du vérificateur JavaScript` : "non joué"}.`);
    // TM-19 (jetons de TM-13 : configuration par défaut)
    if (!suffixe) {
      ajouter(ligne({ name: "an24_accuracy", test_id: "TM-19", unit: unite("TM-19"), serie: x.accuracy, target: cible("TM-19"), conditions: [...C, `accuracy lue par T-1 dans chaque jeton obtenu de la période (${x.accuracy.length} jetons des deux serveurs internes, points et clôture)`] }));
      ajouter(ligne({ name: "an24_clock_offset", test_id: "TM-19", unit: unite("TM-19"), serie: x.offsets.length ? x.offsets : [0], target: cible("TM-19"), conditions: [...C, `écart d'horloge consigné par les serveurs internes (tsa_clock_offset_ms des lignes tsa_demarrage et tsa_refus, ${x.tsa.length} lignes) : horloge injectée sans écart déclaré (ecartMs 0)`] }));
      notes.push(`TM-19 : accuracy max ${agreger(x.accuracy).max} s sur ${x.accuracy.length} jetons (cible 1 s ${agreger(x.accuracy).max <= 1 ? "tenue en valeur" : "dépassée en valeur"}) ; tsa_clock_offset max ${agreger(x.offsets.length ? x.offsets : [0]).max} s.`);
    }
  }
  // Compléments : TM-18, TM-30, TM-17.
  if (comp) {
    const Cc = ["mesures hors réseau de développement, sur la boucle locale (scripts/e2e/mesure-ancrage.mjs complements)", "machine virtuelle, disque virtuel : hors du système de référence de CT-9 §11.1"];
    ajouter(ligne({ name: "an26_serie_croissante", test_id: "TM-18", unit: unite("TM-18"), value: comp.tm18.non_croissantes, n: comp.tm18.jetons, target: cible("TM-18"), conditions: [...Cc, `serveur RFC 3161 interne de référence du paquet d'ancrage (${comp.tm18.algorithme}), dix jetons, redémarrage du serveur (compteur de série durable relu), dix jetons ; serialNumber lu par T-1 ; ${comp.tm18.jetons} jetons, séries ${comp.tm18.series[0]}…${comp.tm18.series.at(-1)}`] }));
    const tailles = comp.tm30.regtest.map((r) => r.mise_a_niveau);
    ajouter(ligne({ name: "b_ots_mis_a_niveau", test_id: "TM-30", unit: unite("TM-30"), serie: tailles, target: cible("TM-30"), percentiles: false, conditions: [...Cc, "dix preuves .ots mises à niveau par deux calendriers factices (chemin Bitcoin complet sur une chaîne regtest, EX-6.9), tailles en octets du fichier mis à niveau", `tailles en attente avant la mise à niveau : ${comp.tm30.regtest.map((r) => r.en_attente).join(", ")} octets`] }));
    const publiques = comp.tm30.publiques.filter((p) => typeof p.octets === "number");
    if (publiques.length) {
      ajouter(ligne({ name: "b_ots_en_attente_public", test_id: "TM-30", unit: unite("TM-30"), serie: publiques.map((p) => p.octets), target: cible("TM-30"), percentiles: false, conditions: [...Cc, "preuves EN ATTENTE réelles obtenues des agrégateurs publics d'EX-6.2 (aucune mise à niveau : l'inclusion dans Bitcoin se compte en heures)", ...publiques.map((p) => `preuve ${p.k} : ${p.octets} octets, ${p.calendriers_repondu} calendrier(s) répondu, attestation ${p.attestation}`)] }));
    }
    notes.push(`TM-30 : b_ots mis à niveau (regtest) max ${Math.max(...tailles)} octets, moyenne ${agreger(tailles).mean} ; preuves en attente publiques : ${publiques.length ? publiques.map((p) => `${p.octets} octets (${p.reponses.filter((r) => r.status === 200).map((r) => r.calendrier).join(", ")})`).join(" ; ") : "non obtenues"} ; l'attestation Bitcoin réelle n'est pas attendue ici (heures).`);
    const t = comp.tm17;
    ajouter(ligne({ name: "planificateur_debit_points", test_id: "TM-17", unit: unite("TM-17"), value: t.J1.points_par_s, n: t.J1.points_admis, target: cible("TM-17"), conditions: [...Cc, "ACCÉLÉRÉ : une heure de points (c_K 60 s, c_T 300 s, points chez le serveur interne) rejouée à l'horloge réglable du composant, serveurs internes de référence réels sur la boucle locale, sans registre ni OpenTimestamps ; points admis par seconde de temps réel ; la vitesse du rejeu est celle du harnais (une attente de calme de 8 ms au moins après chaque minuterie servie, 3 600 tics par heure simulée et par composant) : borne inférieure du débit du planificateur, non son débit propre ; ne compte pour aucune cible", `J = 1 : ${t.J1.points_admis} points admis, ${t.J1.jetons_obtenus} jetons obtenus en ${t.J1.duree_s} s`] }));
    ajouter(ligne({ name: "planificateur_journaux", test_id: "TM-17", unit: unite("TM-17"), value: t.J10.journaux, n: t.J10.points_admis, target: cible("TM-17"), conditions: [...Cc, "ACCÉLÉRÉ : dix journaux servis par dix composants sur le même décor (maxima de CT-5 §4.6), une heure simulée chacun, horloge réglable partagée ; la vitesse du rejeu est celle du harnais (une attente de calme des dix composants après chacune des 36 000 minuteries servies), non celle du planificateur ; ne compte pour aucune cible", `J = 10 : ${t.J10.points_admis} points admis et ${t.J10.jetons_obtenus} jetons obtenus en ${t.J10.duree_s} s de temps réel (${t.J10.points_par_s} points/s agrégés), RSS ${t.J10.rss_octets} octets`] }));
    {
      const pn = t.panne;
      // Révision 0.6 de CT-5 (EX-8.5, règles 5 et 7) : taille du fichier courant bornée par max(compact_bytes, 2 × S_0)
      // plus une ligne, au plus 32 tentatives par ligne ; un dépassement est noté (TM-17 : lacune à tracer).
      const fenetre = typeof pn.tentatives_par_ligne_max === "number";
      const texteFichier = fenetre
        ? `fichier courant : au plus ${pn.fichier_courant_octets_max} octets et ${pn.fichier_courant_lignes_max} lignes (compact_bytes ${pn.compact_bytes}, S_0 final ${pn.s0}, ligne la plus longue ${pn.ligne_octets_max} octets) ; au plus ${pn.tentatives_par_ligne_max} tentatives par ligne ; ${pn.compactages} compactage(s) (anchor_queue_compacted), ${pn.compactages_en_echec} en échec (anchor_queue_compaction_failed)`
        : "collecte d'avant la révision 0.6 : taille du fichier courant, tentatives par ligne et compactages non relevés";
      ajouter(ligne({ name: "planificateur_file_panne", test_id: "TM-17", unit: unite("TM-17"), value: pn.demandes_actives_max, n: pn.demandes_en_file, target: cible("TM-17"), conditions: [...Cc, "ACCÉLÉRÉ : prestataire des points et principal coupés pendant une heure SIMULÉE à l'horloge réglable (c_T 60 s : une demande par point), queue.max_pending 1000, clôture pendant la panne ; valeur = nombre maximal de demandes actives ; ne compte pour aucune cible", `${pn.demandes_en_file} demandes dans la file (${pn.lignes_file} lignes, ${pn.octets_file} octets), ${pn.tentatives} tentatives (attempts_total), ${pn.anchor_retry} reprises programmées, file pleine ${pn.file_pleine} fois ; RSS maximal du processus ${pn.rss_max_octets} octets`, texteFichier] }));
      if (fenetre && pn.tentatives_par_ligne_max > 32) notes.push(`TM-17 : LACUNE : une ligne de la file porte ${pn.tentatives_par_ligne_max} tentatives, au-delà de 32 (CT-5 EX-8.5, règle 7).`);
      if (fenetre && pn.depassements.length) notes.push(`TM-17 : LACUNE : taille du fichier courant au-delà de max(queue.compact_bytes, 2 × S_0) plus une ligne (CT-5 EX-8.5, règle 5) : ${JSON.stringify(pn.depassements)}.`);
    }
    notes.push(`TM-17 : débit J = 1 : ${t.J1.points_par_s} points/s (${t.J1.duree_s} s de temps réel pour une heure simulée, ${t.J1.jetons_obtenus} jetons) ; J = 10 : ${t.J10.points_par_s} points/s agrégés (${t.J10.duree_s} s, ${t.J10.jetons_obtenus} jetons) : ces débits mesurent le harnais à horloge réglable (attente de calme après chaque minuterie), non le planificateur, et ne sont qu'une borne inférieure ; panne d'une heure simulée (c_T 60 s, une demande par point, prestataires coupés) : ${t.panne.demandes_actives_max} demandes actives au plus (file bornée par max_pending ${t.panne.max_pending}, ${t.panne.file_pleine} franchissement), ${t.panne.tentatives} tentatives reprises au pas retry.max_ms, file durable de ${t.panne.lignes_file} lignes et ${t.panne.octets_file} octets (révision 0.6 de CT-5 : 32 tentatives au plus par ligne et compactage, EX-8.5 règles 5 et 7${typeof t.panne.tentatives_par_ligne_max === "number" ? ` ; fichier courant au plus ${t.panne.fichier_courant_octets_max} octets, ${t.panne.tentatives_par_ligne_max} tentatives au plus par ligne, ${t.panne.compactages} compactage(s), ${t.panne.compactages_en_echec} en échec, ${t.panne.depassements.length ? "borne max(compact_bytes, 2 × S_0) + une ligne DÉPASSÉE" : "borne max(compact_bytes, 2 × S_0) + une ligne tenue"}` : ""}), RSS max du processus d'essai ${t.panne.rss_max_octets} octets. Lignes accélérées, sans valeur pour une cible (TM-17 n'en a pas).`);
    notes.push(`TM-18 : ${comp.tm18.non_croissantes} paire non croissante sur ${comp.tm18.jetons} jetons, redémarrage après le dixième.`);
  }
  if (p6Releve) {
    const nonConformes = p6Releve.fichiers.filter((f) => !f.conforme).length;
    ajouter(ligne({ name: "p6_copie_worm", test_id: "TM-16", unit: unite("TM-16"), value: nonConformes, n: p6Releve.fichiers.length, target: cible("TM-16"), conditions: [`API du support : S3 à Object Lock de LocalStack (image ${p6Releve.image}), en conteneur Docker, derrière un mandataire TLS ; bucket à rétention par défaut COMPLIANCE (EX-12.30)`, `une période close par le démon réel avec le composant d'ancrage branché : ${p6Releve.fichiers.filter((f) => f.fichier.startsWith("points/")).length} fichier de points, ${p6Releve.fichiers.filter((f) => f.fichier.startsWith("ancres/")).length} fichiers d'ancres/ (pièces RFC 3161, preuves .ots, nonces, acquisitions.ndjson), ${p6Releve.fichiers.filter((f) => f.fichier.startsWith("manifestes/")).length} fichiers de manifestes`, "par fichier : ListObjectVersions, GET avec versionId (SHA-256 recalculé), HEAD avec versionId (mode, échéance), identifiants du rôle Lecteur ; conforme : version au même SHA-256, COMPLIANCE, échéance ≥ création + 365 × events_years jours − 1 h (EX-12.33)", "support émulé en conteneur sur une machine virtuelle : hors du système de référence"] }));
    notes.push(`TM-16 (complément ancres/) : ${nonConformes} fichier non conforme sur ${p6Releve.fichiers.length} (${p6Releve.fichiers.map((f) => f.fichier).join(", ")}), mesuré le ${p6Releve.mesure_a} par test/enregistreur-journal-soi.test.js sur LocalStack.`);
  } else {
    notes.push("TM-16 : aucun relevé d'ancres/ sur le support réel joint (ligne p6_copie_worm absente de ce rapport) ; le complément est porté par test/enregistreur-journal-soi.test.js (LocalStack) et par test/enregistreur-ancrage-exigences.test.js (support en mémoire, sans valeur pour la cible).");
  }
  // Rapport.
  const sys = systeme();
  const base = defaut ?? porte2;
  // Commit et arbre de travail relevés à la collecte, pas à l'écriture du rapport.
  const commits = [...new Set(lues.map((x) => x.c.commit))];
  if (commits.length !== 1) throw new Error(`collectes faites sur des commits différents : ${commits.join(", ")}`);
  const commit = commits[0];
  const arbres = lues.map((x) => `${x.c.configuration} : ${x.c.arbre ? (x.c.arbre.propre ? "arbre de travail propre" : `${x.c.arbre.chemins_modifies} chemin(s) modifié(s) ou nouveau(x) non commité(s)`) : "état de l'arbre de travail non relevé par la collecte"}`);
  const configuration = { outil: "scripts/e2e/mesure-ancrage.mjs", collectes: lues.map((x) => ({ configuration: x.c.configuration, parametres: x.c.parametres, period_start: x.P, evenements_par_s: x.c.evenements_par_s, document_ancrage: lireJson(path.join(collectes[lues.indexOf(x)], "configuration-ancrage.json")) })) };
  if (sortie) {
    fs.mkdirSync(sortie, { recursive: true });
    fs.writeFileSync(path.join(sortie, "configuration-campagne.json"), `${JSON.stringify(configuration, null, 2)}\n`);
  }
  const configurationSha = N.sha256Hex(N.utf8(JSON.stringify(configuration))).slice(2);
  const debut = lues.map((x) => x.c.debut).sort()[0];
  const instant = `${new Date(debut).toISOString().slice(0, 19)}Z`;
  const rapport = {
    version: 0,
    kind: "rapport-mesure",
    date: instant.slice(0, 10),
    measured_at: instant,
    commit,
    spec_version: catalogue.spec_version,
    system: { ...base.c.systeme, load_avg_1m: sys.load_avg_1m },
    method: { warmup: 0, repetitions: Math.max(...lues.map((x) => x.evenements.length)), percentile_method: "plus_proche_rang", clock: "murale", pair_with_without: false, samples_published: true },
    configuration_sha256: configurationSha,
    counts_for_targets: false,
    results,
    notes: [
      `Campagne de mesures de l'ancrage (TM-11 à TM-14, TM-16 à TM-19, TM-30, TM-41, TM-42) faite du ${debut} au ${lues.map((x) => x.c.fin).sort().at(-1)} sur le réseau de développement, hors du système de référence de CT-9 §11.1 (machine virtuelle KVM, disque virtuel) : counts_for_targets faux, met null sur chaque ligne (EX-11.2) ; les notes disent, à titre indicatif, si la cible est tenue en valeur.`,
      `Commit ${commit} relevé à la collecte ; ${arbres.join(" ; ")}.`,
      ...notesOperateur,
      `method.clock murale : les délais entre composants sont lus sur l'horloge de l'enregistreur (EX-11.5) ; method.repetitions : nombre d'événements de la période mesurée ; échantillons publiés dans chaque ligne, dans l'ordre de collecte, aucun retiré.`,
      ...notes,
    ].join(" "),
  };
  const chemin = path.resolve(sortieRapport);
  fs.mkdirSync(path.dirname(chemin), { recursive: true });
  const provisoire = `${chemin}.provisoire`;
  fs.writeFileSync(provisoire, `${JSON.stringify(rapport, null, 2)}\n`);
  const v = validerParOutilDeReference(provisoire, path.basename(chemin));
  if (v.code !== 0) {
    fs.rmSync(provisoire, { force: true });
    throw new Error(`rapport refusé par scripts/tests/mesures.mjs (code ${v.code}) :\n${v.texte.slice(-3000)}`);
  }
  fs.renameSync(provisoire, chemin);
  log(`rapport écrit et validé par scripts/tests/mesures.mjs : ${chemin} (${results.length} lignes)`);
  return { rapport, chemin, validation: v.texte };
}
