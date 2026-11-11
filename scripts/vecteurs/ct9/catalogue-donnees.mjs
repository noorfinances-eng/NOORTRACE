// Source de données du catalogue de CT-9 (spec/CT-9-plan-de-tests.md, EX-4.5)
// et construction du catalogue (schéma plan-de-tests-v0, racine) à partir :
//
//   - des modules donnees/*.mjs : en-tête, niveaux et étapes (racine.mjs),
//     entrées TU-, TV-, TI-, TE-, TM-, TR-, TQ- telles qu'imprimées, membres
//     propres des TA- et des cinq scénarios (ta.mjs), ordre et colonne
//     « non testé » des risques acceptés (risques.mjs), justifications NC- (nc.mjs),
//     réponses aux occurrences de « CT-9 » (tc.mjs) ;
//   - de spec/vecteurs/ct-7/menaces.json, lu par le générateur : menace,
//     composant, `covers` (response.refs), `threat_test_text` (test) et risque
//     accepté de chaque TA-1 à TA-102 (EX-10.2), nom, borne, porteur et menace
//     de chaque risque accepté ;
//   - des occurrences de « CT-9 » relues dans spec/*.md (0.2), auxquelles les
//     réponses de tc.mjs sont appariées rang par rang (même clé exigée).
//
// Rien n'est lu ni écrit ici : construireCatalogue() reçoit ce que le
// générateur a lu et rend l'objet catalogue ou lève une erreur nommée.

import { META, LEVELS, PHASE2_STEPS } from "./donnees/racine.mjs";
import { TU } from "./donnees/tu.mjs";
import { TV } from "./donnees/tv.mjs";
import { TI } from "./donnees/ti.mjs";
import { TE } from "./donnees/te.mjs";
import { TA, SCENARIOS } from "./donnees/ta.mjs";
import { TM } from "./donnees/tm.mjs";
import { TR } from "./donnees/tr.mjs";
import { TQ } from "./donnees/tq.mjs";
import { RISQUES_ACCEPTES } from "./donnees/risques.mjs";
import { NON_TESTS } from "./donnees/nc.mjs";
import { TC_REPONSES } from "./donnees/tc.mjs";

export { META, LEVELS, PHASE2_STEPS, TU, TV, TI, TE, TA, SCENARIOS, TM, TR, TQ, RISQUES_ACCEPTES, NON_TESTS, TC_REPONSES };

/** Blocage des entrées rattachées à l'étape 8 par la démonstration de référence (10.5). */
export const BLOCAGE_ETAPE_8 = "Démonstration de référence et tests de bout en bout : phase 2, étape 8.";

/** Commande d'un fichier de test cité (EX-3.10) ; plusieurs fichiers sont joints par « && ». */
export const commandeDe = (fichier) => fichier === "test/adversarial.test.js" ? "npx mocha --timeout 600000 test/adversarial.test.js" : `npx hardhat --config hardhat.config.mjs test ${fichier}`;

/** Spécifications visées, déduites de `covers`, dans l'ordre CT-1 à CT-8 (EX-4.1) ; une entrée sans `covers` garde ses `specs` écrites. */
export const specsDe = (covers) => [...new Set(covers.map((c) => c.split(" ")[0]))].sort((x, y) => Number(x.slice(3)) - Number(y.slice(3)));

const uniq = (a) => a.filter((v, i) => a.indexOf(v) === i);

/**
 * État d'une entrée tel que le catalogue le porte (EX-3.10). Pour un état
 * `executable` qui cite des fichiers de test, `command` est reconstruite depuis
 * ces fichiers (règle (d), EX-3.10 : « s'exécute par la commande citée ») ;
 * une entrée qui ne cite que des étapes de CI garde la commande écrite.
 */
export function normaliserStatut(s) {
  if (s.state !== "executable") return s;
  const out = { state: "executable" };
  if (s.tests) out.tests = s.tests;
  if (s.ci_steps) out.ci_steps = s.ci_steps;
  const complete = s.command && (s.tests ?? []).every((x) => s.command.includes(x.file));
  out.command = s.tests && !complete ? uniq(s.tests.map((x) => x.file)).map(commandeDe).join(" && ") : s.command;
  if (s.complement) out.complement = s.complement;
  if (s.depends_on) out.depends_on = s.depends_on;
  return out;
}

/**
 * Construit le catalogue.
 *   menaces      contenu de spec/vecteurs/ct-7/menaces.json ;
 *   occurrences  occurrences de « CT-9 » ([{ key, line }], ordre des fichiers
 *                puis des lignes, procédé de 0.2).
 * Lève une erreur si une menace n'a pas son TA-n, si un TA- n'a pas de menace,
 * si deux entrées portent le même identifiant, si les numéros d'une famille
 * ne se suivent pas, si un risque accepté de menaces.json manque ou est en
 * trop, ou si une occurrence n'a pas de réponse à son rang (ou l'inverse).
 */
export function construireCatalogue({ menaces, occurrences }) {
  const erreurs = [];
  const MN = new Map(menaces.threats.map((t) => [t.id, t]));

  // TA-1 à TA-102 : menace, composant, covers, texte de test et risque accepté viennent de menaces.json.
  const ta = TA.map((d) => {
    const n = /^TA-([0-9]+)$/.exec(d.id)?.[1];
    const m = MN.get(`MN-${n}`);
    if (!m) { erreurs.push(`${d.id} : aucune menace MN-${n} dans menaces.json`); return null; }
    const covers = [...m.response.refs];
    const status = normaliserStatut(d.status);
    const o = {
      id: d.id, level: "TA", title: `Réponse retirée : ${d.response_removed.what}`, specs: specsDe(covers), covers,
      preconditions: d.preconditions, steps: d.steps, oracle: d.oracle, status, threats: [m.id],
      adversarial: {
        threat: m.id, component: m.component, response_removed: d.response_removed, attack: d.attack,
        expected_with_response: d.expected_with_response, expected_without_response: d.expected_without_response,
        execution: d.execution, accepted_risk: m.residual?.accepted_risk?.id ?? null, threat_test_text: m.test,
      },
    };
    if (d.notes) o.notes = d.notes;
    return o;
  }).filter(Boolean);
  for (const id of MN.keys()) if (!ta.some((t) => t.adversarial.threat === id)) erreurs.push(`${id} : aucune entrée TA-${id.slice(3)} dans la source de données`);

  // Scénarios du plan (10.5) : composition de TA-, covers en union, menaces des composés.
  const scenarios = SCENARIOS.map((s) => {
    const composes = s.composition.map((id) => ta.find((t) => t.id === id));
    if (composes.some((c) => !c)) { erreurs.push(`${s.id} : composition citant un TA- inconnu`); return null; }
    const covers = uniq(composes.flatMap((t) => t.covers));
    const threats = composes.map((t) => t.threats[0]);
    return {
      id: s.id, level: "TA", title: `Scénario du plan : ${s.scenario} (${s.composition.join(", ")})`, specs: specsDe(covers), covers,
      preconditions: s.preconditions, steps: s.steps, oracle: s.oracle,
      status: { state: "a_ecrire", phase2_step: s.phase2_step, blocking: BLOCAGE_ETAPE_8 }, threats,
      adversarial: {
        threat: null, component: null,
        response_removed: {
          what: `Les réponses des menaces composées (${threats.join(", ")}), telles que les tests ${s.composition.join(", ")} les nomment`,
          how: "Rejouer, une à la fois, la réponse retirée de chaque test composé dans la démonstration de référence ; le scénario se joue aussi avec toutes les réponses en place",
          where: "démonstration de référence de CT-2 §19 (phase 2, étape 8) et bibliothèques de référence des tests composés",
        },
        attack: s.attack, expected_with_response: s.oracle,
        expected_without_response: s.expected_without_response,
        execution: "phase_2", accepted_risk: null, threat_test_text: null, composition: s.composition,
      },
    };
  }).filter(Boolean);

  // Risques acceptés (10.6) : nom, borne, porteur et menace de menaces.json ; ordre et « non testé » de la source.
  const raMenaces = new Map(menaces.threats.filter((t) => t.residual?.accepted_risk).map((t) => [t.residual.accepted_risk.id, { ...t.residual.accepted_risk, threat: t.id }]));
  const accepted_risks = RISQUES_ACCEPTES.map((r) => {
    const m = raMenaces.get(r.id);
    if (!m) { erreurs.push(`${r.id} : absent de menaces.json`); return null; }
    const test = ta.find((t) => t.adversarial.threat === m.threat);
    if (!test) { erreurs.push(`${r.id} : menace ${m.threat} sans TA-`); return null; }
    const a = test.adversarial;
    const o = {
      id: r.id, name: m.name, bound: m.bound, owner: m.owner, threat: m.threat, test: test.id, test_state: test.status.state,
      tested: `${test.id} éprouve la réponse qui borne le risque (${a.response_removed.what}) : avec elle, ${a.expected_with_response.replace(/\.$/, "")} ; sans elle, le test échoue.`,
      not_tested: r.not_tested,
    };
    if (r.measured_by) o.measured_by = r.measured_by;
    return o;
  }).filter(Boolean);
  for (const id of raMenaces.keys()) if (!RISQUES_ACCEPTES.some((r) => r.id === id)) erreurs.push(`${id} : risque accepté de menaces.json sans ligne dans la source de données`);

  // Traçabilité (0.2) : une ligne par occurrence, réponse au même rang.
  const traceability = [];
  const n = Math.max(occurrences.length, TC_REPONSES.length);
  for (let i = 0; i < n; i++) {
    const o = occurrences[i];
    const r = TC_REPONSES[i];
    if (!o) { erreurs.push(`TC-${i + 1} : réponse « ${r.key} » sans occurrence de « CT-9 »`); continue; }
    if (!r) { erreurs.push(`TC-${i + 1} : occurrence « ${o.key} » (l. ${o.line}) sans réponse dans la source de données`); continue; }
    if (o.key !== r.key) { erreurs.push(`TC-${i + 1} : occurrence « ${o.key} » (l. ${o.line}) mais réponse « ${r.key} »`); continue; }
    traceability.push({ id: `TC-${i + 1}`, key: o.key, line: o.line, delegated: r.delegated, response: r.response });
  }

  // Entrées dans l'ordre du texte ; numérotation sans trou par famille (EX-3.1).
  // `specs` est déduit de `covers` pour toute entrée qui en a (EX-4.1) ; la commande des entrées exécutables suit la règle (d).
  const normaliser = (t) => ({ ...t, specs: t.covers.length ? specsDe(t.covers) : t.specs, status: normaliserStatut(t.status) });
  const tests = [...TU, ...TV, ...TI, ...TE, ...ta, ...scenarios, ...TM, ...TR, ...TQ].map(normaliser);
  const compteurs = {};
  const vus = new Set();
  for (const t of tests) {
    compteurs[t.level] = (compteurs[t.level] ?? 0) + 1;
    if (t.id !== `${t.level}-${compteurs[t.level]}`) erreurs.push(`${t.id} : attendu ${t.level}-${compteurs[t.level]}`);
    if (vus.has(t.id)) erreurs.push(`${t.id} : identifiant en double`);
    vus.add(t.id);
  }
  if (erreurs.length) throw new Error(`source de données du catalogue :\n - ${erreurs.join("\n - ")}`);
  return { ...META, levels: LEVELS, phase2_steps: PHASE2_STEPS, tests, non_tests: NON_TESTS, accepted_risks, traceability };
}
