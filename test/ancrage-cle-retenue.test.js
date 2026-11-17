// CT-5 (complément du 2026-11-16) : six passages que le texte ne tranchait pas encore, écrits selon le comportement
// sûr de la référence (scripts/lib/ancrage.mjs) et du composant d'ancrage (paquets/ancrage).
//
// 1. EX-9.4 : une ancre de période qui n'a ni son reçu ni un autre état final retient sa clé : aucune ancre d'une
//    période postérieure ne part avant elle, à sa création, à l'échéance de sa reprise ni quand la clé se libère.
//    Avant : les deux implémentations ne retenaient la clé que lorsque l'ancre de la période, attendant ses points,
//    était la première candidate à la libération ; l'ancre d'un point de la période suivante partait dès que la clé
//    n'avait plus d'ancre en vol, et l'ancre de la période suivante aussi, avant celle de la période qui attendait
//    (trace registre-periode-retient-la-cle ; traces de travail ci-dessous).
// 2. EX-9.4 et EX-8.12, point 6 : une ancre a_reprendre dont l'échéance est passée pendant l'arrêt n'est pas candidate
//    au point 6 (la passe a programmé sa reprise) ; elle part au point 7.
// 3. AN-36 et A.4 : deux invariants d'EX-9.4 vérifiés sur la trace (violationsAncrePeriode, violationsCleRetenue).
// 4. A.4 (AN-37) : ordre d'une action et d'une entrée du même instant, pour savoir si une réponse des calendriers
//    s'applique ; la lecture rend le verdict de la référence, et ses deux variantes ne le rendent pas.
// 5. EX-8.11 : soumission OpenTimestamps aboutie au-delà de give_up_after_s après created_at : ots_give_up dès la preuve
//    en attente (avant : à la réponse de la première mise à niveau), première mise à niveau à first_after_s.
// 6. EX-8.10 : l'alerte du refus définitif de l'ancre d'une période est levée de nouveau après un redémarrage.
//
// Les vecteurs sont lus dans le dépôt ; le code est lu dans le dépôt, ou sous NOORTRACE_REVUE_RACINE (code d'avant :
// essai rouge). Les mutants sont des copies sous NOORTRACE_TMP (défaut os.tmpdir()), détruites à la fin.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { MODES, contexte, confronterParcours, violationsAncrePeriode } from "./fixtures/ancrage-confrontation/parcours.mjs";

const DEPOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : DEPOT;
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const CT5 = path.join(DEPOT, "spec", "vecteurs", "ct-5");
const PLANIFICATEUR = "paquets/ancrage/src/planificateur/planificateur.mjs";
const COPIES = [];
const trace = (id) => JSON.parse(fs.readFileSync(path.join(CT5, "planification", `${id}.json`), "utf8"));
const unique = () => `?t=${Date.now()}-${Math.random()}`;
const NOUVELLES = ["registre-periode-retient-la-cle", "redemarrage-ots-abandon-soumission-tardive", "registre-refus-ancre-periode-redemarrage"];
const ETATS_FINAUX = new Set(["obtenue", "complete", "sans_objet", "refusee", "remplacee"]);

/** Copie de RACINE (scripts/lib et paquets/ancrage/src), un fichier modifié par des remplacements uniques ; rend sa racine. */
function copie(nom, sousArbre, fichier, paires) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-cle-retenue-${nom}-`));
  COPIES.push(racine);
  for (const s of ["scripts/lib", "paquets/ancrage/src"]) {
    fs.mkdirSync(path.join(racine, path.dirname(s)), { recursive: true });
    if (s === sousArbre) fs.cpSync(path.join(RACINE, s), path.join(racine, s), { recursive: true });
    else fs.symlinkSync(path.join(RACINE, s), path.join(racine, s));
  }
  for (const l of ["spec", "node_modules", "package.json"]) fs.symlinkSync(path.join(DEPOT, l), path.join(racine, l));
  const f = path.join(racine, fichier);
  let texte = fs.readFileSync(f, "utf8");
  for (const [ancien, nouveau] of paires) {
    expect(texte.split(ancien).length - 1, `copie ${nom} : « ${ancien.slice(0, 100)} »`).to.equal(1);
    texte = texte.replace(ancien, () => nouveau);
  }
  fs.writeFileSync(f, texte);
  return racine;
}
const mutantReference = (nom, paires) => copie(nom, "scripts/lib", "scripts/lib/ancrage.mjs", paires);
const mutantComposant = (nom, paires) => copie(nom, "paquets/ancrage/src", PLANIFICATEUR, paires);

async function modules(racine) {
  const u = unique();
  return {
    A: await import(pathToFileURL(path.join(racine, "scripts", "lib", "ancrage.mjs")).href + u),
    P: await import(pathToFileURL(path.join(racine, PLANIFICATEUR)).href + u),
    T: await import(pathToFileURL(path.join(racine, "paquets", "ancrage", "src", "planificateur", "traces.mjs")).href + u),
  };
}

/** Écarts de la référence (verifierTrace) et du composant (rejouerTrace) sur une trace. */
async function ecarts(t, racines = {}) {
  const A = (await modules(racines.R ?? RACINE)).A;
  const T = (await modules(racines.C ?? RACINE)).T;
  let r;
  try {
    r = A.verifierTrace(t).length;
  } catch (e) {
    r = `exception : ${e.message}`;
  }
  let c;
  try {
    c = T.rejouerTrace(t).ecarts.length;
  } catch (e) {
    c = `exception : ${e.message}`;
  }
  return { reference: r, composant: c };
}
const diverge = (n) => n !== 0;

/**
 * Second invariant d'AN-36 (EX-9.4, complément du 2026-11-16 : une ancre de période qui attend retient sa clé) : rend
 * les départs d'une ancre au registre (ligne `envoyee` écrite depuis un autre état) alors qu'une ancre de période de
 * même `org_id` et `journal_id` et de `period_start` plus petit n'était pas dans un état final. Ne lit que la trace.
 */
function violationsCleRetenue(queueBefore, actions, fileFinale) {
  const sujets = new Map();
  for (const d of [...queueBefore, ...fileFinale]) sujets.set(d.id, d.subject);
  const etats = new Map(queueBefore.map((d) => [d.id, d.state]));
  const violations = [];
  for (const [indice, a] of actions.entries()) {
    if (a.action !== "ecrire_file" || typeof a.request_id !== "string") continue;
    const avant = etats.get(a.request_id);
    etats.set(a.request_id, a.detail.state);
    if (!a.request_id.startsWith("ancre_registre_") || a.detail.state !== "envoyee" || avant === "envoyee") continue;
    const s = sujets.get(a.request_id);
    for (const [id, etat] of etats) {
      if (!id.startsWith("ancre_registre_periode:") || ETATS_FINAUX.has(etat)) continue;
      const sp = sujets.get(id);
      if (sp.org_id === s.org_id && sp.journal_id === s.journal_id && sp.period_start < s.period_start) violations.push({ indice, t: a.t, ancre: a.request_id, periode: id, etat });
    }
  }
  return violations;
}

/**
 * Lecture d'A.4 (AN-37, complément du 2026-11-16) : une tentative OpenTimestamps s'ouvre par une action soumettre_ots
 * ou mettre_a_niveau_ots de la demande (ou se lit en_cours dans queue_before) et se ferme à la première reponse_ots de
 * la demande qui suit, et, pour une soumission, au demarrage. Une action d'instant t précède l'entrée de même instant ;
 * un demarrage clôt d'abord les soumissions ouvertes. `variante` lit autrement (essai des deux règles d'ordre).
 * Rend, par réponse des calendriers, [instant, id, s'applique].
 */
function lectureAN37(t, variante = null) {
  const ouverte = new Map();
  for (const d of t.queue_before) {
    if (!d.kind.startsWith("ots_")) continue;
    const der = d.attempts.at(-1);
    if (der && der.outcome === "en_cours") ouverte.set(d.id, d.state === "en_attente" ? "mise_a_niveau" : "soumission");
  }
  const ouvrir = (a) => {
    if (a.action === "soumettre_ots") ouverte.set(a.request_id, "soumission");
    else if (a.action === "mettre_a_niveau_ots") ouverte.set(a.request_id, "mise_a_niveau");
  };
  const actions = t.expected;
  let j = 0;
  const verdicts = [];
  for (const e of t.inputs) {
    if (variante === "demarrage-apres") while (j < actions.length && actions[j].t <= e.t) ouvrir(actions[j++]);
    if (e.type === "demarrage") for (const [id, sorte] of [...ouverte]) if (sorte === "soumission") ouverte.delete(id);
    while (j < actions.length && (variante === "actions-apres" ? actions[j].t < e.t : actions[j].t <= e.t)) ouvrir(actions[j++]);
    if (e.type !== "reponse_ots") continue;
    verdicts.push([e.t, e.data.request_id, ouverte.has(e.data.request_id)]);
    ouverte.delete(e.data.request_id);
  }
  return verdicts;
}
/** Réponses des calendriers que la lecture et la référence (lignes tentative_close, demande_close, demande_inconnue) classent autrement. */
function ecartsAN37(t, variante = null) {
  const NON = new Set(["tentative_close", "demande_close", "demande_inconnue"]);
  const cle = (x, id) => `${x}|${id}`;
  const reponses = new Set(t.inputs.filter((e) => e.type === "reponse_ots").map((e) => cle(e.t, e.data.request_id)));
  const ref = new Map();
  for (const a of t.expected) {
    if (a.action !== "journaliser" || a.detail.event !== "anchor_response_rejected" || !NON.has(a.detail.error_code)) continue;
    const k = cle(a.t, a.request_id);
    if (reponses.has(k)) ref.set(k, (ref.get(k) ?? 0) + 1);
  }
  const lu = new Map();
  for (const [x, id, s] of lectureAN37(t, variante)) if (!s) lu.set(cle(x, id), (lu.get(cle(x, id)) ?? 0) + 1);
  return [...new Set([...ref.keys(), ...lu.keys()])].filter((k) => (ref.get(k) ?? 0) !== (lu.get(k) ?? 0));
}

// Constantes du journal de référence (A.2).
const C5 = JSON.parse(fs.readFileSync(path.join(CT5, "constantes.json"), "utf8")).reference_journal;
const periode = (n) => {
  const p = C5.periods.find((x) => x.index === n);
  return { org_id: C5.org_id, journal_id: C5.journal_id, period_start: p.period_start, period_hash: p.period_hash, generated_at: p.generated_at };
};
const point = (nom) => {
  const k = C5.checkpoints[nom];
  return { org_id: C5.org_id, journal_id: C5.journal_id, period_start: C5.periods.find((p) => p.index === k.period).period_start, tree_size: k.tree_size, checkpoint_hash: k.checkpoint_hash, checkpoint_ts: k.checkpoint_ts };
};
const AK = (nom) => `ancre_registre_point:${C5.checkpoints[nom].checkpoint_hash}`;
const AP = (n) => `ancre_registre_periode:${periode(n).period_hash}`;
const OP = (n) => `ots_periode:${periode(n).period_hash}`;
const E = (t, type, data = {}) => ({ t, type, data });
const inclusion = (t, id, b) => E(t, "inclusion_registre", { request_id: id, block_number: b, capture_sha256: "0x" + "ab".repeat(32) });
const echec = (t, id, code = "noeud_injoignable") => E(t, "echec_registre", { request_id: id, code });
const vide = (id, config, jitter_ms, queue_before, inputs) => ({ version: 0, id, description: "travail", config, jitter_ms, queue_before, inputs, expected: [], queue_after: [] });

/**
 * Traces de travail (non publiées). L'attendu est la suite de la référence du dépôt (la règle) ; le composant doit la
 * reproduire ; sous NOORTRACE_REVUE_RACINE, le code d'avant est confronté à elle.
 * - `reprise` : K5 (période 2) part avant la clôture de la période 1, qui arrive tard, puis échoue ; l'ancre de la
 *   période 1 part, puis échoue ; à l'échéance de sa reprise, l'ancre de K5 est retenue ; elle part au reçu de la période.
 * - `cloture` : l'ancre de la période 1 échoue deux fois (reprise allongée) ; la période 2, sans ancre de point
 *   (`nouveaux_evenements`, points de tree_size 0), se clôt : son ancre est retenue jusqu'au reçu de celle de la période 1.
 * - `demarrage` : file de registre-periode-retient-la-cle arrêtée à 14:01:02 (ancre de la période 1 en reprise, ancre de
 *   K5 retenue) ; au démarrage, ni la passe ni le point 6 ne la font partir.
 * - `echue` (EX-8.12, point 6) : l'ancre de K4 échoue avant la clôture ; arrêt brutal juste après la ligne a_envoyer de
 *   la soumission OpenTimestamps ; au redémarrage, l'ancre de K4, échue pendant l'arrêt, part au point 7, après la
 *   soumission du point 6.
 */
function tracesDeTravail(A) {
  const t59 = trace("registre-periode-retient-la-cle");
  const defaut = trace("registre-refus-ancre-periode").config;
  const tous = { ...structuredClone(defaut), registry: { ...defaut.registry, checkpoints: "tous" } };
  const long = { ...structuredClone(t59.config), registry: { ...t59.config.registry, checkpoints: "nouveaux_evenements" } };
  const cas = {};
  cas.reprise = vide("travail-cle-retenue-reprise", tous, [11, 12], [], [
    E("2026-11-03T13:59:00.000Z", "demarrage"),
    E("2026-11-03T14:00:00.250Z", "point_produit", point("K4")),
    inclusion("2026-11-03T14:00:00.500Z", AK("K4"), 21500),
    E("2026-11-03T14:01:00.000Z", "point_produit", point("K5")),
    echec("2026-11-03T14:01:00.500Z", AK("K5")),
    E("2026-11-03T14:01:01.000Z", "periode_close", periode(1)),
    echec("2026-11-03T14:01:02.000Z", AP(1)),
    E("2026-11-03T14:01:05.511Z", "tic"),
    E("2026-11-03T14:01:07.012Z", "tic"),
    inclusion("2026-11-03T14:01:08.000Z", AP(1), 21501),
    inclusion("2026-11-03T14:01:09.000Z", AK("K5"), 21502),
    E("2026-11-03T14:01:30.000Z", "arret"),
  ]);
  cas.cloture = vide("travail-cle-retenue-cloture", long, [11, 12], [], [
    E("2026-11-03T13:59:00.000Z", "demarrage"),
    E("2026-11-03T14:00:00.250Z", "point_produit", point("K4")),
    E("2026-11-03T14:00:00.250Z", "periode_close", periode(1)),
    inclusion("2026-11-03T14:00:00.500Z", AK("K4"), 21500),
    echec("2026-11-03T14:00:01.000Z", AP(1)),
    E("2026-11-03T14:10:01.011Z", "tic"),
    echec("2026-11-03T14:10:02.000Z", AP(1)),
    E("2026-11-03T15:00:00.112Z", "periode_close", periode(2)),
    E("2026-11-03T15:50:02.012Z", "tic"),
    inclusion("2026-11-03T15:50:03.000Z", AP(1), 21600),
    inclusion("2026-11-03T15:50:04.000Z", AP(2), 21601),
    E("2026-11-03T15:51:00.000Z", "arret"),
  ]);
  const coupe = t59.inputs.findIndex((e) => e.t === "2026-11-03T14:01:01.000Z");
  const file59 = A.rejouerTrace({ ...t59, inputs: [...t59.inputs.slice(0, coupe + 1), E("2026-11-03T14:01:02.000Z", "arret")] }).file;
  cas.demarrage = vide("travail-cle-retenue-demarrage", t59.config, [], file59, [
    E("2026-11-03T14:05:00.000Z", "demarrage"),
    E("2026-11-03T14:11:01.137Z", "tic"),
    inclusion("2026-11-03T14:11:02.000Z", AP(1), 21700),
    inclusion("2026-11-03T14:11:03.000Z", AK("K5"), 21701),
    E("2026-11-03T14:11:30.000Z", "arret"),
  ]);
  const avant = A.rejouerTrace(vide("x", defaut, [11], [], [
    E("2026-11-03T13:59:00.000Z", "demarrage"),
    E("2026-11-03T14:00:00.250Z", "point_produit", point("K4")),
    echec("2026-11-03T14:00:00.300Z", AK("K4")),
    E("2026-11-03T14:00:00.400Z", "periode_close", periode(1)),
    E("2026-11-03T14:00:01.000Z", "arret"),
  ]));
  const n = avant.lignes.findIndex((l) => { const d = JSON.parse(l); return d.id === OP(1) && d.state === "a_envoyer"; });
  const lus = A.lireFile(avant.lignes.slice(0, n + 1).map((l) => l + "\n").join(""));
  cas.echue = vide("travail-a-reprendre-echue-au-demarrage", defaut, [], lus.demandes, [
    E("2026-11-03T14:00:30.000Z", "demarrage"),
    inclusion("2026-11-03T14:00:31.000Z", AK("K4"), 21800),
    inclusion("2026-11-03T14:00:32.000Z", AP(1), 21801),
    E("2026-11-03T14:01:00.000Z", "arret"),
  ]);
  for (const t of Object.values(cas)) {
    const r = A.rejouerTrace(t);
    t.expected = r.actions;
    t.queue_after = r.file;
  }
  return { cas, etatsEchue: lus.demandes.map((d) => [d.id, d.state]) };
}
const envois = (t) => t.expected.filter((a) => a.action === "envoyer_registre").map((a) => [a.t, a.request_id]);
const attentes = (t) => t.expected.filter((a) => a.action === "programmer" && a.detail.reason === "attente_nonce").map((a) => [a.t, a.request_id]);

after(function () {
  for (const r of COPIES) fs.rmSync(r, { recursive: true, force: true });
});

describe("CT-5 EX-9.4, EX-8.12, AN-36, AN-37, EX-8.11, EX-8.10 : six passages écrits selon le comportement sûr (complément du 2026-11-16)", function () {
  this.timeout(600000);

  for (const id of NOUVELLES) {
    it(`${id} : rejouée sans écart par la référence et par le composant`, async function () {
      expect(await ecarts(trace(id))).to.deep.equal({ reference: 0, composant: 0 });
    });
  }

  it("registre-periode-retient-la-cle : à l'échec de l'ancre de la période 1, la clé n'a plus d'ancre en vol mais rien ne part ; K6 et la période 2 attendent à leur création ; les envois suivent l'ordre des périodes", function () {
    const t = trace("registre-periode-retient-la-cle");
    expect(envois(t)).to.deep.equal([
      ["2026-11-03T14:00:00.250Z", AK("K4")],
      ["2026-11-03T14:00:01.000Z", AP(1)],
      ["2026-11-03T14:11:01.137Z", AP(1)],
      ["2026-11-03T15:51:02.041Z", AP(1)],
      ["2026-11-03T15:51:03.000Z", AK("K6")],
      ["2026-11-03T15:51:04.000Z", AP(2)],
    ]);
    expect(attentes(t)).to.deep.equal([
      ["2026-11-03T14:00:00.250Z", AP(1)],
      ["2026-11-03T14:01:00.000Z", AK("K5")],
      ["2026-11-03T15:00:00.112Z", AK("K6")],
      ["2026-11-03T15:00:02.000Z", AP(2)],
    ]);
    // À 15:00:00.112, aucune ancre n'est en vol : K6 n'attend que l'ancre de la période 1, en reprise.
    const etats = new Map();
    for (const a of t.expected) if (a.action === "ecrire_file" && a.t < "2026-11-03T15:00:00.112Z") etats.set(a.request_id, a.detail.state);
    expect([...etats].filter(([id, e]) => id.startsWith("ancre_registre_") && e === "envoyee")).to.deep.equal([]);
    expect(etats.get(AP(1))).to.equal("a_reprendre");
  });

  it("traces de travail (clé retenue à l'échéance d'une reprise, à la clôture de la période suivante, au démarrage ; ancre a_reprendre échue au démarrage) : les deux implémentations concordent et les deux invariants d'AN-36 tiennent", async function () {
    const { cas, etatsEchue } = tracesDeTravail((await modules(DEPOT)).A);
    expect(envois(cas.reprise)).to.deep.equal([["2026-11-03T14:00:00.250Z", AK("K4")], ["2026-11-03T14:01:00.000Z", AK("K5")], ["2026-11-03T14:01:01.000Z", AP(1)], ["2026-11-03T14:01:07.012Z", AP(1)], ["2026-11-03T14:01:08.000Z", AK("K5")]]);
    expect(attentes(cas.reprise)).to.deep.equal([["2026-11-03T14:01:05.511Z", AK("K5")]]);
    expect(envois(cas.cloture)).to.deep.equal([["2026-11-03T14:00:00.250Z", AK("K4")], ["2026-11-03T14:00:00.500Z", AP(1)], ["2026-11-03T14:10:01.011Z", AP(1)], ["2026-11-03T15:50:02.012Z", AP(1)], ["2026-11-03T15:50:03.000Z", AP(2)]]);
    expect(attentes(cas.cloture)).to.deep.equal([["2026-11-03T14:00:00.250Z", AP(1)], ["2026-11-03T15:00:00.112Z", AP(2)]]);
    // Démarrage : l'ancre de K5, a_envoyer et retenue, ne produit aucune action dans la passe ni au point 6.
    expect(cas.demarrage.queue_before.find((d) => d.id === AK("K5")).state).to.equal("a_envoyer");
    expect(cas.demarrage.expected.filter((a) => a.t === "2026-11-03T14:05:00.000Z" && a.request_id === AK("K5"))).to.deep.equal([]);
    expect(envois(cas.demarrage)).to.deep.equal([["2026-11-03T14:11:01.137Z", AP(1)], ["2026-11-03T14:11:02.000Z", AK("K5")]]);
    // A reprendre échue au démarrage (EX-8.12, point 6) : la soumission a_envoyer part au point 6, l'ancre de K4 au point 7.
    expect(etatsEchue).to.deep.include.members([[AK("K4"), "a_reprendre"], [AP(1), "a_envoyer"], [OP(1), "a_envoyer"]]);
    const debut = cas.echue.expected.filter((a) => a.t === "2026-11-03T14:00:30.000Z").map((a) => [a.action, a.request_id]);
    const iSoumission = debut.findIndex(([a, id]) => a === "soumettre_ots" && id === OP(1));
    const iK4 = debut.findIndex(([a, id]) => a === "envoyer_registre" && id === AK("K4"));
    expect(iSoumission).to.be.at.least(0);
    expect(iK4).to.be.above(iSoumission);
    for (const t of Object.values(cas)) {
      expect(violationsAncrePeriode(t.queue_before, t.expected, t.queue_after), t.id).to.deep.equal([]);
      expect(violationsCleRetenue(t.queue_before, t.expected, t.queue_after), t.id).to.deep.equal([]);
      expect(await ecarts(t), t.id).to.deep.equal({ reference: 0, composant: 0 });
    }
  });

  it("AN-36 : sur chacune des soixante-deux traces publiées, les deux invariants d'EX-9.4 tiennent ; le second signale l'ancre de la période 2 partie avant celle de la période 1 (suite d'avant de la trace de travail `cloture`)", async function () {
    const fichiers = fs.readdirSync(path.join(CT5, "planification")).filter((f) => f.endsWith(".json")).sort();
    // CT-5 A.3 (complément du 2026-11-16 : l'ancre d'un point en reprise quand le point suivant est admis, une trace de plus).
    expect(fichiers).to.have.lengthOf(62);
    for (const f of fichiers) {
      const t = JSON.parse(fs.readFileSync(path.join(CT5, "planification", f), "utf8"));
      expect(violationsAncrePeriode(t.queue_before, t.expected, t.queue_after), f).to.deep.equal([]);
      expect(violationsCleRetenue(t.queue_before, t.expected, t.queue_after), f).to.deep.equal([]);
    }
    const { cas } = tracesDeTravail((await modules(DEPOT)).A);
    const t = structuredClone(cas.cloture);
    // Suite d'avant : à la clôture de la période 2 (15:00:00.112), son ancre écrite envoyee.
    const i = t.expected.findIndex((a) => a.t === "2026-11-03T15:00:00.112Z" && a.action === "programmer" && a.request_id === AP(2));
    t.expected.splice(i, 1, { t: "2026-11-03T15:00:00.112Z", action: "ecrire_file", request_id: AP(2), detail: { state: "envoyee" } });
    const v = violationsCleRetenue(t.queue_before, t.expected, t.queue_after);
    expect(v.map((x) => [x.t, x.ancre, x.periode, x.etat])).to.deep.equal([["2026-11-03T15:00:00.112Z", AP(2), AP(1), "a_reprendre"]]);
  });

  it("A.4 (AN-37) : la lecture de l'ordre d'une action et d'une entrée du même instant rend, sur les soixante-deux traces et sur les segments de la confrontation (seize modes), le verdict de la référence pour chaque réponse des calendriers ; ses deux variantes ne le rendent pas", async function () {
    const traces = fs.readdirSync(path.join(CT5, "planification")).filter((f) => f.endsWith(".json")).map((f) => JSON.parse(fs.readFileSync(path.join(CT5, "planification", f), "utf8")));
    for (const t of traces) expect(ecartsAN37(t), t.id).to.deep.equal([]);
    // Segments de la confrontation : la référence est enveloppée pour garder, par segment, la file relue, les entrées et les actions.
    const M = await modules(RACINE);
    const segments = [];
    const A = {
      ...M.A,
      creerPlanificateur: (config, o) => {
        const ref = M.A.creerPlanificateur(config, o);
        const s = { queue_before: [], inputs: [], expected: [] };
        segments.push(s);
        const charger = ref.charger.bind(ref);
        const recevoir = ref.recevoir.bind(ref);
        ref.charger = (q) => {
          s.queue_before = structuredClone(q ?? []);
          return charger(q);
        };
        ref.recevoir = (e) => {
          s.inputs.push(e);
          const r = recevoir(e);
          s.expected.push(...r);
          return r;
        };
        return ref;
      },
    };
    const ctx = contexte({ ...M, A, vecteurs: CT5 });
    for (const mode of Object.keys(MODES)) for (let g = 9000; g < 9030; g++) expect(confronterParcours(ctx, g, mode), `${mode} ${g}`).to.equal(null);
    const reponses = segments.reduce((n, s) => n + s.inputs.filter((e) => e.type === "reponse_ots").length, 0);
    expect(reponses).to.be.above(1000);
    const lus = (variante) => segments.reduce((n, s) => n + ecartsAN37(s, variante).length, 0);
    expect(lus(null)).to.equal(0);
    expect(lus("actions-apres"), "actions d'un instant lues après l'entrée").to.be.above(0);
    expect(lus("demarrage-apres"), "démarrage lu après les actions de son instant").to.be.above(0);
  });

  it("redemarrage-ots-abandon-soumission-tardive : ots_give_up une fois, dès la preuve en attente (15:30:01), avant l'écriture en_attente ; première mise à niveau à first_after_s, la suivante un jour plus tard", function () {
    const t = trace("redemarrage-ots-abandon-soumission-tardive");
    expect(t.config.opentimestamps.upgrade).to.deep.equal({ first_after_s: 60, interval_s: 1800, give_up_after_s: 3600 });
    expect(t.expected.filter((a) => a.request_id === OP(1) && a.action === "alerter").map((a) => [a.t, a.detail.code])).to.deep.equal([["2026-11-03T15:30:01.000Z", "ots_give_up"]]);
    expect(t.expected.filter((a) => a.t === "2026-11-03T15:30:01.000Z" && a.request_id === OP(1)).map((a) => a.action)).to.deep.equal(["stocker", "alerter", "ecrire_file", "programmer"]);
    expect(t.expected.filter((a) => a.action === "mettre_a_niveau_ots").map((a) => a.t)).to.deep.equal(["2026-11-03T15:31:01.000Z"]);
    expect(t.queue_after.find((d) => d.id === OP(1))).to.include({ state: "en_attente", due_at: "2026-11-04T15:31:02.000Z", created_at: "2026-11-03T14:00:00.250Z" });
  });

  it("registre-refus-ancre-periode-redemarrage : l'alerte prestataires_epuises critique, levée avant l'arrêt, l'est de nouveau au premier refus après le redémarrage, puis plus", function () {
    const t = trace("registre-refus-ancre-periode-redemarrage");
    expect(t.queue_before.find((d) => d.id === AP(1)).attempts.map((a) => [a.outcome, a.error_code])).to.deep.equal([["echec_permanente", "refus_emetteur_inconnu"]]);
    expect(t.expected.filter((a) => a.request_id === AP(1) && a.action === "alerter" && a.detail.code === "prestataires_epuises").map((a) => [a.t, a.detail.severity])).to.deep.equal([["2026-11-03T14:05:03.000Z", "critique"]]);
    expect(t.inputs.filter((e) => e.type === "echec_registre").map((e) => e.t)).to.deep.equal(["2026-11-03T14:05:03.000Z", "2026-11-03T14:10:04.000Z"]);
  });

  it("textes : CT-5 (note de révision, EX-9.4, EX-8.12, EX-8.11, EX-8.10, EX-10.7, AN-36, AN-41, A.3, A.4), INDEX.md et spec/README.md nomment les règles et les trois traces", function () {
    const ct5 = fs.readFileSync(path.join(DEPOT, "spec", "CT-5-ancrage.md"), "utf8");
    const plat = ct5.replace(/\s+/g, " ");
    const index = fs.readFileSync(path.join(CT5, "INDEX.md"), "utf8");
    const readme = fs.readFileSync(path.join(DEPOT, "spec", "README.md"), "utf8");
    for (const id of NOUVELLES) {
      expect(plat, id).to.include(`\`${id}\``);
      expect(plat, id).to.include(`${id}.json`);
      expect(index, id).to.include(`\`${id}.json\``);
    }
    expect(index).to.include("`redemarrage-ots-abandon-soumission-tardive.avant.ndjson`");
    expect(index).to.include("`registre-refus-ancre-periode-redemarrage.avant.ndjson`");
    expect(plat).to.include("Complément du 2026-11-16 (une ancre de période qui attend retient sa clé). La clé d'une ancre est libre quand elle n'a aucune ancre en vol (`envoyee`) et qu'aucune ancre de période d'une période antérieure de la même clé");
    expect(plat).to.include("aucune ne l'est ici, et une ancre `a_reprendre` dont l'échéance est passée pendant l'arrêt part à sa minuterie, au point 7");
    expect(plat).to.include("Complément du 2026-11-16 (soumission aboutie au-delà de l'âge d'abandon).");
    expect(plat).to.include("le premier refus qui suit un redémarrage la lève de nouveau, une fois (trace `registre-refus-ancre-periode-redemarrage`)");
    expect(plat).to.include("Complément du 2026-11-16 (ordre d'une action et d'une entrée du même instant).");
    expect(plat).to.include("Complément du 2026-11-16 (AN-36, ordre des ancres d'une clé).");
    expect(plat).to.include("complément du 2026-11-16, ordre des ancres d'une clé d'EX-9.4 : l'ancre d'une période ne passe `envoyee`");
    expect(plat).to.include("`ots_give_up` dès le passage `en_attente` d'une soumission aboutie au-delà de `give_up_after_s`");
    expect(plat).to.include("complément du 2026-11-16 : soixante et une traces ; EX-9.4, EX-8.11, EX-8.10");
    expect(plat).to.include("les soixante-deux traces de 8.10 et A.3");
    expect(plat).to.include("(vingt-cinq traces)");
    expect(readme).to.include("Les soixante-deux traces normatives");
  });

  const T59 = ["registre-periode-retient-la-cle"];
  const MUTANTS_REFERENCE = [
    ["creation-point-sans-retenue", T59, [['      if (this.cleOccupee(ancre) || this.attendPeriode(ancre) || this.attendPoints(ancre)) this.programmer(ancre, t, t, "attente_nonce");', '      if (this.cleOccupee(ancre) || this.attendPoints(ancre)) this.programmer(ancre, t, t, "attente_nonce");']]],
    ["cloture-sans-retenue", ["travail:cloture"], [['      else if (this.attendPeriode(a)) this.programmer(a, t, t, "attente_nonce");\n', ""]]],
    ["reprise-sans-retenue", ["travail:reprise"], [['          else if (this.attendPeriode(d)) this.programmer(d, t, t, "attente_nonce");\n', ""]]],
    ["servir-sans-retenue", T59, [["!this.int(d.id).reprises.has(null))) && !this.attendPeriode(d));", "!this.int(d.id).reprises.has(null))));"]]],
    ["a-reprendre-echue-candidate-au-demarrage", ["travail:echue"], [["(d.state === \"a_reprendre\" && d.due_at !== null && ms(d.due_at) <= t && !this.int(d.id).reprises.has(null))) && !this.attendPeriode(d));", "(d.state === \"a_reprendre\" && d.due_at !== null && ms(d.due_at) <= t)) && !this.attendPeriode(d));"]]],
    ["ots-give-up-a-la-mise-a-niveau", ["redemarrage-ots-abandon-soumission-tardive"], [['      if (t - ms(d.created_at) >= o.upgrade.give_up_after_s * 1000 && !s.alertes.has("ots_give_up")) {', "      if (false) {"]]],
    ["alerte-refus-une-fois-par-ancre", ["registre-refus-ancre-periode-redemarrage"], [['    if (permanent && !s.alertes.has("prestataires_epuises")) {', '    if (permanent && !s.alertes.has("prestataires_epuises") && !d.attempts.slice(0, -1).some((x) => x.outcome === "echec_permanente")) {']]],
  ];
  for (const [nom, ids, paires] of MUTANTS_REFERENCE) {
    it(`mutant ${nom} (référence) : ${ids.join(", ")} diverge (tué)`, async function () {
      const R = mutantReference(nom, paires);
      const { cas } = tracesDeTravail((await modules(DEPOT)).A);
      for (const id of ids) {
        const t = id.startsWith("travail:") ? cas[id.slice(8)] : trace(id);
        expect(diverge((await ecarts(t, { R })).reference), id).to.equal(true);
      }
    });
  }

  const MUTANTS_COMPOSANT = [
    ["attente-sans-retenue", [...T59, "travail:cloture", "travail:reprise", "travail:demarrage"], [["    if (this.attendPeriode(d)) return true;\n", ""]]],
    ["a-reprendre-echue-candidate-au-demarrage", ["travail:echue"], [['(d) => d.kind.startsWith("ancre_registre_") && d.state === "a_envoyer" && d.subject.org_id === org_id', '(d) => d.kind.startsWith("ancre_registre_") && (d.state === "a_envoyer" || (d.state === "a_reprendre" && d.due_at !== null && ms(d.due_at) <= this.now)) && d.subject.org_id === org_id']]],
    ["ots-give-up-a-la-mise-a-niveau", ["redemarrage-ots-abandon-soumission-tardive"], [["        if (this.now - ms(req.created_at) >= o.upgrade.give_up_after_s * 1000 && !i.giveUp) {", "        if (false) {"]]],
    ["alerte-refus-une-fois-par-ancre", ["registre-refus-ancre-periode-redemarrage"], [["        if (!i.epuisementAlerte) {\n          i.epuisementAlerte = true;\n          this.emettre(\"alerter\", d.id, { code: \"prestataires_epuises\", severity: \"critique\" });\n        }\n      }\n      this.ecrire(d, \"a_reprendre\");", "        if (!i.epuisementAlerte && !d.attempts.slice(0, -1).some((x) => x.outcome === \"echec_permanente\")) {\n          i.epuisementAlerte = true;\n          this.emettre(\"alerter\", d.id, { code: \"prestataires_epuises\", severity: \"critique\" });\n        }\n      }\n      this.ecrire(d, \"a_reprendre\");"]]],
  ];
  for (const [nom, ids, paires] of MUTANTS_COMPOSANT) {
    it(`mutant ${nom} (composant) : ${ids.join(", ")} diverge (tué)`, async function () {
      const C = mutantComposant(nom, paires);
      const { cas } = tracesDeTravail((await modules(DEPOT)).A);
      for (const id of ids) {
        const t = id.startsWith("travail:") ? cas[id.slice(8)] : trace(id);
        expect(diverge((await ecarts(t, { C })).composant), id).to.equal(true);
      }
    });
  }
});
