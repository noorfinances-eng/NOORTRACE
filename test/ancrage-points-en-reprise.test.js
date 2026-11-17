// CT-5 EX-9.5 et EX-9.4 (complément du 2026-11-16) : l'ancre d'un point en reprise quand le point suivant de sa période
// est admis.
//
// 1. EX-9.5 : une ancre de point `a_reprendre` dont aucune tentative n'a été admise par un nœud (codes d'échec
//    `noeud_injoignable`, `nonce_incoherent`, `transaction_refusee`, et ceux du composant qui disent de même que rien
//    n'est parti) est encore à envoyer : l'ancre d'un point plus récent de la même période la remplace, comme une
//    ancre `a_envoyer`. Avant : le composant d'ancrage la remplaçait (sauf sur `nonce_incoherent`, qu'il ne comptait
//    pas), la référence la renvoyait à l'échéance de sa reprise, après l'ancre du point plus récent : les deux
//    divergeaient, et l'ordre des blocs de la série était renversé (`hors_ordre`, EX-10.7).
// 2. EX-9.4 : une ancre de point qui a pu partir (`recu_absent`, ou toute tentative d'un autre code) n'est jamais
//    abandonnée (EX-9.5) ; l'ancre d'un point plus récent de la même période ne part pas avant elle : elle attend
//    (`attente_nonce`) son reçu ou un autre état final. Avant : les deux implémentations faisaient partir le point le
//    plus récent dès que la clé n'avait plus d'ancre en vol, puis renvoyaient l'ancre en reprise : `hors_ordre` si le
//    registre les incluait dans cet ordre.
//
// Les vecteurs sont lus dans le dépôt ; le code est lu dans le dépôt, ou sous NOORTRACE_REVUE_RACINE (code d'avant :
// essai rouge). Les mutants sont des copies sous NOORTRACE_TMP (défaut os.tmpdir()), détruites à la fin.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { contexte, confronterParcours, decrire, violationsAncrePeriode, violationsOrdrePoints } from "./fixtures/ancrage-confrontation/parcours.mjs";

const DEPOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : DEPOT;
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const CT5 = path.join(DEPOT, "spec", "vecteurs", "ct-5");
const PLANIFICATEUR = "paquets/ancrage/src/planificateur/planificateur.mjs";
const TRACE = "registre-points-en-reprise";
const COPIES = [];
const trace = (id) => JSON.parse(fs.readFileSync(path.join(CT5, "planification", `${id}.json`), "utf8"));
const unique = () => `?t=${Date.now()}-${Math.random()}`;

/** Copie de RACINE (scripts/lib et paquets/ancrage/src), un fichier modifié par des remplacements uniques ; rend sa racine. */
function copie(nom, sousArbre, fichier, paires) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-points-en-reprise-${nom}-`));
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

// Constantes du journal de référence (A.2).
const C5 = JSON.parse(fs.readFileSync(path.join(CT5, "constantes.json"), "utf8")).reference_journal;
const point = (nom) => {
  const k = C5.checkpoints[nom];
  return { org_id: C5.org_id, journal_id: C5.journal_id, period_start: C5.periods.find((p) => p.index === k.period).period_start, tree_size: k.tree_size, checkpoint_hash: k.checkpoint_hash, checkpoint_ts: k.checkpoint_ts };
};
const AK = (nom) => `ancre_registre_point:${C5.checkpoints[nom].checkpoint_hash}`;
const E = (t, type, data = {}) => ({ t, type, data });
const inclusion = (t, id, b) => E(t, "inclusion_registre", { request_id: id, block_number: b, capture_sha256: "0x" + "ab".repeat(32) });
const echec = (t, id, code) => E(t, "echec_registre", { request_id: id, code });
const vide = (id, config, jitter_ms, queue_before, inputs) => ({ version: 0, id, description: "travail", config, jitter_ms, queue_before, inputs, expected: [], queue_after: [] });
const envois = (t) => t.expected.filter((a) => a.action === "envoyer_registre").map((a) => [a.t, a.request_id]);
const attentes = (t) => t.expected.filter((a) => a.action === "programmer" && a.detail.reason === "attente_nonce").map((a) => [a.t, a.request_id]);
const etat = (t, id) => t.queue_after.find((d) => d.id === id);

/**
 * Configuration des traces de travail : celle de la trace registre-refus-ancre-periode (défauts d'A.2), tous les points
 * ancrés, reçu attendu une heure (aucun renvoi périodique), attente de reprise de 10 min, puis 20 min (le point suivant est admis
 * pendant la reprise).
 */
function configTravail() {
  const c = structuredClone(trace("registre-refus-ancre-periode").config);
  c.registry = { ...c.registry, checkpoints: "tous", inclusion_alert_s: 3600 };
  c.rfc3161.retry = { ...c.rfc3161.retry, initial_ms: 600000, max_ms: 3600000 };
  return c;
}

/**
 * Traces de travail (non publiées). L'attendu est la suite de la référence sous RACINE ; le composant doit la
 * reproduire. Pour chaque code, l'ancre de K2 part à 13:53:00, le registre signale son échec à 13:53:01 (reprise
 * 10 min plus tard) ; K3 est admis à 13:54:00, pendant la reprise.
 * - codes « rien n'est parti » : l'ancre de K2 est remplacée par celle de K3, qui part aussitôt ; incluse à 13:54:01.
 * - `recu_absent` : l'ancre de K3 attend (`attente_nonce`) ; celle de K2 repart à l'échéance de sa reprise
 *   (14:03:01.011) ; à son reçu (14:03:02), l'ancre de K3 part ; incluse à 14:03:03.
 * - `mixte` : l'ancre de K1 échoue sur `noeud_injoignable`, repart, puis échoue sur `recu_absent` : une tentative a pu
 *   partir ; K2, admis pendant la seconde reprise, attend son reçu.
 * - `demarrage` : file relue où l'ancre de K2, `a_reprendre` sur `noeud_injoignable`, a une tentative sortie de la
 *   fenêtre de 32 avant l'arrêt, inconnue (EX-8.5, règle 7) : une transaction a pu partir ; K3, admis ensuite, attend.
 */
const RIEN_N_EST_PARTI = ["noeud_injoignable", "nonce_incoherent", "transaction_refusee"];
function tracesDeTravail(A) {
  const cfg = configTravail();
  const cas = {};
  for (const code of RIEN_N_EST_PARTI) {
    cas[code] = vide(`travail-points-en-reprise-${code.replaceAll("_", "-")}`, cfg, [11, 12], [], [
      E("2026-11-03T13:52:30.000Z", "demarrage"),
      E("2026-11-03T13:53:00.000Z", "point_produit", point("K2")),
      echec("2026-11-03T13:53:01.000Z", AK("K2"), code),
      E("2026-11-03T13:54:00.000Z", "point_produit", point("K3")),
      inclusion("2026-11-03T13:54:01.000Z", AK("K3"), 21500),
      E("2026-11-03T14:03:01.011Z", "tic"),
      E("2026-11-03T14:03:30.000Z", "arret"),
    ]);
  }
  cas.recu_absent = vide("travail-points-en-reprise-recu-absent", cfg, [11, 12], [], [
    E("2026-11-03T13:52:30.000Z", "demarrage"),
    E("2026-11-03T13:53:00.000Z", "point_produit", point("K2")),
    echec("2026-11-03T13:53:01.000Z", AK("K2"), "recu_absent"),
    E("2026-11-03T13:54:00.000Z", "point_produit", point("K3")),
    E("2026-11-03T14:03:01.011Z", "tic"),
    inclusion("2026-11-03T14:03:02.000Z", AK("K2"), 21500),
    inclusion("2026-11-03T14:03:03.000Z", AK("K3"), 21501),
    E("2026-11-03T14:03:30.000Z", "arret"),
  ]);
  cas.mixte = vide("travail-points-en-reprise-mixte", cfg, [11, 12], [], [
    E("2026-11-03T13:41:30.000Z", "demarrage"),
    E("2026-11-03T13:42:00.000Z", "point_produit", point("K1")),
    echec("2026-11-03T13:42:01.000Z", AK("K1"), "noeud_injoignable"),
    E("2026-11-03T13:52:01.011Z", "tic"),
    echec("2026-11-03T13:52:02.000Z", AK("K1"), "recu_absent"),
    E("2026-11-03T13:53:00.000Z", "point_produit", point("K2")),
    E("2026-11-03T14:12:02.012Z", "tic"),
    inclusion("2026-11-03T14:12:03.000Z", AK("K1"), 21500),
    inclusion("2026-11-03T14:12:04.000Z", AK("K2"), 21501),
    E("2026-11-03T14:12:30.000Z", "arret"),
  ]);
  // File relue : l'ancre de K2 a_reprendre sur noeud_injoignable, sa tentative 1 sortie de la fenêtre (attempts_total 2).
  const avant = A.rejouerTrace(vide("x", cfg, [11, 12], [], [
    E("2026-11-03T13:52:30.000Z", "demarrage"),
    E("2026-11-03T13:53:00.000Z", "point_produit", point("K2")),
    echec("2026-11-03T13:53:01.000Z", AK("K2"), "noeud_injoignable"),
    E("2026-11-03T13:53:02.000Z", "arret"),
  ]));
  const file = avant.file.map((d) => {
    if (d.id !== AK("K2")) return d;
    const a = d.attempts.at(-1);
    return { ...d, attempts: [{ ...a, n: 2, correlation_id: A.identifiantCorrelation(d.kind, d.subject.hash, 2) }], attempts_total: 2 };
  });
  cas.demarrage = vide("travail-points-en-reprise-demarrage", cfg, [], file, [
    E("2026-11-03T13:53:30.000Z", "demarrage"),
    E("2026-11-03T13:54:00.000Z", "point_produit", point("K3")),
    E("2026-11-03T14:03:01.011Z", "tic"),
    inclusion("2026-11-03T14:03:02.000Z", AK("K2"), 21500),
    inclusion("2026-11-03T14:03:03.000Z", AK("K3"), 21501),
    E("2026-11-03T14:03:30.000Z", "arret"),
  ]);
  for (const t of Object.values(cas)) {
    const r = A.rejouerTrace(t);
    t.expected = r.actions;
    t.queue_after = r.file;
  }
  return cas;
}

/**
 * EX-10.7 sur une trace : si le registre inclut les transactions dans l'ordre où elles partent (dernier envoi de
 * chaque ancre de point obtenue), la série des points de la période est-elle dans l'ordre des checkpoint_ts ? Rend les
 * inversions (`hors_ordre`) de verifierCompletudeRegistre.
 */
async function horsOrdre(t) {
  const { A } = await modules(DEPOT);
  const J = await import(pathToFileURL(path.join(DEPOT, "scripts", "lib", "journal.mjs")).href);
  const dernier = new Map();
  for (const a of t.expected) if (a.action === "envoyer_registre" && a.request_id.startsWith("ancre_registre_point:")) dernier.set(a.request_id, a.t);
  const obtenues = [...dernier].filter(([id]) => etat(t, id)?.state === "obtenue").sort((x, y) => (x[1] < y[1] ? -1 : x[1] > y[1] ? 1 : 0));
  const points = Object.keys(C5.checkpoints).map(point).filter((p) => p.period_start === C5.periods.find((x) => x.index === 1).period_start);
  const ancres = obtenues.map(([id], i) => ({ doc_type: J.DOC_TYPE_POINT_DE_CONTROLE, issuer: "0x00000000000000000000000000000000000000aa", fingerprint: J.empreinteAncrePoint(C5.org_id, C5.journal_id, id.split(":")[1]), block_number: 30000 + i, log_index: 0 }));
  return A.verifierCompletudeRegistre({ journaux: [{ org_id: C5.org_id, journal_id: C5.journal_id, points }], ancres, emetteurs: ["0x00000000000000000000000000000000000000aa"] }).hors_ordre;
}

after(function () {
  for (const r of COPIES) fs.rmSync(r, { recursive: true, force: true });
});

describe("CT-5 EX-9.5, EX-9.4 : l'ancre d'un point en reprise quand le point suivant de sa période est admis (complément du 2026-11-16)", function () {
  this.timeout(600000);
  let cas;
  before(async function () {
    cas = tracesDeTravail((await modules(RACINE)).A);
  });

  for (const code of RIEN_N_EST_PARTI) {
    it(`${code} (rien n'est parti) : l'ancre de K2 en reprise est remplacée par celle de K3, qui part aussitôt ; K2 ne repart jamais ; les deux implémentations concordent`, async function () {
      const t = cas[code];
      expect(envois(t)).to.deep.equal([["2026-11-03T13:53:00.000Z", AK("K2")], ["2026-11-03T13:54:00.000Z", AK("K3")]]);
      expect(etat(t, AK("K2"))).to.include({ state: "remplacee", replaced_by: AK("K3") });
      expect(t.expected.filter((a) => a.action === "remplacer").map((a) => [a.t, a.request_id, a.detail.replaced_by])).to.deep.equal([["2026-11-03T13:54:00.000Z", AK("K2"), AK("K3")]]);
      expect(etat(t, AK("K3")).state).to.equal("obtenue");
      expect(await horsOrdre(t)).to.deep.equal([]);
      expect(await ecarts(t)).to.deep.equal({ reference: 0, composant: 0 });
    });
  }

  it("recu_absent (une transaction a pu partir) : l'ancre de K2 n'est pas remplacée ; celle de K3 attend le nonce à sa création et part au reçu de K2 ; les deux implémentations concordent", async function () {
    const t = cas.recu_absent;
    expect(envois(t)).to.deep.equal([["2026-11-03T13:53:00.000Z", AK("K2")], ["2026-11-03T14:03:01.011Z", AK("K2")], ["2026-11-03T14:03:02.000Z", AK("K3")]]);
    expect(attentes(t)).to.deep.equal([["2026-11-03T13:54:00.000Z", AK("K3")]]);
    expect(t.expected.filter((a) => a.action === "remplacer")).to.deep.equal([]);
    expect([AK("K2"), AK("K3")].map((id) => etat(t, id).state)).to.deep.equal(["obtenue", "obtenue"]);
    expect(await horsOrdre(t)).to.deep.equal([]);
    expect(await ecarts(t)).to.deep.equal({ reference: 0, composant: 0 });
  });

  it("une tentative noeud_injoignable puis une recu_absent : l'ancre de K1 n'est plus « encore à envoyer » ; K2 attend son reçu", async function () {
    const t = cas.mixte;
    expect(envois(t)).to.deep.equal([["2026-11-03T13:42:00.000Z", AK("K1")], ["2026-11-03T13:52:01.011Z", AK("K1")], ["2026-11-03T14:12:02.012Z", AK("K1")], ["2026-11-03T14:12:03.000Z", AK("K2")]]);
    expect(attentes(t)).to.deep.equal([["2026-11-03T13:53:00.000Z", AK("K2")]]);
    expect(await horsOrdre(t)).to.deep.equal([]);
    expect(await ecarts(t)).to.deep.equal({ reference: 0, composant: 0 });
  });

  it("démarrage : une ancre a_reprendre dont une tentative est sortie de la fenêtre avant l'arrêt (inconnue) n'est pas remplacée ; K3 attend son reçu", async function () {
    const t = cas.demarrage;
    expect(t.queue_before.find((d) => d.id === AK("K2"))).to.include({ state: "a_reprendre", attempts_total: 2 });
    expect(envois(t)).to.deep.equal([["2026-11-03T14:03:01.011Z", AK("K2")], ["2026-11-03T14:03:02.000Z", AK("K3")]]);
    expect(attentes(t)).to.deep.equal([["2026-11-03T13:54:00.000Z", AK("K3")]]);
    expect(await ecarts(t)).to.deep.equal({ reference: 0, composant: 0 });
  });

  it("AN-36 : sur les traces de travail, aucune ancre de point ne part avant celle d'un point antérieur de sa période qui n'a ni son reçu ni un autre état final, aucune ancre de période avant celles de ses points", function () {
    for (const t of Object.values(cas)) {
      expect(violationsOrdrePoints(t.queue_before, t.expected, t.queue_after), t.id).to.deep.equal([]);
      expect(violationsAncrePeriode(t.queue_before, t.expected, t.queue_after), t.id).to.deep.equal([]);
    }
  });

  it(`${TRACE} : rejouée sans écart par la référence et par le composant`, async function () {
    expect(await ecarts(trace(TRACE))).to.deep.equal({ reference: 0, composant: 0 });
  });

  it(`${TRACE} : K2 (noeud_injoignable) remplacée par K3 ; K3 (recu_absent) retient K4, point de clôture, et la période ; au retour, K3, K4 puis la période, dans l'ordre des checkpoint_ts`, async function () {
    const t = trace(TRACE);
    const AP1 = `ancre_registre_periode:${C5.periods.find((x) => x.index === 1).period_hash}`;
    expect(envois(t)).to.deep.equal([
      ["2026-11-03T13:53:00.000Z", AK("K2")],
      ["2026-11-03T13:54:00.000Z", AK("K3")],
      ["2026-11-03T14:04:01.041Z", AK("K3")],
      ["2026-11-03T14:04:02.000Z", AK("K4")],
      ["2026-11-03T14:04:03.000Z", AP1],
    ]);
    expect(attentes(t)).to.deep.equal([["2026-11-03T14:00:00.250Z", AK("K4")], ["2026-11-03T14:00:00.250Z", AP1]]);
    expect(etat(t, AK("K2"))).to.include({ state: "remplacee", replaced_by: AK("K3") });
    expect([AK("K3"), AK("K4"), AP1].map((id) => etat(t, id).state)).to.deep.equal(["obtenue", "obtenue", "obtenue"]);
    expect(await horsOrdre(t)).to.deep.equal([]);
    expect(violationsOrdrePoints(t.queue_before, t.expected, t.queue_after)).to.deep.equal([]);
  });

  it("AN-36 : sur chacune des soixante-deux traces publiées, l'ordre des ancres des points d'une période tient", function () {
    const fichiers = fs.readdirSync(path.join(CT5, "planification")).filter((f) => f.endsWith(".json")).sort();
    // CT-5 A.3 (complément du 2026-11-16 : l'ancre d'un point en reprise quand le point suivant est admis, une trace de
    // plus) : soixante-deux traces.
    expect(fichiers).to.have.lengthOf(62);
    for (const f of fichiers) {
      const t = JSON.parse(fs.readFileSync(path.join(CT5, "planification", f), "utf8"));
      expect(violationsOrdrePoints(t.queue_before, t.expected, t.queue_after), f).to.deep.equal([]);
    }
  });

  it("confrontation (A.4), modes reprises et coupe+reprises+rfc : 100 parcours chacun, aucune divergence ni violation des invariants d'EX-9.4", async function () {
    const ctx = contexte({ ...(await modules(RACINE)), vecteurs: CT5 });
    for (const mode of ["reprises", "coupe+reprises+rfc"]) {
      for (let g = 7000; g < 7100; g++) {
        const d = confronterParcours(ctx, g, mode);
        expect(d, d ? decrire(d) : "").to.equal(null);
      }
    }
  });

  it("CT-5 (EX-9.5, EX-9.4, AN-36, note de révision, A.3, A.4), INDEX.md et spec/README.md disent la règle et nomment la trace", function () {
    // Texte lu les blancs réduits à une espace (les passages sont repliés à la largeur du fichier).
    const ct5 = fs.readFileSync(path.join(DEPOT, "spec", "CT-5-ancrage.md"), "utf8").replace(/\s+/g, " ");
    const ex95 = ct5.slice(ct5.indexOf("**EX-9.5**"), ct5.indexOf("**EX-9.6**"));
    for (const code of [...RIEN_N_EST_PARTI, "recu_absent"]) expect(ex95, code).to.include(`\`${code}\``);
    expect(ex95).to.include(TRACE);
    const ex94 = ct5.slice(ct5.indexOf("**EX-9.4**"), ct5.indexOf("**EX-9.5**"));
    expect(ex94).to.include("ancre d'un point antérieur");
    expect(ct5).to.include("Complément du 2026-11-16 (l'ancre d'un point en reprise quand le point suivant de sa période est admis)");
    const a3 = ct5.slice(ct5.lastIndexOf("### A.3"), ct5.lastIndexOf("### A.4"));
    expect(a3).to.include(`${TRACE}.json`);
    expect(ct5).to.include("les soixante-deux traces de 8.10 et A.3");
    expect(ct5).to.include("(vingt-cinq traces)");
    expect(fs.readFileSync(path.join(CT5, "INDEX.md"), "utf8")).to.include(`\`${TRACE}.json\``);
    expect(fs.readFileSync(path.join(DEPOT, "spec", "README.md"), "utf8")).to.include("Les soixante-deux traces normatives");
  });

  // Mutants (code d'après) : chacun fait diverger une trace de travail ou la trace publiée.
  const MUTANTS_REFERENCE = [
    ["remplacement-a-envoyer-seulement", [["if (autre === ancre || autre.kind !== \"ancre_registre_point\" || !this.ancreEncoreAEnvoyer(autre)", "if (autre === ancre || autre.kind !== \"ancre_registre_point\" || autre.state !== \"a_envoyer\""]], "noeud_injoignable"],
    ["nonce-incoherent-admis", [["\"noeud_injoignable\", \"nonce_incoherent\", \"transaction_refusee\"", "\"noeud_injoignable\", \"transaction_refusee\""]], "nonce_incoherent"],
    ["sans-ordre-des-points", [["if (d.kind === \"ancre_registre_point\") return this.pointAnterieurEnAttente(d);", "if (d.kind === \"ancre_registre_point\") return false;"]], "recu_absent"],
    ["tentatives-inconnues-ignorees", [["if (s.admiseHorsFenetre || s.inconnues > 0) return false;", "if (s.admiseHorsFenetre) return false;"]], "demarrage"],
  ];
  for (const [nom, paires, c] of MUTANTS_REFERENCE) {
    it(`mutant ${nom} (référence) : la trace de travail ${c} diverge (tué)`, async function () {
      const R = mutantReference(nom, paires);
      expect((await ecarts(cas[c], { R })).reference).to.satisfy(diverge);
    });
  }
  const MUTANTS_COMPOSANT = [
    ["nonce-incoherent-admis", [["\"noeud_injoignable\", \"nonce_incoherent\", \"transaction_refusee\"", "\"noeud_injoignable\", \"transaction_refusee\""]], "nonce_incoherent"],
    ["sans-ordre-des-points", [["if (d.kind === \"ancre_registre_point\") return this.pointAnterieurEnAttente(d);", "if (d.kind === \"ancre_registre_point\") return false;"]], "recu_absent"],
  ];
  for (const [nom, paires, c] of MUTANTS_COMPOSANT) {
    it(`mutant ${nom} (composant) : la trace de travail ${c} diverge (tué)`, async function () {
      const C = mutantComposant(nom, paires);
      expect((await ecarts(cas[c], { C })).composant).to.satisfy(diverge);
    });
  }
  it(`mutant sans-ordre-des-points (composant) : ${TRACE} diverge (tué)`, async function () {
    const C = mutantComposant("sans-ordre-des-points-trace", [["if (d.kind === \"ancre_registre_point\") return this.pointAnterieurEnAttente(d);", "if (d.kind === \"ancre_registre_point\") return false;"]]);
    expect((await ecarts(trace(TRACE), { C })).composant).to.satisfy(diverge);
  });
});
