// Reprise au démarrage du planificateur d'ancrage : trois règles que la note de
// la révision 0.10 de CT-5 comptait parmi ce que le composant fait, appliquées
// par la référence (scripts/lib/ancrage.mjs) et le composant d'ancrage
// (paquets/ancrage) depuis le complément du 2026-11-16 :
//
// - EX-4.13 : au démarrage, le `due_at` d'une demande `a_reprendre` postérieur
//   à l'instant courant plus `retry.max_ms` est ramené à cette borne (trace
//   `redemarrage-due-at-borne`) ;
// - EX-5.8 : une demande de jeton `obtenue` de la file sans enregistrement
//   `obtenue` promu de même `token_sha256` dans `acquisitions.ndjson` est
//   rouverte, alertée `file_perdue` et renvoyée (trace
//   `redemarrage-jeton-sans-acquisition`) ;
// - EX-8.12 : une demande de jeton recréée dont `acquisitions.ndjson` porte un
//   enregistrement `obtenue` promu est créée `obtenue` avec ce résultat, sans
//   requête (traces `file-perdue-jeton-point-obtenu` et
//   `file-perdue-jeton-periode-obtenu`).
//
// Chaque trace publiée est rejouée sans écart par la référence et par le
// composant ; chaque règle retirée de la référence ou du composant (copie sous
// NOORTRACE_TMP, défaut os.tmpdir(), détruite à la fin) fait diverger le rejeu
// (mutant tué). Le composant réel (montage d'essai, autorités locales) lit
// acquisitions.ndjson au démarrage : une ligne retirée fait rouvrir la demande ;
// une file perdue après la clôture recrée le jeton de clôture obtenu, sans
// requête. Les traces sont lues dans le dépôt, ou sous NOORTRACE_REVUE_RACINE.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import * as N from "@noortrace/noyau";
import { ErreurTransport } from "@noortrace/ancrage/rfc3161";
import { lireFiles } from "@noortrace/ancrage/planificateur";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import { attenteCalme, monterComposant, remisePoint, remiseCloture, repertoireTemporaire, enAttente } from "./fixtures/ancrage-composant/outils.mjs";

const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : PROJECT_ROOT;
const PLANIFICATION = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-5", "planification");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const COPIES = [];
const PERIODE = 1793862000; // 2026-11-05T07:00:00Z
const T0 = PERIODE * 1000;

const trace = (id) => JSON.parse(fs.readFileSync(path.join(PLANIFICATION, `${id}.json`), "utf8"));
const unique = () => `?t=${Date.now()}-${Math.random()}`;

/** Copie d'un sous-arbre de RACINE sous TMP (node_modules, spec et package.json liés), un fichier modifié par un remplacement unique. */
function copie(nom, sousArbre, fichier, ancien, nouveau) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-reprise-acquisitions-${nom}-`));
  COPIES.push(racine);
  fs.mkdirSync(path.join(racine, path.dirname(sousArbre)), { recursive: true });
  fs.cpSync(path.join(RACINE, sousArbre), path.join(racine, sousArbre), { recursive: true });
  for (const l of ["spec", "node_modules", "package.json"]) fs.symlinkSync(path.join(PROJECT_ROOT, l), path.join(racine, l));
  if (fichier) {
    const f = path.join(racine, fichier);
    const texte = fs.readFileSync(f, "utf8");
    const n = texte.split(ancien).length - 1;
    if (n !== 1) throw new Error(`copie ${nom} : « ${ancien} » trouvé ${n} fois`);
    fs.writeFileSync(f, texte.replace(ancien, () => nouveau));
  }
  return racine;
}
const reference = (racine) => import(pathToFileURL(path.join(racine, "scripts", "lib", "ancrage.mjs")).href + unique());
const composant = (racine) => import(pathToFileURL(path.join(racine, "paquets", "ancrage", "src", "planificateur", "traces.mjs")).href + unique());
const mutantReference = async (nom, ancien, nouveau) => reference(copie(nom, "scripts/lib", "scripts/lib/ancrage.mjs", ancien, nouveau));
const mutantComposant = async (nom, ancien, nouveau) => composant(copie(nom, "paquets/ancrage/src", "paquets/ancrage/src/planificateur/planificateur.mjs", ancien, nouveau));

after(function () {
  for (const r of COPIES) fs.rmSync(r, { recursive: true, force: true });
});

/** Écarts de la référence (verifierTrace) et du composant (rejouerTrace) sur une trace publiée. */
async function ecarts(id, { R = null, C = null } = {}) {
  const t = trace(id);
  const ref = R ?? (await reference(RACINE));
  const comp = C ?? (await composant(RACINE));
  return { reference: ref.verifierTrace(t).length, composant: comp.rejouerTrace(t).ecarts.length };
}

describe("CT-5, reprise au démarrage : borne de due_at, demande rouverte, demande recréée obtenue (EX-4.13, EX-5.8, EX-8.12 ; complément du 2026-11-16)", function () {
  this.timeout(300000);

  it("EX-4.13 : la trace redemarrage-due-at-borne (reprise datée 15:42:10 par une heure murale avancée, redémarrage à 13:43:00) est rejouée sans écart par la référence et le composant : programmer backoff à 13:48:00 puis ligne a_reprendre au démarrage, tentative 2 à 13:48:00 ; la mise à niveau d'une preuve OpenTimestamps en_attente n'est pas bornée (redemarrage-reprise : 20:00:01)", async function () {
    const t = trace("redemarrage-due-at-borne");
    expect(t.queue_before.find((d) => d.kind === "jeton_point").due_at).to.equal("2026-11-03T15:42:10.000Z");
    expect(t.expected.slice(1, 3).map((a) => [a.action, a.detail])).to.deep.equal([["programmer", { next_at: "2026-11-03T13:48:00.000Z", reason: "backoff" }], ["ecrire_file", { state: "a_reprendre" }]]);
    expect(t.expected.filter((a) => a.action === "envoyer_rfc3161").map((a) => [a.t, a.detail.attempt])).to.deep.equal([["2026-11-03T13:48:00.000Z", 2]]);
    expect(await ecarts("redemarrage-due-at-borne")).to.deep.equal({ reference: 0, composant: 0 });
    const reprise = trace("redemarrage-reprise");
    expect(reprise.expected.find((a) => a.action === "programmer" && a.detail.reason === "mise_a_niveau").detail.next_at).to.equal("2026-11-03T20:00:01.000Z");
    expect(await ecarts("redemarrage-reprise")).to.deep.equal({ reference: 0, composant: 0 });
  });
  it("mutant CT-5 EX-4.13 (référence) : sans la borne, la reprise attend 15:42:10 (tué par la trace)", async function () {
    const R = await mutantReference("borne-ref", "if (d.due_at !== null && d.due_at !== undefined && ms(d.due_at) > borne) {", "if (false) {");
    expect((await ecarts("redemarrage-due-at-borne", { R })).reference).to.be.above(0);
  });
  it("mutant CT-5 EX-4.13 (composant) : sans la borne, le composant diverge de la trace (tué)", async function () {
    const C = await mutantComposant("borne-comp", "if (!d.due_at || ms(d.due_at) <= borne) return false;", "return false;");
    expect((await ecarts("redemarrage-due-at-borne", { C })).composant).to.be.above(0);
  });

  it("EX-5.8 : la trace redemarrage-jeton-sans-acquisition (jeton de clôture obtenu dans la file, absent des acquisitions relues) est rejouée sans écart : demande rouverte a_reprendre, alerte file_perdue, renvoi au principal au rang 2, nouveau jeton promu ; sans le membre acquisitions, rien n'est rouvert", async function () {
    const t = trace("redemarrage-jeton-sans-acquisition");
    const ph1 = t.queue_before.find((d) => d.kind === "jeton_periode");
    expect(t.inputs[0].data.acquisitions.map((a) => a.request_id)).to.not.include(ph1.id);
    expect(t.expected.slice(1, 3).map((a) => [a.action, a.request_id, a.detail])).to.deep.equal([["ecrire_file", ph1.id, { state: "a_reprendre" }], ["alerter", ph1.id, { code: "file_perdue", severity: "critique" }]]);
    expect(t.expected.filter((a) => a.action === "envoyer_rfc3161").map((a) => [a.request_id, a.detail.provider, a.detail.attempt])).to.deep.equal([[ph1.id, "qtsa-principal", 2]]);
    expect(t.queue_after.find((d) => d.id === ph1.id).state).to.equal("obtenue");
    expect(await ecarts("redemarrage-jeton-sans-acquisition")).to.deep.equal({ reference: 0, composant: 0 });
    // Sans le membre acquisitions (entrée d'avant le complément), la règle ne s'applique pas : aucune requête.
    const sans = { ...t, inputs: [{ ...t.inputs[0], data: {} }, ...t.inputs.slice(1)] };
    const A = await reference(RACINE);
    expect(A.rejouerTrace(sans).actions.filter((a) => a.action === "envoyer_rfc3161")).to.deep.equal([]);
  });
  it("mutant CT-5 EX-5.8 (référence) : sans la réouverture, la demande reste obtenue et la trace diverge (tué)", async function () {
    const R = await mutantReference("reouverture-ref", "    if (acquisitions) {\n      for (const d of this.file()) {", "    if (false) {\n      for (const d of this.file()) {");
    expect((await ecarts("redemarrage-jeton-sans-acquisition", { R })).reference).to.be.above(0);
  });
  it("mutant CT-5 EX-5.8 (composant) : sans la réouverture, le composant diverge de la trace (tué)", async function () {
    const C = await mutantComposant("reouverture-comp", "    if (acquisitions) {\n      for (const d of this.demandesTriees()) {", "    if (false) {\n      for (const d of this.demandesTriees()) {");
    expect((await ecarts("redemarrage-jeton-sans-acquisition", { C })).composant).to.be.above(0);
  });

  it("EX-8.12 : les traces file-perdue-jeton-point-obtenu et file-perdue-jeton-periode-obtenu sont rejouées sans écart : la demande de jeton recréée est obtenue avec le résultat relu, sans tentative ni requête, et satisfait ses échéances (D_1 à D_10 ; n_T)", async function () {
    const p = trace("file-perdue-jeton-point-obtenu");
    const relu = p.inputs[1].data.acquisitions[0];
    const jk3 = p.queue_after.find((d) => d.id === relu.request_id);
    expect(jk3).to.deep.include({ state: "obtenue", attempts: [], attempts_total: 0, result: relu.result });
    expect(p.expected.filter((a) => a.action === "envoyer_rfc3161" && a.request_id === jk3.id)).to.deep.equal([]);
    expect(p.expected.filter((a) => a.action === "echeance" && a.request_id === jk3.id && a.detail.state === "satisfaite").map((a) => a.detail.k)).to.deep.equal([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const q = trace("file-perdue-jeton-periode-obtenu");
    const reluP = q.inputs[1].data.acquisitions[0];
    expect(q.queue_after.find((d) => d.id === reluP.request_id)).to.deep.include({ state: "obtenue", attempts: [], attempts_total: 0, result: reluP.result });
    expect(q.expected.filter((a) => a.action === "envoyer_rfc3161")).to.deep.equal([]);
    expect(await ecarts("file-perdue-jeton-point-obtenu")).to.deep.equal({ reference: 0, composant: 0 });
    expect(await ecarts("file-perdue-jeton-periode-obtenu")).to.deep.equal({ reference: 0, composant: 0 });
  });
  it("mutants CT-5 EX-8.12 (référence) : sans la création obtenue, le jeton de K3 puis le jeton de clôture sont demandés à nouveau (tués)", async function () {
    const R1 = await mutantReference("recree-point-ref", "        if (recu) this.obtenueRecreee(j, t, recu);", "        if (false) this.obtenueRecreee(j, t, recu);");
    expect((await ecarts("file-perdue-jeton-point-obtenu", { R: R1 })).reference).to.be.above(0);
    const R2 = await mutantReference("recree-periode-ref", "    if (j && recu) this.obtenueRecreee(j, t, recu);", "    if (false) this.obtenueRecreee(j, t, recu);");
    expect((await ecarts("file-perdue-jeton-periode-obtenu", { R: R2 })).reference).to.be.above(0);
  });
  it("mutants CT-5 EX-8.12 (composant) : sans la création obtenue, le composant diverge des deux traces (tués)", async function () {
    const C1 = await mutantComposant("recree-point-comp", "        if (recu) this.obtenueRecreee(jeton, recu);\n        else this.ecrireJetonPointInitial(jeton);", "        this.ecrireJetonPointInitial(jeton);");
    expect((await ecarts("file-perdue-jeton-point-obtenu", { C: C1 })).composant).to.be.above(0);
    const C2 = await mutantComposant("recree-periode-comp", "      if (recu) this.obtenueRecreee(jeton, recu);\n      else if (this.sansRegistre)", "      if (this.sansRegistre)");
    expect((await ecarts("file-perdue-jeton-periode-obtenu", { C: C2 })).composant).to.be.above(0);
  });
});

// --- Composant d'ancrage réel : acquisitions.ndjson relu au démarrage (CT-5 EX-5.8, EX-8.12).

async function rejouer(m, c, calme, de, a) {
  for (const point of m.serie.points.slice(0, -1)) {
    const t = N.decoderHorodatage(point.checkpoint_ts);
    const mn = (t - T0) / 60000;
    if (mn < de || mn > a) continue;
    await m.horloge.aller(t, calme);
    m.remis.push(point);
    expect((await c.remettrePoint(remisePoint(point))).admis, point.checkpoint_ts).to.equal(true);
    await calme();
  }
}

/** Réécrit acquisitions.ndjson de la période sans les lignes d'une demande. */
function retirerAcquisitions(dir, requestId) {
  const [kind, hash] = requestId.split(":");
  const objet = kind === "jeton_periode" ? "manifeste" : "point";
  const racine = path.join(dir, "stockage");
  const fichiers = [];
  const parcourir = (r) => {
    for (const e of fs.readdirSync(r, { withFileTypes: true })) {
      if (e.isDirectory()) parcourir(path.join(r, e.name));
      else if (e.name === "acquisitions.ndjson") fichiers.push(path.join(r, e.name));
    }
  };
  parcourir(racine);
  let retirees = 0;
  for (const f of fichiers) {
    const lignes = fs.readFileSync(f, "utf8").split("\n").filter(Boolean);
    const gardees = lignes.filter((l) => {
      const e = JSON.parse(l);
      const visee = e.object === objet && e.imprint === hash;
      if (visee) retirees += 1;
      return !visee;
    });
    fs.writeFileSync(f, gardees.map((l) => l + "\n").join(""));
  }
  return retirees;
}

describe("CT-5, composant d'ancrage : acquisitions.ndjson relu au démarrage (EX-5.8, EX-8.12 ; complément du 2026-11-16)", function () {
  this.timeout(600000);

  it("EX-5.8 : le jeton d'un point est obtenu ; l'enregistrement promu retiré d'acquisitions.ndjson, le redémarrage rouvre la demande (alerte_file_perdue), la renvoie au rang 2 et promeut un nouveau jeton ; sans retrait, un redémarrage ne rouvre rien", async function () {
    const dir = repertoireTemporaire("noortrace-reprise-acquisitions-5-8-");
    const m = await monterComposant({ dir, periodStart: PERIODE, evenements: { 1: 1 }, ErreurTransport, surcharges: { opentimestamps: { enabled: false } } });
    if (m.condition) return enAttente(this, m.condition);
    let c;
    try {
      c = m.creer({ epoque: 1 });
      let calme = attenteCalme(c);
      await c.demarrer();
      await rejouer(m, c, calme, 0, 5);
      await m.horloge.avancer(5000, calme);
      const avant = lireFiles(m.configuration.queue.path).demandes.find((d) => d.kind === "jeton_point" && d.state === "obtenue");
      expect(avant, "un jeton de point obtenu").to.not.equal(undefined);
      await c.arreter({ attendre: false });
      // Redémarrage sans retrait : rien n'est rouvert.
      c = m.creer({ epoque: 2 });
      calme = attenteCalme(c);
      await c.demarrer();
      await m.horloge.avancer(2000, calme);
      expect(m.journal.de("alerte_file_perdue")).to.deep.equal([]);
      expect(c.demandes().find((d) => d.id === avant.id).state).to.equal("obtenue");
      await c.arreter({ attendre: false });
      // Enregistrement promu perdu : la demande est rouverte et renvoyée.
      expect(retirerAcquisitions(dir, avant.id)).to.be.at.least(1);
      c = m.creer({ epoque: 3 });
      calme = attenteCalme(c);
      await c.demarrer();
      await m.horloge.avancer(5000, calme);
      expect(m.journal.de("alerte_file_perdue").map((l) => l.data.request_id)).to.deep.equal([avant.id]);
      const apres = c.demandes().find((d) => d.id === avant.id);
      expect(apres.state).to.equal("obtenue");
      expect(apres.attempts_total).to.equal(2);
      expect(apres.result.sha256).to.not.equal(avant.result.sha256);
      await c.arreter({ attendre: false });
    } finally {
      if (c?.etat().demarre) await c.arreter({ attendre: false });
      await m.fermer();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("EX-8.12 : la période close et son jeton de clôture obtenu, la file est perdue ; au redémarrage, le manifeste relu recrée les demandes de la période, celle du jeton de clôture obtenue avec le jeton relu d'acquisitions.ndjson, sans requête au principal", async function () {
    const dir = repertoireTemporaire("noortrace-reprise-acquisitions-8-12-");
    let m = null;
    m = await monterComposant({ dir, periodStart: PERIODE, evenements: { 1: 1 }, ErreurTransport, surcharges: { opentimestamps: { enabled: false } }, contexteSurcharges: { listerPeriodes: async () => (m.cloturee ? [{ manifeste: m.serie.manifeste }] : []) } });
    if (m.condition) return enAttente(this, m.condition);
    let c;
    try {
      c = m.creer({ epoque: 1 });
      let calme = attenteCalme(c);
      await c.demarrer();
      await rejouer(m, c, calme, 0, 59);
      const cloture = m.serie.points.at(-1);
      await m.horloge.aller(N.decoderHorodatage(cloture.checkpoint_ts), calme);
      m.remis.push(cloture);
      expect((await c.remettrePoint(remisePoint(cloture))).admis).to.equal(true);
      expect((await c.remettreCloture(remiseCloture(m.serie))).admis).to.equal(true);
      m.cloturee = true;
      await calme();
      await m.horloge.avancer(600000, calme);
      const avant = c.demandes().find((d) => d.kind === "jeton_periode");
      expect(avant.state).to.equal("obtenue");
      await c.arreter({ attendre: false });
      fs.rmSync(m.configuration.queue.path, { recursive: true, force: true });
      const requetesAvant = m.transport.requetes.length;
      c = m.creer({ epoque: 2 });
      calme = attenteCalme(c);
      await c.demarrer();
      await m.horloge.avancer(5000, calme);
      const recree = c.demandes().find((d) => d.kind === "jeton_periode");
      expect(recree.state).to.equal("obtenue");
      expect(recree.attempts).to.deep.equal([]);
      expect(recree.result.sha256).to.equal(avant.result.sha256);
      expect(m.transport.requetes.slice(requetesAvant).filter((r) => r.url === m.principal.prestataire.url)).to.deep.equal([]);
      expect(m.journal.de("anchoring_queue_rebuilt").at(-1).data.recreated).to.be.at.least(2);
      await c.arreter({ attendre: false });
    } finally {
      if (c?.etat().demarre) await c.arreter({ attendre: false });
      await m.fermer();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
