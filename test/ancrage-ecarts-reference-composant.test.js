// CT-5 : derniers écarts entre la référence (scripts/lib/ancrage.mjs) et le
// composant d'ancrage (paquets/ancrage), qu'aucune trace n'exerçait ; le
// complément du 2026-11-16 écrit la ligne qui manquait et l'implémentation qui
// divergeait la rejoint :
//
// - EX-6.2 : le nonce OpenTimestamps est tiré une fois par demande et repris
//   par chaque soumission, après un échec comme après un redémarrage ;
// - EX-8.11 : une réponse des calendriers sans preuve écrite n'est jamais
//   promue (`preuve_absente` à la soumission ; en attente à la mise à niveau) ;
// - EX-8.12 : une ligne `a_reprendre` qui porte encore une soumission en cours
//   se reprend comme une soumission `envoyee` ; une seule action `programmer`
//   `immediat` par demande ; les séries repartent dans l'ordre des tentatives
//   closes par le démarrage ;
// - EX-8.16 : détail des tentatives (soumission, renvois au registre, refus
//   RFC 3161, jeton promu) ; ordre de deux minuteries de même échéance ;
// - EX-8.5, règles 1 et 2, 8.9 : réponses et événements du registre qui ne
//   s'appliquent pas, borne d'une pièce ; EX-5.10 : jeton absent, PKIFailureInfo
//   hors liste, précision hors de la plage d'un instant, ordre des
//   avertissements, jeton gardé seulement d'un status 0 ou 1 promu ou pièce ;
//   EX-8.10 : reçu et échec sans transaction en vol, due_at ;
//   EX-8.8 : erreur permanente d'une série pendant que l'autre est active.
//
// Sept traces nouvelles (ots-preuve-absente, redemarrage-ots-a-reprendre-en-cours,
// reponses-hors-tentative, registre-renvois, redemarrage-releve-deux-series,
// minuteries-simultanees, jeton-tardif-avertissements) départagent. Chaque règle
// retirée de la référence ou du composant (copie sous NOORTRACE_TMP, défaut
// os.tmpdir(), détruite à la fin) fait diverger le rejeu (mutant tué). Les
// vecteurs sont lus dans le dépôt ; le code est lu dans le dépôt, ou sous
// NOORTRACE_REVUE_RACINE (code d'avant : essai rouge).

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";

const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : PROJECT_ROOT;
const CT5 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-5");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const COPIES = [];
const unique = () => `?t=${Date.now()}-${Math.random()}`;
const trace = (id) => JSON.parse(fs.readFileSync(path.join(CT5, "planification", `${id}.json`), "utf8"));

/** Copie d'un sous-arbre de RACINE sous TMP (node_modules, spec et package.json liés), un fichier modifié par un remplacement unique. */
function copie(nom, sousArbre, fichier, ancien, nouveau) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-ecarts-${nom}-`));
  COPIES.push(racine);
  fs.mkdirSync(path.join(racine, path.dirname(sousArbre)), { recursive: true });
  fs.cpSync(path.join(RACINE, sousArbre), path.join(racine, sousArbre), { recursive: true });
  for (const l of ["spec", "node_modules", "package.json"]) fs.symlinkSync(path.join(PROJECT_ROOT, l), path.join(racine, l));
  const f = path.join(racine, fichier);
  const texte = fs.readFileSync(f, "utf8");
  const n = texte.split(ancien).length - 1;
  if (n !== 1) throw new Error(`copie ${nom} : « ${ancien.slice(0, 120)} » trouvé ${n} fois`);
  fs.writeFileSync(f, texte.replace(ancien, () => nouveau));
  return racine;
}
const reference = (racine) => import(pathToFileURL(path.join(racine, "scripts", "lib", "ancrage.mjs")).href + unique());
const composant = (racine) => import(pathToFileURL(path.join(racine, "paquets", "ancrage", "src", "planificateur", "traces.mjs")).href + unique());
const PLANIFICATEUR = "paquets/ancrage/src/planificateur/planificateur.mjs";
const mutantReference = (nom, ancien, nouveau) => reference(copie(nom, "scripts/lib", "scripts/lib/ancrage.mjs", ancien, nouveau));
const mutantComposant = (nom, ancien, nouveau) => composant(copie(nom, "paquets/ancrage/src", PLANIFICATEUR, ancien, nouveau));

after(function () {
  for (const r of COPIES) fs.rmSync(r, { recursive: true, force: true });
});

/** Écarts de la référence (verifierTrace) et du composant (rejouerTrace) sur une trace publiée. */
async function ecarts(id, { R = null, C = null } = {}) {
  const t = trace(id);
  const ref = R ?? (await reference(RACINE));
  const comp = C ?? (await composant(RACINE));
  let r;
  try {
    r = ref.verifierTrace(t).length;
  } catch (e) {
    r = `exception : ${e.message}`;
  }
  let c;
  try {
    c = comp.rejouerTrace(t).ecarts.length;
  } catch (e) {
    c = `exception : ${e.message}`;
  }
  return { reference: r, composant: c };
}
/** Le mutant fait diverger la trace du côté visé (écart ou exception). */
const diverge = (n) => typeof n === "string" || n > 0;

const OP1 = "ots_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1";
const TRACES = ["ots-preuve-absente", "redemarrage-ots-a-reprendre-en-cours", "reponses-hors-tentative", "registre-renvois", "redemarrage-releve-deux-series", "minuteries-simultanees", "jeton-tardif-avertissements"];

/**
 * Référence en exploitation (aleatoireSysteme) : clôture de la période 1, puis la soumission OpenTimestamps
 * échoue (un calendrier) et repart ; un second planificateur relit la file sur la même source et redémarre.
 * Rend les nonces soumis avant et après le redémarrage et le nombre de tirages demandés à la source.
 */
async function noncesExploitation(A) {
  const t = trace("ots-reponses-insuffisantes");
  const systeme = A.aleatoireSysteme(250);
  let tirages = 0;
  const source = { ...systeme, nonceOts: (x) => { tirages += 1; return systeme.nonceOts(x); }, gigue: () => 0 };
  const p1 = A.creerPlanificateur(t.config, { aleatoire: source });
  p1.charger([]);
  for (const e of t.inputs.slice(0, 3)) p1.recevoir(e);
  p1.recevoir({ t: "2026-11-03T14:00:06.000Z", type: "tic", data: {} });
  const avant = p1.actions.filter((a) => a.action === "soumettre_ots").map((a) => a.detail.nonce);
  const p2 = A.creerPlanificateur(t.config, { aleatoire: source });
  p2.charger(A.lireFile(p1.lignes.map((l) => l + "\n").join("")).demandes);
  p2.recevoir({ t: "2026-11-03T14:00:30.000Z", type: "demarrage", data: {} });
  const apres = p2.actions.filter((a) => a.action === "soumettre_ots" && a.request_id === OP1).map((a) => a.detail.nonce);
  return { avant, apres, tirages };
}

describe("CT-5 : derniers écarts entre la référence et le composant d'ancrage (complément du 2026-11-16)", function () {
  this.timeout(300000);

  it("EX-6.2 (référence) : en exploitation, un seul nonce par soumission OpenTimestamps ; la soumission rejouée après un échec et après un redémarrage le reprend", async function () {
    const { avant, apres, tirages } = await noncesExploitation(await reference(RACINE));
    expect(avant).to.have.lengthOf(2);
    expect(apres).to.have.lengthOf(1);
    expect(new Set([...avant, ...apres]).size).to.equal(1);
    // Le planificateur tire une fois par demande et par processus ; la source rend ensuite le même nonce.
    expect(tirages).to.equal(2);
  });

  for (const id of TRACES) {
    it(`trace ${id} : rejouée sans écart par la référence et par le composant`, async function () {
      expect(await ecarts(id)).to.deep.equal({ reference: 0, composant: 0 });
    });
  }

  it("EX-8.11 : ots-preuve-absente ; aucune soumission sans preuve promue, preuve_absente rejetée de classe transitoire ; attestation Bitcoin sans preuve à la mise à niveau : en attente ; lignes tentative_close, demande_close, demande_inconnue", function () {
    const t = trace("ots-preuve-absente");
    expect(t.expected.filter((a) => a.action === "stocker" && a.request_id === OP1).every((a) => a.detail.sha256 !== null)).to.equal(true);
    expect(t.expected.filter((a) => a.action === "rejeter_reponse").map((a) => a.detail.error_code)).to.deep.equal(["preuve_absente", "preuve_absente"]);
    expect(t.expected.filter((a) => a.action === "journaliser" && a.detail.event === "anchor_response_rejected").map((a) => a.detail.error_code)).to.deep.equal(["preuve_absente", "tentative_close", "preuve_absente", "demande_close", "demande_inconnue"]);
    const ots = t.queue_after.find((d) => d.id === OP1);
    expect(ots.attempts.map((a) => a.error_code)).to.deep.equal(["preuve_absente", "preuve_absente", null, "en_attente", null]);
  });

  it("EX-8.12, EX-8.16 : redemarrage-ots-a-reprendre-en-cours ; la tentative laissée en_cours est close redemarrage au démarrage, la soumission repart au rang 3, détail « soumission a 2 calendriers » ; fichiers de reprise/", function () {
    const t = trace("redemarrage-ots-a-reprendre-en-cours");
    expect(t.queue_before.find((d) => d.id === OP1)).to.deep.include({ state: "a_reprendre" });
    const ots = t.queue_after.find((d) => d.id === OP1);
    expect(ots.attempts.map((a) => [a.n, a.outcome, a.error_code, a.detail])).to.deep.equal([
      [1, "echec_transitoire", "reponses_insuffisantes", "1 calendrier(s) ; moins de 2 reponses valables"],
      [2, "echec_transitoire", "redemarrage", "redemarrage : reponse non recue"],
      [3, "en_cours", null, "soumission a 2 calendriers"],
    ]);
    for (const id of ["redemarrage-ots-a-reprendre-en-cours", "redemarrage-releve-deux-series"]) {
      for (const f of ["avant", "apres"]) expect(fs.existsSync(path.join(CT5, "reprise", `${id}.${f}.ndjson`)), `${id} ${f}`).to.equal(true);
    }
  });

  // Mutants de la référence (règle retirée : la trace diverge, ou le tirage du nonce change).
  it("mutants EX-6.2 (référence) : nonce tiré à chaque soumission par le planificateur, ou source d'exploitation sans mémoire (tués)", async function () {
    const planif = await mutantReference("nonce-planificateur", "    s.nonceOts ??= Buffer.from(this.aleatoire.nonceOts({ kind: d.kind, subject: d.subject }));", "    s.nonceOts = Buffer.from(this.aleatoire.nonceOts({ kind: d.kind, subject: d.subject }));");
    expect((await noncesExploitation(planif)).tirages).to.be.above(2);
    const source = await mutantReference("nonce-source", "      let n = noncesOts.get(cle);", "      let n = null;");
    const r = await noncesExploitation(source);
    expect(new Set([...r.avant, ...r.apres]).size).to.be.above(1);
  });

  const MUTANTS_REFERENCE = [
    ["preuve-absente", "ots-preuve-absente", "      if (insuffisantes || !preuve) {", "      if (insuffisantes) {"],
    ["mise-a-niveau-sans-preuve", "ots-preuve-absente", "    if (data.attestation === \"complete\" && preuve) {", "    if (data.attestation === \"complete\") {"],
    ["ots-hors-tentative", "ots-preuve-absente", "error_code: ETATS_FINAUX.has(d.state) ? \"demande_close\" : \"tentative_close\", ...this.rangDesigne(d, totalTentatives(d)), provider: null, kept: preuve });", "error_code: ETATS_FINAUX.has(d.state) ? \"demande_close\" : \"tentative_inconnue\" });"],
    ["a-reprendre-en-cours", "redemarrage-ots-a-reprendre-en-cours", "        if (d.state === \"envoyee\" || (d.state === \"a_reprendre\" && d.attempts.some((a) => a.outcome === \"en_cours\"))) {\n          this.perdreTentatives(d, t);", "        if (d.state === \"envoyee\") {\n          this.perdreTentatives(d, t);"],
    ["demande-inconnue", "reponses-hors-tentative", "error_code: \"demande_inconnue\", attempt: data.attempt ?? null, provider: null, kept: false });", "error_code: \"tentative_inconnue\", attempt: data.attempt ?? null });"],
    ["rang-inconnu-garde", "reponses-hors-tentative", "      if (jeton) this.emettre(t, \"stocker\", d.id, { sha256: data.token_sha256, size: data.token_size, bound: null });\n", ""],
    ["borne-piece", "reponses-hors-tentative", "      const valable = nonceDesigne !== null && data.gen_time", "      const valable = Boolean(data.gen_time) || data.gen_time"],
    ["jeton-absent", "reponses-hors-tentative", "    if (data.token_sha256 === null || data.token_sha256 === undefined) return { ...res, code: \"reponse_illisible\", detail: \"TimeStampToken absent\" };\n", ""],
    ["failure-info-hors-liste", "reponses-hors-tentative", "fi === null || fi === undefined || !FAILURE_INFOS.has(fi)", "fi === null || fi === undefined"],
    ["doublon-registre", "reponses-hors-tentative", "    const enVol = d?.attempts[d.attempts.length - 1]?.outcome === \"en_cours\";\n    if (!d || !d.kind.startsWith(\"ancre_registre_\") || ETATS_FINAUX.has(d.state) || !enVol) {\n      this.journaliser(t, data.request_id ?? null, d && d.kind.startsWith(\"ancre_registre_\") ? { event: \"anchor_duplicate_ignored\", state: d.state } : { event: \"anchor_duplicate_ignored\", reason: \"demande_inconnue\" });\n      return;\n    }\n    const s = this.int(d.id);", "    const enVol = d?.attempts[d.attempts.length - 1]?.outcome === \"en_cours\";\n    if (!d || !d.kind.startsWith(\"ancre_registre_\") || ETATS_FINAUX.has(d.state) || !enVol) {\n      this.journaliser(t, data.request_id ?? null, { event: \"anchor_duplicate_ignored\", reason: d ? `etat ${d.state}` : \"demande_inconnue\" });\n      return;\n    }\n    const s = this.int(d.id);"],
    ["recu-sans-transaction", "registre-renvois", "    const enVol = d?.attempts[d.attempts.length - 1]?.outcome === \"en_cours\";\n    if (!d || !d.kind.startsWith(\"ancre_registre_\") || ETATS_FINAUX.has(d.state) || !enVol) {\n      this.journaliser(t, data.request_id ?? null, d && d.kind.startsWith(\"ancre_registre_\") ? { event: \"anchor_duplicate_ignored\", state: d.state } : { event: \"anchor_duplicate_ignored\", reason: \"demande_inconnue\" });\n      return;\n    }\n    const s = this.int(d.id);", "    const enVol = d?.attempts[d.attempts.length - 1]?.outcome === \"en_cours\" || d?.state === \"a_reprendre\";\n    if (!d || !d.kind.startsWith(\"ancre_registre_\") || ETATS_FINAUX.has(d.state) || !enVol) {\n      this.journaliser(t, data.request_id ?? null, d && d.kind.startsWith(\"ancre_registre_\") ? { event: \"anchor_duplicate_ignored\", state: d.state } : { event: \"anchor_duplicate_ignored\", reason: \"demande_inconnue\" });\n      return;\n    }\n    const s = this.int(d.id);"],
    ["minuteries-armement", "minuteries-simultanees", "      if (ca !== cb) return ca - cb;", "      return a.seq - b.seq;"],
    ["borne-hors-plage", "jeton-tardif-avertissements", "bound: borne !== null && borneInstantValide(ms(data.gen_time), data.accuracy_s ?? 0) ? iso(borne) : null });", "bound: borne !== null ? iso(borne) : null });"],
    ["nonces-hors-fenetre", "file-fenetre-32", "    for (const a of d.attempts) if (!gardees.includes(a) && a.nonce) this.int(d.id).noncesHorsFenetre.set(a.n, a.nonce);\n", ""],
  ];
  for (const [nom, id, ancien, nouveau] of MUTANTS_REFERENCE) {
    it(`mutant ${nom} (référence) : ${id} diverge (tué)`, async function () {
      const R = await mutantReference(nom, ancien, nouveau);
      expect(diverge((await ecarts(id, { R })).reference)).to.equal(true);
    });
  }

  const MUTANTS_COMPOSANT = [
    ["preuve-absente", "ots-preuve-absente", "      const code = insuffisantes ? \"reponses_insuffisantes\" : \"preuve_absente\";", "      const code = \"reponses_insuffisantes\";"],
    ["a-reprendre-en-cours", "redemarrage-ots-a-reprendre-en-cours", "        } else if (d.state === \"envoyee\" || (d.state === \"a_reprendre\" && d.attempts.some((a) => a.outcome === \"en_cours\"))) {", "        } else if (d.state === \"envoyee\") {"],
    ["detail-soumission", "redemarrage-ots-a-reprendre-en-cours", "    this.nouvelleTentative(req, { detail: `soumission a ${this.config.opentimestamps.calendars.length} calendriers` });", "    this.nouvelleTentative(req, { detail: \"soumission envoyee\" });"],
    ["rang-inconnu", "reponses-hors-tentative", "kept: jeton }, attempt ?? data.attempt);", "kept: jeton }, attempt ?? (sortie ? data.attempt : null));"],
    ["jeton-statut", "reponses-hors-tentative", "    const jeton = (data.pki_status === 0 || data.pki_status === 1) && data.token_sha256 !== null && data.token_sha256 !== undefined;", "    const jeton = data.token_sha256 !== null && data.token_sha256 !== undefined;"],
    ["piece-seule", "reponses-hors-tentative", "    if (jeton && (verdict.issue === \"obtenue\" || verdict.piece)) this.emettre(", "    if (jeton) this.emettre("],
    ["detail-nonce", "reponses-hors-tentative", "piece(\"nonce_different\", `nonce ${data.nonce_in_response} different de ${attempt.nonce}`)", "piece(\"nonce_different\", \"nonce du TSTInfo different de celui de la requete\")"],
    ["detail-politique", "reponses-hors-tentative", "piece(\"politique_differente\", \"politique differente de la politique demandee\")", "piece(\"politique_differente\", \"politique differente de reqPolicy\")"],
    ["detail-http-permanent", "reponses-hors-tentative", "      return permanente(code, `http ${statut}${data.retry_after_s !== null && data.retry_after_s !== undefined ? ` ; Retry-After ${data.retry_after_s} s` : \"\"}`);", "      return permanente(code, `http ${statut}`);"],
    ["detail-renvoi", "registre-renvois", "    this.nouvelleTentative(d, { detail: i.inclusionLate === 1 ? \"renvoi des memes octets\" : \"remplacement au meme nonce\" });", "    this.nouvelleTentative(d, { detail: \"transaction envoyee\" });"],
    ["due-at-envoi-registre", "registre-renvois", "    // repartie d'a_reprendre.\n    d.due_at = null;\n", "    // repartie d'a_reprendre.\n"],
    ["due-at-attente-nonce", "registre-renvois", "      d.due_at = this.horodatage(this.now);\n      this.emettre(\"programmer\", d.id, { next_at: this.horodatage(this.now), reason: \"attente_nonce\" });", "      this.emettre(\"programmer\", d.id, { next_at: this.horodatage(this.now), reason: \"attente_nonce\" });"],
    ["recu-sans-transaction", "registre-renvois", "    const a = this.derniereTentative(d);\n    if (estFinale(d) || !a || a.outcome !== \"en_cours\") {\n      this.emettre(\"journaliser\", d.id, { event: \"anchor_duplicate_ignored\", state: d.state });\n      return;\n    }\n    const i = this.interneDe(d.id);", "    let a = this.derniereTentative(d);\n    if (estFinale(d)) {\n      this.emettre(\"journaliser\", d.id, { event: \"anchor_duplicate_ignored\", state: d.state });\n      return;\n    }\n    if (!a || a.outcome !== \"en_cours\") a = this.nouvelleTentative(d, { detail: \"transaction envoyee\" });\n    const i = this.interneDe(d.id);"],
    ["echec-sans-transaction", "registre-renvois", "    const a = this.derniereTentative(d);\n    if (estFinale(d) || !a || a.outcome !== \"en_cours\") {\n      this.emettre(\"journaliser\", d.id, { event: \"anchor_duplicate_ignored\", state: d.state });\n      return;\n    }\n    this.annulerTimers(d.id, [\"recu\", \"reprise_registre\"]);\n    const code = data.code;", "    const a = this.derniereTentative(d);\n    if (estFinale(d) || !a) {\n      this.emettre(\"journaliser\", d.id, { event: \"anchor_duplicate_ignored\", state: d.state });\n      return;\n    }\n    this.annulerTimers(d.id, [\"recu\", \"reprise_registre\"]);\n    const code = data.code;"],
    ["programmer-par-serie", "redemarrage-releve-deux-series", "            if (rang === 0) this.programmer(d, this.now, \"immediat\", \"reprise\", { provider: f });\n            else this.timers.push({ at: this.now, id: d.id, type: \"reprise\", seq: this.seqTimer++, provider: f });", "            this.programmer(d, this.now, \"immediat\", \"reprise\", { provider: f });"],
    ["ordre-series", "redemarrage-releve-deux-series", "          const fournisseurs = [...new Set(perdus)];", "          const fournisseurs = [...new Set(d.attempts.filter((a) => a.error_code === \"redemarrage\").map((a) => a.provider))];"],
    ["permanente-ecrite", "redemarrage-releve-deux-series", "      this.ecrire(req, req.attempts.some((a) => a.outcome === \"en_cours\") ? \"envoyee\" : \"a_reprendre\");\n      return;", "      return;"],
    ["precision-t7", "jeton-tardif-avertissements", "    if (!(Math.abs(genTime + (data.accuracy_s ?? 0) * 1000) <= 8.64e15)) return piece(\"verification_T-7\", \"precision hors de la plage d'un instant (T-7)\");\n", ""],
    ["ordre-avertissements", "jeton-tardif-avertissements", "    if (Math.abs(genTime - envoi) > fr.clock_tolerance_s * 1000) avertissements.push(\"horloge_suspecte\");\n    return { issue: \"obtenue\", avertissements, valable: true };", "    if (Math.abs(genTime - envoi) > fr.clock_tolerance_s * 1000) avertissements.unshift(\"horloge_suspecte\");\n    return { issue: \"obtenue\", avertissements, valable: true };"],
    ["ordre-alertes", "jeton-tardif-avertissements", "    const alertes = [\"horloge_suspecte\", \"reponse_tardive\"].filter((a) => avertissements.includes(a)).map(", "    const alertes = avertissements.map("],
    ["detail-jeton-promu", "jeton-tardif-avertissements", "    attempt.detail = `${data.pki_status === 1 ? \"grantedWithMods\" : \"granted\"} ; T-1 a T-9 reussies${avertissements.length ? ` ; avertissement ${avertissements.join(\", \")}` : \"\"}`;", "    attempt.detail = `granted ; T-1 a T-9 reussies${avertissements.map((a) => ` ; avertissement ${a}`).join(\"\")}`;"],
    ["borne-hors-plage", "jeton-tardif-avertissements", " && Math.abs(msGenTime(data.gen_time) + (data.accuracy_s ?? 0) * 1000) <= 8.64e15\n", "\n"],
  ];
  for (const [nom, id, ancien, nouveau] of MUTANTS_COMPOSANT) {
    it(`mutant ${nom} (composant) : ${id} diverge (tué)`, async function () {
      const C = await mutantComposant(nom, ancien, nouveau);
      expect(diverge((await ecarts(id, { C })).composant)).to.equal(true);
    });
  }

  it("INDEX.md, CT-5 (A.3, A.4, note de révision, EX-8.16) et spec/README.md nomment les sept traces ; A.4 compte soixante-deux traces, vingt-cinq à file", function () {
    const index = fs.readFileSync(path.join(CT5, "INDEX.md"), "utf8");
    const ct5 = fs.readFileSync(path.join(PROJECT_ROOT, "spec", "CT-5-ancrage.md"), "utf8").replace(/[ \n]+/g, " ");
    const readme = fs.readFileSync(path.join(PROJECT_ROOT, "spec", "README.md"), "utf8");
    const a3 = ct5.slice(ct5.indexOf("### A.3 Disposition"), ct5.indexOf("### A.4 Familles"));
    const a4 = ct5.slice(ct5.indexOf("### A.4 Familles"), ct5.indexOf("### A.5 "));
    for (const id of TRACES) {
      expect(index).to.include(`| \`${id}.json\` |`);
      expect(a3).to.include(`${id}.json`);
      expect(ct5).to.include(`\`${id}\``);
    }
    expect(a3).to.include("quarante-sept traces");
    // A.4 et spec/README.md (complément du 2026-11-16, ordre du démarrage : cinq traces de plus, quatre à file ; clé de chaîne du verrou d'EX-9.4 : une de plus, sans file ; minuteries de deux journaux, EX-8.16 : une de plus, sans file ; puis refus de l'ancre d'une période et ordre des ancres de points, EX-8.10 et EX-9.4 : deux de plus, dont une à file ; puis l'ancre de la période après celle de son point de clôture et l'âge d'abandon OpenTimestamps, EX-9.4 et EX-8.11 : deux de plus, dont une à file ; puis la clé retenue par l'ancre d'une période, la soumission OpenTimestamps tardive et l'alerte du refus après un redémarrage, EX-9.4, EX-8.11 et EX-8.10 : trois de plus, dont deux à file ; puis l'ancre d'un point en reprise quand le point suivant de sa période est admis, EX-9.5 et EX-9.4 : une de plus, sans file).
    expect(a4).to.include("les soixante-deux traces de 8.10 et A.3");
    expect(a4).to.include("(vingt-cinq traces)");
    expect(readme).to.include("Les soixante-deux traces normatives");
    for (const texte of ["code `preuve_absente`", "`soumission a <nombre de calendars> calendriers`", "`renvoi des memes octets`", "`remplacement au meme nonce`", "dans l'ordre de la file (`created_at`, puis `id`)"]) expect(ct5).to.include(texte);
  });
});
