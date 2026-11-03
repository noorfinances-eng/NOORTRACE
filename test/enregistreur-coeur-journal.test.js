// Un journal produit par le cœur à partir de captures factices : échanges de
// modèle, appels de lecture et d'écriture, refus par la politique, appel
// soumis à approbation (service d'approbation factice, remise signée par les
// comptes Hardhat 1 et 2, décision scellée, ré-émission relayée), rotation de
// clé, points de contrôle alignés, clôture de période. Le journal est vérifié
// par la bibliothèque noyau ; un dossier de preuve minimal (CT-1 §11) de
// l'appel relayé après approbation est exporté, puis vérifié par le noyau ET
// par le binaire Go `noortrace-verifier` (contrôles 4, 5 et 8 non exécutés,
// raison admise).
//
// Le binaire est construit par verificateur/scripts/construire.sh avec
// go1.27.3 (GOFLAGS=-mod=vendor, GOTOOLCHAIN=local) : le répertoire de `go`
// est pris dans NOORTRACE_GO_BIN, à défaut dans PATH ; sans go1.27.3, ce test
// est marqué en attente.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import { verifierRepertoireDossier } from "@noortrace/noyau/dossier-fichiers";
import {
  Coeur, HorlogeReglable, AncrageMemoire, SupportWormMemoire, pieceJson, pieceTexte, ErreurEnregistreur, validerConfiguration, lireEvenements,
} from "@noortrace/enregistreur";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { RACINE, configurationDev, repertoireTemporaire, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";

const ms = (t) => N.decoderHorodatage(t);

/** Construit noortrace-verifier avec go1.27.3, ou rend null. */
function construireVerificateur(dir) {
  const dirGo = process.env.NOORTRACE_GO_BIN ?? null;
  const env = { ...process.env, GOFLAGS: "-mod=vendor", GOTOOLCHAIN: "local" };
  if (dirGo) env.PATH = `${dirGo}${path.delimiter}${env.PATH}`;
  const v = spawnSync("go", ["version"], { env, encoding: "utf8" });
  if (v.status !== 0 || !/go1\.27\.3 /.test(v.stdout)) return null;
  const sortie = path.join(dir, "noortrace-verifier");
  execFileSync(path.join(RACINE, "verificateur", "scripts", "construire.sh"), ["-o", sortie], { env, cwd: path.join(RACINE, "verificateur"), stdio: "pipe" });
  return sortie;
}

describe("enregistreur, cœur : journal produit, vérifié par le noyau et par le binaire Go", function () {
  this.timeout(120000);
  let dir;
  let coeur;
  let horloge;
  let service;
  let ancrage;
  let worm;
  const ev = {};
  let config;

  const hote = { id: "agent-sinistres-stdio", launched_by: "agent-sinistres", on_behalf_of: null, scope: "sinistres:lecture,paiement" };
  const delegation = { launched_by: "agent-sinistres", on_behalf_of: null, scope: "sinistres:lecture,paiement", run_id: "run-test-0001" };
  const definitionPaiement = { name: "sap__payments.create", description: "Cree un paiement", inputSchema: { type: "object" } };
  const definitionLecture = { name: "sap__claims.get", description: "Lit un sinistre", inputSchema: { type: "object" }, annotations: { readOnlyHint: true } };

  async function appel(tool, original, classe, args, horodatage, resultat) {
    horloge.aller(ms(horodatage));
    const argsPiece = pieceJson(args);
    const def = tool === "sap__payments.create" ? definitionPaiement : definitionLecture;
    const pDef = pieceJson(def, { media_type: "application/json" });
    const pListe = pieceJson({ tools: [definitionLecture, definitionPaiement] }, { media_type: "application/json" });
    for (const p of [argsPiece, pDef, pListe]) await coeur.ecrirePiece(p);
    const capture = {
      host: hote,
      delegation,
      tool_announced: tool,
      tool_original: original,
      server_alias: "sap",
      class: classe,
      arguments: argsPiece.reference,
      context: [pDef.referenceContexte(), pListe.referenceContexte()],
      intent: "Regler le sinistre de test",
      code: { model: "fournisseur/modele-test", prompt_version: null },
    };
    const reponse = await coeur.evaluer({
      tool_announced: tool,
      tool_original: original,
      server_alias: "sap",
      arguments: args,
      class: classe,
      delegation,
      intent: capture.intent,
      code: { model: capture.code.model, prompt_version: null, policy_version: coeur.versionPolitique, recorder: "0.1.0" },
      context: capture.context,
    });
    if (reponse.decision === "refuse") return { refus: await coeur.scellerRefus(capture, reponse) };
    if (reponse.ticket_state === "nouveau") return { retenue: await coeur.scellerRetenue(capture, reponse, args), reponse };
    if (reponse.ticket_state === "en_attente") return { attente: true };
    const relais = await coeur.preparerRelais(capture, { reponse, argumentsEnClair: args, upstream_id: "e-000000000001" });
    horloge.avancer(200);
    const r = pieceJson(resultat);
    return { relaye: await coeur.terminerRelais(relais, { resultat: r, resultatRedige: resultat, argumentsRediges: args, duration_ms: 200, is_error: false }), intention: relais.intention };
  }

  before(async function () {
    dir = repertoireTemporaire();
    ({ config } = configurationDev(dir, { journal_id: N.octetsVersHex(N.keccak256(N.utf8("journal-coeur-test"))) }));
    config.checkpoint_interval_s = 60;
    const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(config)));
    expect(v.erreurs).to.deep.equal([]);
    config = v.config;
    horloge = new HorlogeReglable(ms("2026-11-10T10:14:02.100Z"));
    service = new ServiceApprobationFactice({
      org_id: config.recorder.org_id,
      journal_id: config.recorder.journal_id,
      decider: (r) => {
        if (r.tool_announced === "sap__payments.create") return { decision: "a_approuver", rule: "paiement > 5000 CHF" };
        if (r.tool_announced === "sap__claims.delete") return { decision: "refuse", rule: "suppression interdite" };
        return { decision: "autorise", rule: null };
      },
    });
    ancrage = new AncrageMemoire();
    worm = new SupportWormMemoire();
    coeur = await Coeur.demarrer({ config, secrets: secretsDev(), horloge, service, ancrage, worm });
    coeur.definirOutils([
      { tool_announced: "sap__claims.get", tool_original: "claims.get", server_alias: "sap", class: "lecture", effects: null },
      { tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", class: "ecriture", effects: null },
    ]);

    // Échange de modèle.
    horloge.aller(ms("2026-11-10T10:14:05.000Z"));
    const req = pieceJson({ model: "modele-test", messages: [{ role: "user", content: "Traite le sinistre." }] });
    const rep = pieceJson({ content: [{ type: "text", text: "Je lis le sinistre." }], stop_reason: "tool_use" });
    const prompt = pieceTexte("prompt systeme de test");
    for (const p of [req, rep, prompt]) await coeur.ecrirePiece(p);
    ev.echange = await coeur.scellerEchange({ delegation, code: { model: "fournisseur/modele-test", prompt_version: prompt.sha256 }, intent: "Je lis le sinistre.", requete: req.reference, reponse: rep.reference, duration_ms: 900, is_error: false });
    // Points alignés à 10:15:00 et 10:16:00 (à 1 s près, EX-12.24).
    horloge.aller(ms("2026-11-10T10:15:00.400Z"));
    await coeur.tic();
    ev.lecture = (await appel("sap__claims.get", "claims.get", "lecture", { claim_id: "2026-81044" }, "2026-11-10T10:15:10.000Z", { content: [{ type: "text", text: "Sinistre ouvert" }], isError: false })).relaye;
    ev.refus = (await appel("sap__claims.delete", "claims.delete", "ecriture", { claim_id: "2026-81044" }, "2026-11-10T10:15:20.000Z")).refus;
    const r1 = await appel("sap__payments.create", "payments.create", "ecriture", { claim_id: "2026-81044", amount: "7400.00", currency: "CHF" }, "2026-11-10T10:15:30.000Z");
    ev.retenue = r1.retenue.evenement;
    await new Promise((r) => setTimeout(r, 50));
    horloge.aller(ms("2026-11-10T10:16:00.300Z"));
    await coeur.tic();
    // Ré-émission pendant l'attente : aucun événement.
    expect((await appel("sap__payments.create", "payments.create", "ecriture", { claim_id: "2026-81044", amount: "7400.00", currency: "CHF" }, "2026-11-10T10:16:10.000Z")).attente).to.equal(true);
    // Les approbateurs votent ; la remise est vérifiée (SG-1 à SG-7) et scellée.
    service.decider_ticket(r1.reponse.ticket, { reason: "Pieces validees" });
    horloge.aller(ms("2026-11-10T10:20:00.000Z"));
    const acq = await coeur.traiterRemises();
    expect(acq.map((x) => x.result)).to.deep.equal(["scelle"]);
    ev.decision = coeur.index.decisions.get(r1.reponse.ticket);
    // Ré-émission approuvée : RL-1 à RL-4, intention, relais, consommer.
    const r2 = await appel("sap__payments.create", "payments.create", "ecriture", { claim_id: "2026-81044", amount: "7400.00", currency: "CHF" }, "2026-11-10T10:20:10.000Z", {
      content: [{ type: "text", text: "Paiement PAY-2026-11111 cree" }],
      structuredContent: { payment_id: "PAY-2026-11111" },
      isError: false,
    });
    ev.relaye = r2.relaye;
    ev.intention = r2.intention;
    // Seconde ré-émission : RL-3 (approbation déjà servie) la refuse.
    try {
      await appel("sap__payments.create", "payments.create", "ecriture", { claim_id: "2026-81044", amount: "7400.00", currency: "CHF" }, "2026-11-10T10:20:20.000Z", {});
      ev.rl3 = null;
    } catch (e) {
      ev.rl3 = e;
    }
    // Rotation de clé (EX-11.15) puis encore un appel, signé par la nouvelle clé.
    horloge.aller(ms("2026-11-10T10:30:00.000Z"));
    ev.rotation = await coeur.tournerCle("rec-test-02");
    ev.apres = (await appel("sap__claims.get", "claims.get", "lecture", { claim_id: "2026-81045" }, "2026-11-10T10:31:00.000Z", { content: [], isError: false })).relaye;
    // Clôture de la période à 11:00:00.250.
    horloge.aller(ms("2026-11-10T11:00:00.250Z"));
    await coeur.tic();
    await new Promise((r) => setTimeout(r, 50));
  });

  after(async function () {
    await coeur?.arreter();
  });

  it("les événements ont les sortes, statuts et champs attendus (7.2, 9.1)", function () {
    expect(ev.echange.seq).to.equal(2);
    expect(ev.lecture.execution.status).to.equal("executee");
    expect(ev.lecture.policy).to.deep.equal({ rule: null, decision: "autorise", ticket: null, redaction: null });
    expect(ev.lecture.effects).to.deep.equal([]);
    expect(ev.refus.execution.status).to.equal("refusee");
    expect(ev.refus.policy.decision).to.equal("refuse");
    expect(ev.retenue.execution.status).to.equal("retenue");
    expect(ev.decision.approval.at).to.equal(ev.decision.ts);
    expect(ev.decision.approval.request_hash).to.equal(ev.retenue.hash);
    expect(ev.relaye.policy).to.deep.equal({ ...ev.retenue.policy });
    expect(ev.relaye.approval).to.deep.equal(ev.decision.approval);
    // Gabarit d'effets de sap/payments.create dans l'exemple de 15.3, évalué sur les valeurs rédigées (EX-7.6).
    expect(ev.relaye.effects).to.deep.equal([{ system: "SAP", action: "ecriture", object: "PAY-2026-11111", amount: "7400.00", currency: "CHF" }]);
    expect(ev.intention.intent_id).to.match(/^i-0{19}1-0{11}1$/);
    expect(ev.rl3).to.be.instanceOf(ErreurEnregistreur);
    expect(ev.rl3.donnees.verification).to.equal("RL-3");
    expect(ev.rotation.execution.tool).to.equal("noortrace.journal.rotation-cle");
    expect(ev.rotation.recorder_key_id).to.equal("rec-test-01");
    expect(ev.apres.recorder_key_id).to.equal("rec-test-02");
    const outils = service.messages.map((m) => m.methode);
    for (const m of ["charger", "evaluer", "ouvrir", "decisions", "acquitter", "consommer"]) expect(outils).to.include(m);
  });

  it("le journal vérifie (CT-1 §7, E-1 à E-11, rotation E-10) et ses points de contrôle forment une série valide (CT-1 §10.5)", async function () {
    const evts = await lireEvenements(coeur.repertoire);
    expect(evts[0].execution.tool).to.equal("noortrace.journal.politique");
    const cles = JSON.parse(fs.readFileSync(path.join(dir, "dossier", "cles.json"), "utf8"));
    const r = N.verifierJournal(evts, cles);
    expect(r.valide, JSON.stringify(r.diagnostics ?? r)).to.equal(true);
    const m = JSON.parse(fs.readFileSync(path.join(coeur.repertoire, "manifestes", "periode-1794304800.json"), "utf8"));
    const sig = JSON.parse(fs.readFileSync(path.join(coeur.repertoire, "manifestes", "periode-1794304800.sig"), "utf8"));
    expect(m.count).to.equal(evts.length);
    expect(m.recorder_key_id).to.equal("rec-test-02");
    expect(N.verifierSignatureManifeste(m, sig.sig, await coeur.signataire.clePublique("rec-test-02"))).to.equal(true);
    const serie = fs.readFileSync(path.join(coeur.repertoire, "points", "periode-1794304800.ndjson"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    expect(serie.map((p) => p.checkpoint_ts)).to.deep.equal(["2026-11-10T10:15:00.400Z", "2026-11-10T10:16:00.300Z", "2026-11-10T11:00:00.250Z"]);
    const s = N.verifierSeriePointsDeControle(serie, m, evts, cles);
    expect(s.valide, s.errors.join(" ; ")).to.equal(true);
    expect(ancrage.points.length).to.be.greaterThan(3);
    expect(ancrage.clotures.map((c) => c.periodHash)).to.include(N.hacherManifeste(m));
    // Copies WORM demandées à la fermeture (EX-12.16, interface) : segment, manifeste, signature, série.
    expect(worm.copies.map((c) => [c.nature, c.cle])).to.deep.include.members([
      ["segment", "segments/seg-0000000000000001-00000000000000000001.ndjson"],
      ["manifeste", "manifestes/periode-1794304800.json"],
      ["signature", "manifestes/periode-1794304800.sig"],
      ["points", "points/periode-1794304800.ndjson"],
    ]);
  });

  before(async function () {
    // Export du dossier de l'appel relayé après approbation (période close).
    await coeur.exporterDossier(ev.relaye.seq, path.join(dir, "dossier"));
  });

  it("le dossier exporté de l'appel relayé est valide pour la bibliothèque noyau (contrôles 4, 5, 8 hors périmètre)", function () {
    const r = verifierRepertoireDossier(path.join(dir, "dossier"));
    expect(r.verdict, JSON.stringify(r.controles_en_echec)).to.equal("valide");
    expect(r.controles_en_echec).to.deep.equal([]);
    const index = JSON.parse(fs.readFileSync(path.join(dir, "dossier", "dossier.json"), "utf8"));
    expect(index.parts.map((p) => [p.name, p.present])).to.deep.equal([
      ["evenement", true], ["voisins", true], ["chemin", true], ["manifeste", true], ["manifeste_sig", true], ["cles", true],
      ["approbations", true], ["jeton_rfc3161", false], ["preuve_ots", false], ["registre", false], ["certificat_commit", false],
      ["validateurs", false], ["points_de_controle", true],
    ]);
  });

  it("le dossier exporté est valide pour le binaire Go noortrace-verifier (go1.27.3)", function () {
    const bin = construireVerificateur(dir);
    if (!bin) this.skip();
    const r = spawnSync(bin, [path.join(dir, "dossier"), "--json"], { encoding: "utf8" });
    expect(r.status, r.stdout + r.stderr).to.equal(0);
    const rapport = JSON.parse(r.stdout);
    expect(rapport.verdict).to.equal("valide");
    expect(rapport.failed_checks).to.deep.equal([]);
    const statuts = Object.fromEntries(rapport.controls.map((c) => [c.number, [c.status, c.reason ?? null]]));
    for (const id of [1, 2, 3, 6, 7]) expect(statuts[id][0], `contrôle ${id}`).to.equal("reussi");
    for (const id of [4, 5, 8]) expect(statuts[id]).to.deep.equal(["non_execute", "hors_perimetre_version"]);
  });
});

// Relecture adversariale A, R-A-11 (EX-17.5) : sans WORM, aucun contrôle
// périodique ne tournait ; avec WORM, la relecture quotidienne ne vérifiait
// que la clé courante (segments signés avant une rotation tenus pour faux).
describe("enregistreur, cœur : contrôles périodiques d'EX-17.5 sans WORM, avec toutes les clés de la chaîne (R-A-11)", function () {
  this.timeout(60000);
  const delegation = { launched_by: "x", on_behalf_of: null, scope: "s", run_id: null };
  async function echange(c, k) {
    const p = pieceJson({ k });
    await c.ecrirePiece(p);
    return c.scellerEchange({ delegation, code: { model: null, prompt_version: null }, intent: null, requete: p.reference, reponse: p.reference, duration_ms: k, is_error: false });
  }
  async function journal() {
    const dir = repertoireTemporaire("noortrace-controles-");
    const { config } = configurationDev(dir);
    const h = new HorlogeReglable(ms("2026-11-10T10:14:00.000Z"));
    const c = await Coeur.demarrer({ config: validerConfiguration(new TextEncoder().encode(JSON.stringify(config))).config, secrets: secretsDev(), horloge: h });
    await echange(c, 1);
    h.aller(ms("2026-11-10T11:00:00.300Z"));
    await c.tic();
    await echange(c, 2);
    await c.tournerCle("rec-test-02");
    await echange(c, 3);
    h.aller(ms("2026-11-10T12:00:00.300Z"));
    await c.tic();
    h.aller(ms("2026-11-10T12:00:20.000Z"));
    return { c, h };
  }
  const checks = (c) => c.journal.trouver("integrity_check").map((l) => [l.data.check, l.data.ok]);

  it("toutes les heures (manifeste, signature, continuité, signataire) et une fois par jour (relecture des segments fermés, clés d'avant et d'après la rotation) : en réussite, sans support WORM", async function () {
    const { c } = await journal();
    try {
      expect(c.o.worm ?? null).to.equal(null);
      await c.controles.tic();
      const r = checks(c);
      for (const k of ["manifeste", "signature", "continuite", "signataire", "relecture"]) expect(r, k).to.deep.include([k, true]);
      expect(r.filter(([, ok]) => !ok)).to.deep.equal([]);
      expect(c.journal.trouver("integrity_check").filter((l) => l.data.check === "relecture").map((l) => l.data.segment)).to.have.length(2);
    } finally {
      await c.arreter();
    }
  });

  it("un segment fermé altéré est signalé par la relecture quotidienne (integrity_check en échec, métrique)", async function () {
    const { c, h } = await journal();
    try {
      const seg = path.join(c.repertoire, "segments", fs.readdirSync(path.join(c.repertoire, "segments")).sort()[0]);
      fs.writeFileSync(seg, fs.readFileSync(seg, "utf8").replace('"duration_ms":1,', '"duration_ms":7,'));
      h.aller(ms("2026-11-11T00:00:20.000Z"));
      await c.controles.quotidien(c.horlogeBrute.murale());
      const echec = c.journal.trouver("integrity_check").find((l) => l.data.check === "relecture" && !l.data.ok);
      expect(echec?.data.raison).to.equal("hash_different");
      expect(c.metriques.exposer()).to.match(/noortrace_integrity_check_failures_total\{check="relecture"\} 1/);
    } finally {
      await c.arreter();
    }
  });
});
