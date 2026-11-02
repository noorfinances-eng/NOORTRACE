// Parcours de bout en bout de la rédaction (CT-2 §10, lot « rédaction ») :
// un frontal simulé fidèlement (contrat d'INTERFACES.md, sections a, b et e)
// fait traverser le cœur à des captures qui portent des données sensibles :
// échange de modèle (prompt système, requête en mode `reference`, réponse,
// intention rédigée), lecture, appel d'écriture soumis à approbation avec un
// motif de décision qui contient un IBAN et une adresse (EX-10.24), relais
// après approbation avec un gabarit d'effets, `run_id` déclaré refusé
// (EX-7.2). Les pièces sont rédigées avant hachage par la politique `pii-v1`
// publiée (10.9), dans les fils de calcul (EX-3.6), avec le coffre chiffré
// activé (EX-10.22).
//
// Vérifié : aucun clair ni hachage sans clé du clair dans le stockage du
// journal, le journal d'exploitation et les métriques (EX-10.2) ;
// `policy.redaction` (EX-10.20) ; idempotence des pièces stockées (EX-10.15) ;
// journal accepté par la bibliothèque noyau ; dossier de l'appel relayé,
// avec ses pièces rédigées fournies à part (E-6), accepté par le noyau ET
// par le binaire Go `noortrace-verifier` (go1.27.3, construit par
// verificateur/scripts/construire.sh ; sans lui, ce test est en attente).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import { verifierRepertoireDossier } from "@noortrace/noyau/dossier-fichiers";
import {
  Coeur, HorlogeReglable, Redacteur, controleRedaction, controleSecretsRedaction, validerConfiguration, resoudreSecrets,
  pieceJson, pieceTexte, lireEvenements, JETON_PROMPT_SYSTEME, PolitiqueCompilee, produirePiece, analyserJsonIntegral,
} from "@noortrace/enregistreur";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { RACINE, configurationDev, repertoireTemporaire, CLE_MAC_HEX } from "./fixtures/enregistreur-coeur/outils.mjs";

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

/** Tous les fichiers ordinaires sous un répertoire. */
function fichiers(dir) {
  const sortie = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) sortie.push(...fichiers(p));
    else if (e.isFile()) sortie.push(p);
  }
  return sortie;
}

// Données sensibles des captures, et leurs formes normalisées (10.3).
const IBAN = "CH93 0076 2011 6238 5295 7";
const IBAN_N = "CH9300762011623852957";
const COURRIEL = "j.dupont@example.ch";
const TELEPHONE = "+41 44 123 45 67";
const TELEPHONE_N = "+41441234567";
const AVS = "756.1234.5678.97";
const CARTE = "3782 822463 10005";
const SENSIBLES = [IBAN, IBAN_N, COURRIEL, TELEPHONE, TELEPHONE_N, AVS, "7561234567897", CARTE, "378282246310005", "support@assureur-demo.example"];

/**
 * Frontal simulé : il suit le contrat du cœur pour un frontal MCP et un
 * frontal modèle (INTERFACES.md a, b) et remet chaque valeur au rédacteur
 * avant toute pièce (section e).
 */
class FrontalSimule {
  constructor(coeur, red, hote) {
    this.coeur = coeur;
    this.red = red;
    this.hote = hote;
    this.n = 0;
  }

  async delegation(runIdDeclare) {
    // EX-7.2 : un run_id déclaré n'entre que s'il passe le motif et les détecteurs.
    const admis = await this.red.admettreRunId(runIdDeclare);
    if (!admis) this.coeur.journal.consigner("warning", "frontal_mcp", "delegation_refused", { field: "run_id" });
    return { launched_by: this.hote.launched_by, on_behalf_of: this.hote.on_behalf_of, scope: this.hote.scope, run_id: admis ? runIdDeclare : null };
  }

  /** Échange de modèle par la passerelle (5.3.1), prompt en mode `reference` (EX-8.5). */
  async echange({ requete, reponse, runId }) {
    const delegation = await this.delegation(runId);
    const prompt = await this.red.redigerPromptSysteme(requete.system, { id: "echange" });
    const req = await this.red.redigerPiece({ genre: "json", portee: "requete", valeur: { ...requete, system: JETON_PROMPT_SYSTEME }, origine: requete });
    const rep = await this.red.redigerPiece({ genre: "json", portee: "reponse", valeur: reponse, avecValeur: true });
    // Intention tirée de la réponse rédigée (EX-5.21, EX-10.18) : une référence si elle diffère du texte en clair.
    const texteClair = reponse.content.filter((b) => b.type === "text").map((b) => b.text).join("\n");
    const texteRedige = rep.valeur.content.filter((b) => b.type === "text").map((b) => b.text).join("\n");
    let intent = texteRedige;
    const pieces = [prompt.piece, req.piece, rep.piece];
    if (texteRedige !== texteClair) {
      const p = await this.red.redigerPiece({ genre: "texte", portee: "reponse", texte: texteRedige, origine: texteClair });
      pieces.push(p.piece);
      intent = p.piece.reference;
    }
    for (const p of pieces) await this.coeur.ecrirePiece(p);
    return this.coeur.scellerEchange({
      delegation,
      code: { model: `fournisseur/${rep.valeur.model}`, prompt_version: prompt.piece.sha256 },
      intent,
      requete: req.piece.reference,
      reponse: rep.piece.reference,
      duration_ms: 850,
      is_error: false,
    });
  }

  /** Appel d'outil (4.4 pas 1 à 14) vers un serveur amont simulé. */
  async appel({ tool, original, classe, args, amont, runId, horloge }) {
    const id = `e-${String(++this.n).padStart(12, "0")}`;
    const delegation = await this.delegation(runId);
    const definition = { name: tool, description: `outil ${original}`, inputSchema: { type: "object" } };
    const pDef = pieceJson(definition, { media_type: "application/json" });
    const pListe = pieceJson({ tools: [definition] }, { media_type: "application/json" });
    // Pas 3 : évaluation, arguments en clair, en mémoire seulement.
    const reponse = await this.coeur.evaluer({
      tool_announced: tool,
      tool_original: original,
      server_alias: "sap",
      arguments: args,
      class: classe,
      delegation,
      intent: null,
      code: { model: null, prompt_version: null, policy_version: this.coeur.versionPolitique, recorder: "0.1.0" },
      context: [pDef.referenceContexte(), pListe.referenceContexte()],
    });
    // Pas 4 : rédaction, puis pièce écrite avant tout relais.
    const ra = await this.red.redigerArguments(args, { outil: tool, alias: "sap", id, host: this.hote.id });
    if (reponse.decision !== "refuse" && reponse.ticket_state !== "en_attente") {
      this.red.bloquerArgumentsNonRedigeables(ra, { classe, susceptible: this.coeur.susceptible(tool), id });
    }
    for (const p of [ra.piece, pDef, pListe]) await this.coeur.ecrirePiece(p);
    const capture = {
      host: this.hote,
      delegation,
      tool_announced: tool,
      tool_original: original,
      server_alias: "sap",
      class: classe,
      arguments: ra.piece.reference,
      context: [pDef.referenceContexte(), pListe.referenceContexte()],
      intent: null,
      code: { model: null, prompt_version: null },
    };
    if (reponse.decision === "refuse") return { refus: await this.coeur.scellerRefus(capture, reponse) };
    if (reponse.ticket_state === "nouveau") return { retenue: await this.coeur.scellerRetenue(capture, reponse, args), reponse };
    if (reponse.ticket_state === "en_attente") return { attente: true };
    const relais = await this.coeur.preparerRelais(capture, { reponse, argumentsEnClair: args, upstream_id: id });
    horloge.avancer(300);
    const resultat = amont(args);
    const rr = await this.red.redigerResultat(resultat, { outil: tool, alias: "sap", id, host: this.hote.id });
    const e = await this.coeur.terminerRelais(relais, {
      resultat: rr.piece,
      resultatRedige: rr.valeur,
      argumentsRediges: ra.valeur,
      duration_ms: 300,
      is_error: false,
      sourceNonRedigeable: ra.non_redigeable !== null || rr.non_redigeable !== null,
    });
    return { relaye: e };
  }
}

describe("enregistreur, rédaction : parcours de bout en bout (pii-v1), journal vérifié par le noyau et par le binaire Go", function () {
  this.timeout(180000);
  let dir;
  let coeur;
  let red;
  let horloge;
  let service;
  let config;
  let env;
  const ev = {};

  const hote = { id: "agent-sinistres-stdio", launched_by: "agent-sinistres", on_behalf_of: null, scope: "sinistres:lecture,paiement" };
  const argsPaiement = { claim_id: "2026-81044", amount: "7400.00", currency: "CHF", beneficiary_iban: IBAN, note: `Assuré ${AVS}, contact ${COURRIEL}` };
  const resultatPaiement = { content: [{ type: "text", text: `Paiement PAY-2026-90417 créé ; avis envoyé à ${COURRIEL}` }], structuredContent: { payment_id: "PAY-2026-90417" }, isError: false };

  before(async function () {
    dir = repertoireTemporaire("noortrace-redaction-parcours-");
    ({ config, env } = configurationDev(dir, { journal_id: N.octetsVersHex(N.keccak256(N.utf8("journal-redaction-test"))) }));
    config.storage.vault = { enabled: true, path: path.join(dir, "coffre"), key: { env: "NOORTRACE_TEST_CLE_COFFRE", encoding: "hex" } };
    env.NOORTRACE_TEST_CLE_COFFRE = crypto.createHash("sha256").update("noortrace/tests/redaction/cle-coffre").digest("hex");
    const v = validerConfiguration(N.utf8(JSON.stringify(config)), { reglesSupplementaires: [controleRedaction] });
    expect(v.erreurs).to.deep.equal([]);
    config = v.config;
    expect(config.policy.redaction.name).to.equal("pii-v1");
    const s = resoudreSecrets(config, { env });
    expect([...s.erreurs, ...controleSecretsRedaction(config, s.secrets)]).to.deep.equal([]);
    expect(Buffer.from(s.secrets.get("/storage/relay_mac_key")).toString("hex")).to.equal(CLE_MAC_HEX);
    horloge = new HorlogeReglable(ms("2026-11-10T10:14:02.100Z"));
    service = new ServiceApprobationFactice({
      org_id: config.recorder.org_id,
      journal_id: config.recorder.journal_id,
      decider: (r) => (r.tool_announced === "sap__payments.create" ? { decision: "a_approuver", rule: "paiement > 5000 CHF" } : { decision: "autorise", rule: null }),
    });
    red = Redacteur.depuisConfiguration(config, s.secrets, { fils: 2 });
    coeur = await Coeur.demarrer({ config, secrets: s.secrets, horloge, service, redaction: red, reglesSupplementaires: [controleRedaction] });
    coeur.definirOutils([
      { tool_announced: "sap__claims.get", tool_original: "claims.get", server_alias: "sap", class: "lecture", effects: null },
      { tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", class: "ecriture", effects: null },
    ]);
    const f = new FrontalSimule(coeur, red, hote);

    // Échange de modèle : prompt système, message de l'utilisateur et réponse portent des données sensibles.
    horloge.aller(ms("2026-11-10T10:14:05.000Z"));
    ev.echange = await f.echange({
      runId: "run-demo-0001",
      requete: {
        model: "modele-demo-1",
        max_tokens: 1024,
        system: "Tu es l'agent sinistres. Contact interne : support@assureur-demo.example (jamais communiqué).",
        messages: [{ role: "user", content: `Rappeler l'assuré au ${TELEPHONE} ; carte ${CARTE}.` }],
      },
      reponse: { id: "msg_1", type: "message", role: "assistant", model: "modele-demo-1", content: [{ type: "text", text: `Je règle le sinistre sur ${IBAN}.` }], stop_reason: "end_turn" },
    });
    // Lecture : le résultat porte un IBAN et un téléphone.
    ev.lecture = (
      await f.appel({
        tool: "sap__claims.get",
        original: "claims.get",
        classe: "lecture",
        args: { claim_id: "2026-81044" },
        runId: "run-demo-0001",
        horloge,
        amont: () => ({ content: [{ type: "text", text: `Assuré joignable au ${TELEPHONE}, IBAN ${IBAN}` }], isError: false }),
      })
    ).relaye;
    // Écriture soumise à approbation : retenue, avec un run_id déclaré qui porte un téléphone (refusé, EX-7.2).
    horloge.aller(ms("2026-11-10T10:15:30.000Z"));
    const r1 = await f.appel({ tool: "sap__payments.create", original: "payments.create", classe: "ecriture", args: argsPaiement, runId: `run${TELEPHONE_N}`, horloge });
    ev.retenue = r1.retenue.evenement;
    await new Promise((r) => setTimeout(r, 50));
    // Décision : le motif de l'approbateur contient un IBAN et une adresse (EX-10.24).
    service.decider_ticket(r1.reponse.ticket, { reason: `Pièces vérifiées : IBAN ${IBAN} confirmé par ${COURRIEL}` });
    horloge.aller(ms("2026-11-10T10:20:00.000Z"));
    const acq = await coeur.traiterRemises();
    expect(acq.map((x) => x.result)).to.deep.equal(["scelle"]);
    ev.acquittement = acq[0];
    ev.decision = coeur.index.decisions.get(r1.reponse.ticket);
    // Ré-émission approuvée : relais, résultat rédigé, effets du gabarit sur les valeurs rédigées.
    ev.relaye = (await f.appel({ tool: "sap__payments.create", original: "payments.create", classe: "ecriture", args: argsPaiement, runId: `run${TELEPHONE_N}`, horloge, amont: () => resultatPaiement })).relaye;
    // Clôture de la période.
    horloge.aller(ms("2026-11-10T11:00:00.250Z"));
    await coeur.tic();
    await coeur.exporterDossier(ev.relaye.seq, path.join(dir, "dossier"));
  });

  after(async function () {
    await coeur?.arreter();
    await red?.fermer();
  });

  it("les pièces des événements sont rédigées avant hachage ; policy.redaction vaut pii-v1 si et seulement si une référence est rédigée (EX-10.16, EX-10.20)", async function () {
    const evts = await lireEvenements(coeur.repertoire);
    expect(evts.map((e) => [e.execution.tool, e.execution.status])).to.deep.equal([
      ["noortrace.journal.politique", "executee"],
      ["noortrace.modele.echange", "executee"],
      ["sap__claims.get", "executee"],
      ["sap__payments.create", "retenue"],
      ["noortrace.approbation.decision", "executee"],
      ["sap__payments.create", "executee"],
    ]);
    for (const e of evts) {
      const refs = [e.execution.arguments, e.execution.result, ...(e.context ?? []), ...(e.intent && typeof e.intent === "object" ? [e.intent] : [])].filter(Boolean);
      const redige = refs.some((r) => r.redacted === true);
      expect(e.policy.redaction, `seq ${e.seq}`).to.equal(redige ? "pii-v1" : null);
    }
    expect(ev.echange.execution.arguments.redacted).to.equal(true);
    expect(ev.echange.intent.media_type).to.equal("text/plain");
    expect(ev.echange.delegation.run_id).to.equal("run-demo-0001");
    expect(ev.retenue.delegation.run_id).to.equal(null);
    expect(ev.lecture.execution.result.redacted).to.equal(true);
    const args = analyserJsonIntegral(await coeur.pieces.lire(ev.relaye.execution.arguments.sha256));
    expect(args).to.deep.equal({ amount: "7400.00", beneficiary_iban: "[REDIGE:iban]", claim_id: "2026-81044", currency: "CHF", note: "Assuré [REDIGE:avs], contact [REDIGE:email]" });
    // Effets du gabarit de 15.3 évalués sur les valeurs rédigées, dans un fil de calcul (EX-7.6).
    expect(ev.relaye.effects).to.deep.equal([{ system: "SAP", action: "ecriture", object: "PAY-2026-90417", amount: "7400.00", currency: "CHF" }]);
    // Motif de la décision rédigé avant scellement (EX-10.24), rendu tel quel au service par acquitter.
    expect(ev.decision.approval.reason).to.equal("Pièces vérifiées : IBAN [REDIGE:iban] confirmé par [REDIGE:email]");
    expect(ev.acquittement.approval.reason).to.equal(ev.decision.approval.reason);
    expect(ev.relaye.approval).to.deep.equal(ev.decision.approval);
  });

  it("aucun clair ni hachage sans clé du clair dans le stockage du journal, le journal d'exploitation et les métriques (EX-10.2)", function () {
    const interdits = SENSIBLES.flatMap((v) => [v, N.sha256Hex(N.utf8(v)).slice(2), N.octetsVersHex(N.keccak256(N.utf8(v))).slice(2)]);
    const lus = [...fichiers(path.join(config.storage.root)), config.supervision.ops_log.path, ...fichiers(path.join(dir, "dossier"))];
    expect(lus.length).to.be.greaterThan(15);
    for (const f of lus) {
      const t = fs.readFileSync(f).toString("utf8");
      for (const x of interdits) expect(t.includes(x), `${x} dans ${path.relative(dir, f)}`).to.equal(false);
    }
    const metriques = coeur.metriques.exposer();
    for (const x of interdits) expect(metriques).to.not.include(x);
    // Les comptes du journal d'exploitation sont là, sans valeur (EX-10.17).
    const appliquees = coeur.journal.trouver("redaction_applied");
    expect(appliquees.map((l) => l.data.scope)).to.include.members(["prompt_systeme", "requete", "reponse", "arguments", "resultat"]);
    expect(coeur.metriques.valeur("noortrace_redactions_total", { type: "iban", scope: "arguments" })).to.be.greaterThan(0);
    // Le test discrimine : sans la règle des arguments, le clair entrerait dans la pièce.
    const sansArguments = new PolitiqueCompilee({ ...config.policy.redaction, rules: config.policy.redaction.rules.slice(1) });
    const fuite = produirePiece(sansArguments, { genre: "json", portee: "arguments", outil: "sap__payments.create", valeur: argsPaiement }, { budgetMs: 1000 });
    expect(Buffer.from(fuite.piece.octets).toString()).to.include(IBAN);
  });

  it("réappliquer pii-v1 à chaque pièce rédigée stockée redonne ses octets (EX-10.15)", async function () {
    const evts = await lireEvenements(coeur.repertoire);
    const pii = new PolitiqueCompilee(config.policy.redaction);
    let n = 0;
    for (const e of evts) {
      for (const [ref, portee] of [[e.execution.arguments, e.execution.tool === "noortrace.modele.echange" ? "requete" : "arguments"], [e.execution.result, e.execution.tool === "noortrace.modele.echange" ? "reponse" : "resultat"]]) {
        if (!ref || ref.value !== undefined || ref.redacted !== true) continue;
        const octets = await coeur.pieces.lire(ref.sha256);
        const r = produirePiece(pii, { genre: "json", portee, outil: e.execution.tool, valeur: analyserJsonIntegral(octets) }, { budgetMs: 1000 });
        expect(Buffer.compare(Buffer.from(r.piece.octets), Buffer.from(octets)), `seq ${e.seq}`).to.equal(0);
        expect(r.redacted).to.equal(false);
        n++;
      }
    }
    expect(n).to.be.greaterThan(4);
  });

  it("coffre : un homologue chiffré par pièce rédigée, hors du journal ; déchiffrement à deux personnes seulement (EX-10.22, CT-7 EX-3.11)", async function () {
    const ref = ev.relaye.execution.arguments;
    const f = red.coffre.fichier(ref.sha256);
    expect(fs.existsSync(f)).to.equal(true);
    expect(path.relative(config.storage.root, f).startsWith("..")).to.equal(true);
    expect(coeur.journal.trouver("vault_enabled")).to.have.length(1);
    const registre = path.join(dir, "acces-coffre.ndjson");
    const demande = { par: "auditeur-1", motif: "demande de l'autorité, dossier 2026-81044" };
    let refus = null;
    try {
      await red.coffre.dechiffrer({ sha256: ref.sha256, demande, approbation: null, autorises: ["auditeur-1", "dpo"], registre });
    } catch (e) {
      refus = e;
    }
    expect(refus?.raison).to.equal("seconde_approbation_absente");
    const original = await red.coffre.dechiffrer({ sha256: ref.sha256, demande, approbation: { par: "dpo", sha256: ref.sha256, motif: demande.motif }, autorises: ["auditeur-1", "dpo"], registre });
    expect(analyserJsonIntegral(original)).to.deep.equal(argsPaiement);
    expect(fs.readFileSync(registre, "utf8").trim().split("\n").map((l) => JSON.parse(l).result)).to.deep.equal(["refuse", "accorde"]);
  });

  it("le journal vérifie pour la bibliothèque noyau (CT-1 §7, E-1 à E-11)", async function () {
    const evts = await lireEvenements(coeur.repertoire);
    const cles = JSON.parse(fs.readFileSync(path.join(dir, "dossier", "cles.json"), "utf8"));
    const r = N.verifierJournal(evts, cles);
    expect(r.valide, JSON.stringify(r.diagnostics ?? r)).to.equal(true);
  });

  /** Pièces de l'événement relayé, fournies à part, nommées par leur sha256 (E-6). */
  function piecesAPart() {
    const rep = path.join(dir, "pieces-a-part");
    fs.mkdirSync(rep, { recursive: true });
    const refs = [ev.relaye.execution.arguments, ev.relaye.execution.result, ...ev.relaye.context];
    for (const r of refs) fs.copyFileSync(coeur.pieces.chemin(r.sha256), path.join(rep, r.sha256.slice(2)));
    return { rep, refs };
  }

  it("le dossier de l'appel relayé, avec ses pièces rédigées, est valide pour la bibliothèque noyau (E-6 compris)", function () {
    const { rep, refs } = piecesAPart();
    const pieces = refs.map((r) => new Uint8Array(fs.readFileSync(path.join(rep, r.sha256.slice(2)))));
    const r = verifierRepertoireDossier(path.join(dir, "dossier"), { pieces });
    expect(r.verdict, JSON.stringify(r.controles_en_echec)).to.equal("valide");
    expect(r.controles_en_echec).to.deep.equal([]);
    // Une pièce altérée échoue à E-6 : le contrôle porte bien sur les octets rédigés.
    const altere = [...pieces];
    altere[0] = N.utf8(Buffer.from(pieces[0]).toString().replace("[REDIGE:iban]", "[REDIGE:ibam]"));
    const k = verifierRepertoireDossier(path.join(dir, "dossier"), { pieces: altere });
    expect(k.verdict).to.not.equal("valide");
  });

  it("le dossier de l'appel relayé, avec ses pièces rédigées (--pieces), est valide pour le binaire Go noortrace-verifier (go1.27.3)", function () {
    const bin = construireVerificateur(dir);
    if (!bin) this.skip();
    const { rep } = piecesAPart();
    const r = spawnSync(bin, [path.join(dir, "dossier"), "--pieces", rep, "--json"], { encoding: "utf8" });
    expect(r.status, r.stdout + r.stderr).to.equal(0);
    const rapport = JSON.parse(r.stdout);
    expect(rapport.verdict).to.equal("valide");
    expect(rapport.failed_checks).to.deep.equal([]);
    const statuts = Object.fromEntries(rapport.controls.map((c) => [c.number, [c.status, c.reason ?? null]]));
    for (const id of [1, 2, 3, 6, 7]) expect(statuts[id][0], `contrôle ${id}`).to.equal("reussi");
    for (const id of [4, 5, 8]) expect(statuts[id]).to.deep.equal(["non_execute", "hors_perimetre_version"]);
    expect(rapport.inputs.pieces.files).to.equal(4);
    // Le binaire relit bien les pièces : une pièce altérée rend le dossier invalide.
    const nom = ev.relaye.execution.arguments.sha256.slice(2);
    const brut = fs.readFileSync(path.join(rep, nom), "utf8");
    fs.writeFileSync(path.join(rep, nom), brut.replace("[REDIGE:iban]", "[REDIGE:ibam]"));
    const k = spawnSync(bin, [path.join(dir, "dossier"), "--pieces", rep, "--json"], { encoding: "utf8" });
    expect(k.status).to.equal(1);
    expect(JSON.parse(k.stdout).verdict).to.equal("invalide");
  });
});
