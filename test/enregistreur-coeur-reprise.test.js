// Reprise du cœur après arrêt brutal (CT-2 §12.4, §12.5, EX-9.8) : un
// processus enfant est tué (SIGKILL) pendant qu'il écrit, ou avec un relais
// d'écriture en vol (intention durable, événement absent) ; au redémarrage,
// la fin incomplète du dernier segment est tronquée (EX-12.10), l'intention
// ouverte devient un événement de reprise (EX-12.14), le bail d'un processus
// mort est repris avec une époque supérieure, et la chaîne reste valide. Une
// ligne dont le hash diffère est une corruption, jamais tronquée (EX-12.11) ;
// une intention dont l'événement est durable sans levée est levée
// implicitement (EX-12.14 pas 1) ; un fichier d'intention illisible au milieu
// est une corruption (EX-12.22).

import { expect } from "chai";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as N from "@noortrace/noyau";
import { Coeur, ErreurEnregistreur, HorlogeReglable, MagasinBailFichier, lireEvenements, validerConfiguration, pieceJson } from "@noortrace/enregistreur";
import { configurationDev, graine, repertoireTemporaire, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";

const ENFANT = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "enregistreur-coeur", "enfant.mjs");

function preparer(nom) {
  const dir = repertoireTemporaire(`noortrace-reprise-${nom}-`);
  const { config } = configurationDev(dir, { journal_id: N.octetsVersHex(N.keccak256(N.utf8(`journal-reprise-${nom}`))) });
  const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(config)));
  expect(v.erreurs).to.deep.equal([]);
  const chemin = path.join(dir, "configuration.json");
  fs.writeFileSync(chemin, JSON.stringify(v.config));
  return { dir, config: v.config, chemin };
}

/** Lance l'enfant et rend sa première ligne de sortie qui commence par `attendu`. */
function lancerEnfant(chemin, mode, attendu) {
  const p = spawn(process.execPath, [ENFANT, chemin, mode], { stdio: ["ignore", "pipe", "pipe"] });
  return new Promise((resoudre, rejeter) => {
    let tampon = "";
    let erreurs = "";
    p.stderr.on("data", (d) => (erreurs += d));
    p.stdout.on("data", (d) => {
      tampon += d;
      const ligne = tampon.split("\n").find((l) => l.startsWith(attendu));
      if (ligne) resoudre({ processus: p, ligne });
    });
    p.on("exit", (code) => rejeter(new Error(`enfant terminé (${code}) : ${erreurs}`)));
  });
}

function tuer(p) {
  return new Promise((r) => {
    p.removeAllListeners("exit");
    p.on("exit", () => r());
    p.kill("SIGKILL");
  });
}

function repertoireJournal(config) {
  return path.join(config.storage.root, config.recorder.org_id.slice(2), config.recorder.journal_id.slice(2));
}

function dernierSegment(config) {
  const d = path.join(repertoireJournal(config), "segments");
  return path.join(d, fs.readdirSync(d).sort().pop());
}

function cles() {
  return {
    version: 0,
    keys: [{ key_id: "rec-test-01", algorithm: "ed25519", public_key: "0xe2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045", valid_from: "2020-01-01T00:00:00.000Z", valid_to: null, source: "clé de test de CT-1 §13" }],
  };
}

describe("enregistreur, cœur : reprise après arrêt brutal", function () {
  this.timeout(60000);

  it("processus tué avec un relais d'écriture en vol et une fin de segment déchirée : troncature, événement de reprise, bail repris", async function () {
    const { config, chemin } = preparer("intention");
    const { processus, ligne } = await lancerEnfant(chemin, "intention", "INTENTION");
    const [, intentId, intentionSha] = ligne.trim().split(" ");
    await tuer(processus);
    // Écriture déchirée : une ligne sans \n en fin du dernier segment (EX-12.10).
    const seg = dernierSegment(config);
    const avant = fs.statSync(seg).size;
    fs.appendFileSync(seg, '{"approval":null,"code":{"model":null,"pol');
    const coeur = await Coeur.demarrer({ config, secrets: secretsDev() });
    try {
      expect(fs.statSync(seg).size, "segment tronqué à sa dernière ligne valide").to.equal(avant);
      const tronque = coeur.journal.trouver("segment_truncated");
      expect(tronque).to.have.length(1);
      expect(tronque[0].data.removed_bytes).to.equal(42);
      expect(coeur.ecrivain.epoque, "bail d'un processus mort repris, époque supérieure").to.equal(2);
      const evts = await lireEvenements(coeur.repertoire);
      const reprise = evts[evts.length - 1];
      expect(reprise.execution.tool).to.equal("sap__payments.create");
      expect(reprise.execution.status).to.equal("executee");
      expect(reprise.execution.is_error).to.equal(true);
      expect(reprise.execution.duration_ms).to.equal(0);
      expect(reprise.effects).to.have.length(1);
      const piece = await coeur.pieces.lire(reprise.execution.result.sha256);
      expect(JSON.parse(N.decoderUtf8(piece))).to.deep.equal({ intention_sha256: intentionSha, noortrace_reprise: "resultat inconnu : enregistreur arrete pendant le relais" });
      expect(coeur.journal.trouver("intent_recovered").map((l) => l.data.intent_id)).to.deep.equal([intentId]);
      const r = N.verifierJournal(evts, { ...cles(), org_id: config.recorder.org_id, journal_id: config.recorder.journal_id });
      expect(r.valide, JSON.stringify(r.diagnostics)).to.equal(true);
      expect(coeur.sante().corps.status).to.equal("ok");
    } finally {
      await coeur.arreter();
    }
    // Second redémarrage : rien à reprendre, intention levée.
    const c2 = await Coeur.demarrer({ config, secrets: secretsDev() });
    try {
      expect(c2.journal.trouver("intent_recovered")).to.have.length(0);
      expect(c2.ecrivain.epoque).to.equal(3);
    } finally {
      await c2.arreter();
    }
  });

  it("processus tué pendant une suite d'écritures : la chaîne reprend sans trou ni fourche", async function () {
    const { config, chemin } = preparer("boucle");
    const { processus } = await lancerEnfant(chemin, "boucle", "PRET");
    await new Promise((r) => setTimeout(r, 150));
    await tuer(processus);
    // Octets nuls de remplissage en fin de fichier (EX-12.11 : troncature admise).
    fs.appendFileSync(dernierSegment(config), Buffer.alloc(64));
    const coeur = await Coeur.demarrer({ config, secrets: secretsDev() });
    try {
      const avant = coeur.ecrivain.lastSeq;
      expect(avant).to.be.greaterThan(5);
      const evts = await lireEvenements(coeur.repertoire);
      expect(evts.map((e) => e.seq)).to.deep.equal(evts.map((_, k) => k + 1));
      expect(N.verifierJournal(evts, { ...cles(), org_id: config.recorder.org_id, journal_id: config.recorder.journal_id }).valide).to.equal(true);
      // Le cœur écrit de nouveau, à la suite.
      const p = pieceJson({ apres: true });
      await coeur.ecrirePiece(p);
      const e = await coeur.scellerEchange({ delegation: { launched_by: "x", on_behalf_of: null, scope: "s", run_id: null }, code: { model: null, prompt_version: null }, intent: null, requete: p.reference, reponse: p.reference, duration_ms: 1, is_error: false });
      expect(e.seq).to.equal(avant + 1);
    } finally {
      await coeur.arreter();
    }
  });

  it("une ligne dont le hash diffère est une corruption : rien n'est tronqué, l'écriture est bloquée (EX-12.11)", async function () {
    const { config } = preparer("corruption");
    const c1 = await Coeur.demarrer({ config, secrets: secretsDev() });
    const p = pieceJson({ a: 1 });
    await c1.ecrirePiece(p);
    for (let k = 0; k < 3; k++) {
      await c1.scellerEchange({ delegation: { launched_by: "x", on_behalf_of: null, scope: "s", run_id: null }, code: { model: null, prompt_version: null }, intent: null, requete: p.reference, reponse: p.reference, duration_ms: k, is_error: false });
    }
    await c1.arreter();
    const seg = dernierSegment(config);
    const texte = fs.readFileSync(seg, "utf8");
    const altere = texte.replace('"duration_ms":1,', '"duration_ms":9,');
    expect(altere).to.not.equal(texte);
    fs.writeFileSync(seg, altere);
    const c2 = await Coeur.demarrer({ config, secrets: secretsDev() });
    try {
      expect(fs.readFileSync(seg, "utf8")).to.equal(altere);
      expect(c2.journal.trouver("segment_corrupted")).to.have.length(1);
      expect(c2.sante().corps).to.include({ status: "degraded" });
      expect(c2.sante().corps.reasons).to.deep.equal(["stockage"]);
      let err;
      try {
        await c2.ecrirePiece(p);
      } catch (e) {
        err = e;
      }
      expect(err).to.be.instanceOf(ErreurEnregistreur);
      expect(err.raison).to.equal("stockage");
    } finally {
      await c2.arreter();
    }
  });

  it("intention dont l'événement est durable sans levée : levée implicite, aucun événement de reprise (EX-12.14 pas 1)", async function () {
    const { config } = preparer("implicite");
    const c1 = await Coeur.demarrer({ config, secrets: secretsDev() });
    const args = pieceJson({ claim_id: "1" });
    await c1.ecrirePiece(args);
    const appel = { host: { id: "agent-sinistres-stdio" }, delegation: { launched_by: "agent-sinistres", on_behalf_of: null, scope: "s", run_id: null }, tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", class: "ecriture", arguments: args.reference, context: [], intent: null, code: {} };
    const relais = await c1.preparerRelais(appel, { reponse: { rule: null, decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null }, argumentsEnClair: { claim_id: "1" }, upstream_id: "e-000000000001" });
    const e = await c1.terminerRelais(relais, { resultat: pieceJson({ content: [], isError: false }), resultatRedige: { content: [], isError: false }, argumentsRediges: { claim_id: "1" }, duration_ms: 3, is_error: false });
    await c1.arreter();
    // Arrêt simulé entre le fdatasync de l'événement et la levée : la ligne levée est retirée.
    const fi = path.join(repertoireJournal(config), "intentions", "intentions-00000000000000000001.ndjson");
    const lignes = fs.readFileSync(fi, "utf8").split("\n").filter(Boolean);
    expect(JSON.parse(lignes[2])).to.deep.equal({ lifted: relais.intention.intent_id, seq: e.seq });
    fs.writeFileSync(fi, lignes.slice(0, 2).join("\n") + "\n");
    const c2 = await Coeur.demarrer({ config, secrets: secretsDev() });
    try {
      expect(c2.journal.trouver("intention_levee_implicite")).to.have.length(1);
      expect(c2.journal.trouver("intent_recovered")).to.have.length(0);
      expect(c2.ecrivain.lastSeq).to.equal(e.seq);
    } finally {
      await c2.arreter();
    }
  });

  it("ligne d'intention illisible suivie d'autres lignes : corruption, écriture bloquée (EX-12.22)", async function () {
    const { config } = preparer("intention-corrompue");
    const c1 = await Coeur.demarrer({ config, secrets: secretsDev() });
    await c1.arreter();
    const fi = path.join(repertoireJournal(config), "intentions", "intentions-00000000000000000001.ndjson");
    fs.writeFileSync(fi, '{"intent_id":\n{"lifted":"i-00000000000000000001-000000000001","seq":1}\n');
    const c2 = await Coeur.demarrer({ config, secrets: secretsDev() });
    try {
      expect(c2.journal.trouver("intention_corrompue")).to.have.length(1);
      expect(c2.sante().corps.reasons).to.include("stockage");
    } finally {
      await c2.arreter();
    }
  });
  it("panne du signataire après relais : -31017, événement gardé en attente puis scellé à la sortie du mode « clé » (EX-4.46, EX-14.10, EX-14.11)", async function () {
    const { config } = preparer("attente");
    const coeur = await Coeur.demarrer({ config, secrets: secretsDev() });
    try {
      const args = pieceJson({ claim_id: "2" });
      await coeur.ecrirePiece(args);
      const appel = { host: { id: "agent-sinistres-stdio" }, delegation: { launched_by: "agent-sinistres", on_behalf_of: null, scope: "s", run_id: null }, tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", class: "ecriture", arguments: args.reference, context: [], intent: null, code: {} };
      const relais = await coeur.preparerRelais(appel, { reponse: { rule: null, decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null }, argumentsEnClair: { claim_id: "2" }, upstream_id: "e-000000000002" });
      const backend = coeur.signataire.backend;
      const signer = backend.signer.bind(backend);
      backend.signer = async () => {
        throw new Error("module injoignable");
      };
      let err;
      try {
        await coeur.terminerRelais(relais, { resultat: pieceJson({ content: [], isError: false }), resultatRedige: { content: [], isError: false }, argumentsRediges: { claim_id: "2" }, duration_ms: 5, is_error: false });
      } catch (e) {
        err = e;
      }
      expect(err).to.be.instanceOf(ErreurEnregistreur);
      expect(err.code).to.equal(-31017);
      expect(coeur.attente).to.have.length(1);
      expect(coeur.sante().corps).to.deep.include({ status: "down" });
      expect(coeur.journal.trouver("call_executed_not_durable")).to.have.length(1);
      // Le signataire répond de nouveau : sortie du mode « clé », l'attente est scellée, l'intention levée.
      backend.signer = signer;
      await coeur.tic();
      expect(coeur.attente).to.have.length(0);
      expect(coeur.sante().corps).to.deep.equal({ status: "ok" });
      const evts = await lireEvenements(coeur.repertoire);
      const dernier = evts[evts.length - 1];
      expect(dernier.execution.tool).to.equal("sap__payments.create");
      expect(dernier.execution.is_error).to.equal(false);
      const lignes = fs.readFileSync(path.join(coeur.repertoire, "intentions", "intentions-00000000000000000001.ndjson"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
      expect(lignes[lignes.length - 1]).to.deep.equal({ lifted: relais.intention.intent_id, seq: dernier.seq });
      expect(coeur.journal.trouver("pending_flushed")).to.have.length(1);
    } finally {
      await coeur.arreter();
    }
  });
  it("arrêt avec un événement en attente : au redémarrage, il est scellé à la place d'un événement de reprise (EX-4.46, EX-9.8)", async function () {
    const { config } = preparer("attente-redemarrage");
    const c1 = await Coeur.demarrer({ config, secrets: secretsDev() });
    const args = pieceJson({ claim_id: "3" });
    await c1.ecrirePiece(args);
    const appel = { host: { id: "agent-sinistres-stdio" }, delegation: { launched_by: "agent-sinistres", on_behalf_of: null, scope: "s", run_id: null }, tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", class: "ecriture", arguments: args.reference, context: [], intent: null, code: {} };
    const relais = await c1.preparerRelais(appel, { reponse: { rule: null, decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null }, argumentsEnClair: { claim_id: "3" }, upstream_id: "e-000000000003" });
    c1.signataire.backend.signer = async () => {
      throw new Error("module injoignable");
    };
    let err;
    try {
      await c1.terminerRelais(relais, { resultat: pieceJson({ content: [{ type: "text", text: "ok" }], isError: false }), resultatRedige: {}, argumentsRediges: {}, duration_ms: 7, is_error: false });
    } catch (e) {
      err = e;
    }
    expect(err.code).to.equal(-31017);
    await new Promise((r) => setTimeout(r, 50));
    await c1.arreter();
    const c2 = await Coeur.demarrer({ config, secrets: secretsDev() });
    try {
      expect(c2.journal.trouver("intent_recovered")).to.have.length(0);
      expect(c2.journal.trouver("pending_flushed")).to.have.length(1);
      const evts = await lireEvenements(c2.repertoire);
      const e = evts.find((x) => x.execution.tool === "sap__payments.create");
      expect(e.execution).to.deep.include({ status: "executee", is_error: false, duration_ms: 7 });
      expect(evts.filter((x) => x.execution.tool === "sap__payments.create")).to.have.length(1);
      expect(N.verifierJournal(evts, { ...cles(), org_id: config.recorder.org_id, journal_id: config.recorder.journal_id }).valide).to.equal(true);
    } finally {
      await c2.arreter();
    }
  });
});

// Défauts démontrés par la relecture adversariale A (cœur, stockage, bail) :
// chaque essai de la relecture est rejoué ici comme test de non-régression.
describe("enregistreur, cœur : non-régression de la relecture A (stockage, reprise, bail)", function () {
  this.timeout(120000);
  const ms = (t) => N.decoderHorodatage(t);
  const delegation = { launched_by: "x", on_behalf_of: null, scope: "s", run_id: null };
  const appelEcriture = (args) => ({ host: { id: "agent-sinistres-stdio" }, delegation: { launched_by: "agent-sinistres", on_behalf_of: null, scope: "s", run_id: null }, tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", class: "ecriture", arguments: args.reference, context: [], intent: null, code: {} });
  const autorise = { rule: null, decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null };
  async function echange(coeur, k) {
    const p = pieceJson({ k });
    await coeur.ecrirePiece(p);
    return coeur.scellerEchange({ delegation, code: { model: null, prompt_version: null }, intent: null, requete: p.reference, reponse: p.reference, duration_ms: k, is_error: false });
  }
  const clesJournal = (config) => ({
    version: 0,
    org_id: config.recorder.org_id,
    journal_id: config.recorder.journal_id,
    keys: [{ key_id: "rec-test-01", algorithm: "ed25519", public_key: N.octetsVersHex(N.clePubliqueEd25519(graine("rec-test-01"))), valid_from: "2020-01-01T00:00:00.000Z", valid_to: null, source: "clé de test de CT-1 §13" }],
  });
  /** Fait échouer (EIO) le prochain fdatasync une fois armé (essais essai-eio*.mjs de la relecture). */
  async function pannerDatasync() {
    const h = await fsp.open("/dev/null", "r");
    const Proto = Object.getPrototypeOf(h);
    await h.close();
    const orig = Proto.datasync;
    const etat = { arme: false };
    Proto.datasync = async function () {
      if (etat.arme) {
        etat.arme = false;
        const e = new Error("EIO: i/o error, fdatasync");
        e.code = "EIO";
        throw e;
      }
      return orig.call(this);
    };
    etat.restaurer = () => {
      Proto.datasync = orig;
    };
    return etat;
  }

  it("R-A-1 (CT-1 §10.2, EX-12.24, P-5) : arrêt brutal entre le manifeste et sa signature → au redémarrage, signature écrite sur les octets du manifeste, remise à l'ancrage et copies WORM refaites", async function () {
    const { config, chemin } = preparer("cloture-sig");
    const p = spawn(process.execPath, [ENFANT, chemin, "cloture-sig"], { stdio: ["ignore", "pipe", "pipe"] });
    let sortie = "";
    p.stdout.on("data", (d) => (sortie += d));
    const signal = await new Promise((r) => p.on("exit", (_, s) => r(s)));
    expect(signal).to.equal("SIGKILL");
    expect(sortie).to.match(/KILL rename .*manifestes\/periode-1794304800\.sig/);
    const dirM = path.join(repertoireJournal(config), "manifestes");
    expect(fs.existsSync(path.join(dirM, "periode-1794304800.json"))).to.equal(true);
    expect(fs.existsSync(path.join(dirM, "periode-1794304800.sig"))).to.equal(false);
    const octetsManifeste = fs.readFileSync(path.join(dirM, "periode-1794304800.json"));
    const remises = [];
    const copies = [];
    const ancrage = { remettrePoint: async () => {}, remettreCloture: async (r) => remises.push(r) };
    const worm = { copier: async (c) => (copies.push(c), { version_id: null }) };
    const coeur = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: new HorlogeReglable(ms("2026-11-10T11:05:00.000Z")), ancrage, worm });
    try {
      expect(fs.readFileSync(path.join(dirM, "periode-1794304800.json")).equals(octetsManifeste), "octets du manifeste inchangés").to.equal(true);
      const m = JSON.parse(octetsManifeste.toString("utf8"));
      const s = JSON.parse(fs.readFileSync(path.join(dirM, "periode-1794304800.sig"), "utf8"));
      expect(s.period_hash).to.equal(N.hacherManifeste(m));
      expect(s.recorder_key_id).to.equal(m.recorder_key_id);
      expect(N.verifierSignatureManifeste(m, s.sig, N.clePubliqueEd25519(graine("rec-test-01")))).to.equal(true);
      expect(coeur.journal.trouver("period_signature_restored").map((l) => l.data.period_start)).to.deep.equal([1794304800]);
      expect(remises.map((r) => r.manifeste.period_start)).to.deep.equal([1794304800]);
      for (const k of ["manifestes/periode-1794304800.json", "manifestes/periode-1794304800.sig", "points/periode-1794304800.ndjson"]) {
        expect(copies.map((c) => c.cle), k).to.include(k);
      }
      const evts = await lireEvenements(coeur.repertoire);
      const serie = fs.readFileSync(path.join(coeur.repertoire, "points", "periode-1794304800.ndjson"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
      const v = N.verifierSeriePointsDeControle(serie, m, evts, clesJournal(config));
      expect(v.valide, v.errors.join(" ; ")).to.equal(true);
      expect(coeur.sante().corps).to.deep.equal({ status: "ok" });
    } finally {
      await coeur.arreter();
    }
  });

  it("R-A-3 (EX-12.8) : fdatasync en erreur (EIO) pour un groupe de trois événements → refusés, segment tronqué à la dernière ligne synchronisée, la chaîne reprend sans eux", async function () {
    const { config } = preparer("eio");
    const coeur = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: new HorlogeReglable(ms("2026-11-10T10:14:00.000Z")) });
    const panne = await pannerDatasync();
    try {
      const e1 = await echange(coeur, 1);
      const ps = [2, 3, 4].map((k) => pieceJson({ k }));
      for (const x of ps) await coeur.ecrirePiece(x);
      panne.arme = true;
      const r = await Promise.allSettled(ps.map((x, i) => coeur.scellerEchange({ delegation, code: { model: null, prompt_version: null }, intent: null, requete: x.reference, reponse: x.reference, duration_ms: 100 + i, is_error: false })));
      expect(r.map((x) => x.status)).to.deep.equal(["rejected", "rejected", "rejected"]);
      expect(r.map((x) => x.reason.raison)).to.deep.equal(["stockage", "stockage", "stockage"]);
      expect(coeur.sante().corps.reasons).to.deep.equal(["stockage"]);
      await coeur.tic();
      const tronque = coeur.journal.trouver("segment_truncated");
      expect(tronque).to.have.length(1);
      expect(tronque[0].data).to.deep.include({ expected_seq: e1.seq + 1, raison: "durabilite_non_etablie" });
      expect(coeur.sante().corps).to.deep.equal({ status: "ok" });
      const e5 = await echange(coeur, 5);
      expect(e5.seq, "les lignes non synchronisées sont perdues").to.equal(e1.seq + 1);
      const evts = await lireEvenements(coeur.repertoire);
      expect(evts.map((e) => e.seq)).to.deep.equal(evts.map((_, k) => k + 1));
      expect(evts.filter((e) => e.execution.duration_ms >= 100)).to.have.length(0);
      expect(N.verifierJournal(evts, clesJournal(config)).valide).to.equal(true);
    } finally {
      panne.restaurer();
      await coeur.arreter();
    }
    // Redémarrage : relecture sans trou ni anomalie.
    const c2 = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: new HorlogeReglable(ms("2026-11-10T10:20:00.000Z")) });
    try {
      expect(c2.sante().corps).to.deep.equal({ status: "ok" });
    } finally {
      await c2.arreter();
    }
  });

  it("R-A-3 et R-A-4 (EX-12.8, EX-4.46, EX-14.10) : EIO sur le fdatasync d'un appel relayé → -31017, un seul événement « executee » pour l'appel, après la sortie du mode dégradé et après un redémarrage", async function () {
    const { config } = preparer("eio-relais");
    const coeur = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: new HorlogeReglable(ms("2026-11-10T10:14:00.000Z")) });
    const panne = await pannerDatasync();
    try {
      const args = pieceJson({ claim_id: "X", amount: "1.00", currency: "CHF" });
      await coeur.ecrirePiece(args);
      const relais = await coeur.preparerRelais(appelEcriture(args), { reponse: autorise, argumentsEnClair: { claim_id: "X" }, upstream_id: "e-000000000001" });
      const res = pieceJson({ content: [], isError: false });
      await coeur.ecrirePiece(res);
      panne.arme = true;
      let err;
      try {
        await coeur.terminerRelais(relais, { resultat: res, resultatRedige: { content: [], isError: false }, argumentsRediges: {}, duration_ms: 100, is_error: false });
      } catch (e) {
        err = e;
      }
      expect(err?.code).to.equal(-31017);
      expect(coeur.attente).to.have.length(1);
      await coeur.tic();
      await coeur.tic();
      expect(coeur.attente).to.have.length(0);
      const evts = await lireEvenements(coeur.repertoire);
      expect(evts.filter((e) => e.execution.tool === "sap__payments.create" && e.execution.status === "executee")).to.have.length(1);
    } finally {
      panne.restaurer();
      await coeur.arreter();
    }
    const c2 = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: new HorlogeReglable(ms("2026-11-10T10:30:00.000Z")) });
    try {
      const evts = await lireEvenements(c2.repertoire);
      expect(evts.filter((e) => e.execution.tool === "sap__payments.create" && e.execution.status === "executee"), "aucun second scellement au redémarrage").to.have.length(1);
      expect(c2.journal.trouver("intent_recovered")).to.have.length(0);
      expect(N.verifierJournal(evts, clesJournal(config)).valide).to.equal(true);
    } finally {
      await c2.arreter();
    }
  });

  it("R-A-4 (EX-14.10, EX-9.8) : démon tué pendant la reprise de l'attente, après le scellement et avant la suppression du fichier → l'événement n'est pas scellé deux fois", async function () {
    const { config, chemin } = preparer("attente-double");
    const c1 = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: new HorlogeReglable(ms("2026-11-10T10:14:00.000Z")) });
    const args = pieceJson({ claim_id: "Y" });
    await c1.ecrirePiece(args);
    const relais = await c1.preparerRelais(appelEcriture(args), { reponse: autorise, argumentsEnClair: { claim_id: "Y" }, upstream_id: "e-000000000002" });
    const signer = c1.signataire.backend.signer.bind(c1.signataire.backend);
    c1.signataire.backend.signer = async () => {
      throw new Error("module injoignable");
    };
    let err;
    try {
      await c1.terminerRelais(relais, { resultat: pieceJson({ content: [], isError: false }), resultatRedige: {}, argumentsRediges: {}, duration_ms: 100, is_error: false });
    } catch (e) {
      err = e;
    }
    expect(err?.code).to.equal(-31017);
    c1.signataire.backend.signer = signer;
    await new Promise((r) => setTimeout(r, 50));
    await c1.arreter();
    const p = spawn(process.execPath, [ENFANT, chemin, "reprise-attente"], { stdio: ["ignore", "pipe", "pipe"] });
    let sortie = "";
    p.stdout.on("data", (d) => (sortie += d));
    const signal = await new Promise((r) => p.on("exit", (_, s) => r(s)));
    expect(signal, sortie).to.equal("SIGKILL");
    expect(sortie).to.match(/KILL rm .*attente\/attente-0+1\.ndjson/);
    const c3 = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: new HorlogeReglable(ms("2026-11-10T10:30:00.000Z")) });
    try {
      const evts = await lireEvenements(c3.repertoire);
      expect(evts.filter((e) => e.execution.tool === "sap__payments.create" && e.execution.status === "executee")).to.have.length(1);
      expect(fs.readdirSync(path.join(c3.repertoire, "attente")).filter((n) => n < "attente-00000000000000000003"), "fichiers d'attente repris supprimés").to.deep.equal([]);
      expect(N.verifierJournal(evts, clesJournal(config)).valide).to.equal(true);
    } finally {
      await c3.arreter();
    }
  });

  it("R-A-9 (EX-12.22, EX-12.11, EX-9.8) : après intention_corrompue, le démarrage n'écrit plus rien (ni événement en attente, ni événement de politique)", async function () {
    const { config } = preparer("intervention");
    const h = new HorlogeReglable(ms("2026-11-10T10:14:00.000Z"));
    const c1 = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: h });
    await echange(c1, 1);
    await c1.arreter();
    const fi = path.join(repertoireJournal(config), "intentions", "intentions-00000000000000000001.ndjson");
    fs.appendFileSync(fi, '{"intent_id":"i-0000\n{"lifted":"i-x","seq":1}\n');
    const config2 = structuredClone(config);
    config2.policy.version = `${config.policy.version}-b`;
    h.avancer(60000);
    const avant = (await lireEvenements(repertoireJournal(config))).length;
    const c2 = await Coeur.demarrer({ config: config2, secrets: secretsDev(), horloge: h });
    try {
      expect(c2.journal.trouver("intention_corrompue")).to.have.length(1);
      expect(c2.sante().corps.reasons).to.deep.equal(["stockage"]);
      expect((await lireEvenements(repertoireJournal(config))).length, "aucun événement après la détection").to.equal(avant);
      expect(c2.journal.trouver("policy_announced")).to.have.length(0);
    } finally {
      await c2.arreter();
    }
  });

  describe("R-A-5 : magasin de bail `file` (13.2 : flock(LOCK_EX | LOCK_NB), EX-13.4, EX-13.10)", function () {
    const SCRIPT = `
      const [chemin, t0] = process.argv.slice(1);
      const { MagasinBailFichier } = await import(${JSON.stringify(path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "paquets", "enregistreur", "src", "bail.mjs"))});
      while (Date.now() < Number(t0)) {}
      const b = new MagasinBailFichier(chemin);
      try { const e = await b.acquerir(); console.log("ACQUIS " + process.pid + " " + e); await new Promise((r) => setTimeout(r, 1500)); }
      catch (e) { console.log("REFUS " + process.pid + " " + e.raison); }`;

    it("deux cœurs du même processus sur le même journal : le second est refusé (bail_non_detenu), aucune fourche", async function () {
      const { config } = preparer("deux-ecrivains");
      const h = new HorlogeReglable(ms("2026-11-10T10:14:00.000Z"));
      const A = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: h });
      try {
        await echange(A, 1);
        let err;
        try {
          const B = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: h });
          await B.arreter();
        } catch (e) {
          err = e;
        }
        expect(err).to.be.instanceOf(ErreurEnregistreur);
        expect(err.raison).to.equal("bail_non_detenu");
        expect(A.bail.valide()).to.equal(true);
        expect((await echange(A, 2)).seq).to.equal(3);
        expect(fs.readdirSync(path.join(A.repertoire, "segments"))).to.have.length(1);
      } finally {
        await A.arreter();
      }
      // Libéré par l'arrêt : un nouveau cœur le prend, époque supérieure.
      const C = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: h });
      expect(C.ecrivain.epoque).to.equal(2);
      await C.arreter();
    });

    it("un verrou qui porte le PID d'un processus sans rapport (PID repris) n'empêche pas l'acquisition ; le verrou tenu par un processus vivant l'empêche", async function () {
      const dir = repertoireTemporaire("noortrace-bail-pid-");
      const chemin = path.join(dir, "verrou");
      const etranger = spawn("sleep", ["30"]);
      try {
        fs.writeFileSync(chemin, `${etranger.pid}\n`);
        const b = new MagasinBailFichier(chemin);
        expect(await b.acquerir()).to.equal(1);
        const autre = spawnSync(process.execPath, ["--input-type=module", "-e", SCRIPT, chemin, "0"], { encoding: "utf8" });
        expect(autre.stdout).to.match(/^REFUS [0-9]+ bail_non_detenu/);
        await b.liberer();
        const encore = spawnSync(process.execPath, ["--input-type=module", "-e", SCRIPT, chemin, "0"], { encoding: "utf8" });
        expect(encore.stdout).to.match(/^ACQUIS [0-9]+ 2/);
      } finally {
        etranger.kill();
      }
    });

    it("course de six processus pour un verrou dont le détenteur est mort : jamais deux détenteurs vivants, époques strictement croissantes", async function () {
      const dir = repertoireTemporaire("noortrace-bail-course-");
      const epoques = [];
      for (let n = 0; n < 8; n++) {
        const chemin = path.join(dir, `verrou-${n}`);
        const mort = spawnSync(process.execPath, ["-e", "0"]).pid;
        fs.writeFileSync(chemin, `${mort}\n`);
        fs.writeFileSync(`${chemin}.epoch`, "7\n");
        const t0 = Date.now() + 700;
        const sorties = await Promise.all(Array.from({ length: 6 }, () => new Promise((r) => {
          const p = spawn(process.execPath, ["--input-type=module", "-e", SCRIPT, chemin, String(t0)]);
          let o = "";
          p.stdout.on("data", (d) => (o += d));
          p.on("exit", () => r(o.trim()));
        })));
        const acquis = sorties.filter((s) => s.startsWith("ACQUIS"));
        expect(acquis, `essai ${n} : ${sorties.join(" | ")}`).to.have.length(1);
        epoques.push(Number(acquis[0].split(" ")[2]));
      }
      expect(epoques).to.deep.equal(epoques.map(() => 8));
    });
  });

  describe("soupçons de la relecture A (stockage)", function () {
    it("EX-12.13 : intention et contexte sont écrits par une seule écriture (un arrêt entre les deux est impossible par construction)", async function () {
      const { config } = preparer("une-ecriture");
      const coeur = await Coeur.demarrer({ config, secrets: secretsDev() });
      const h = await fsp.open("/dev/null", "r");
      const Proto = Object.getPrototypeOf(h);
      await h.close();
      const orig = Proto.write;
      const ecritures = [];
      Proto.write = async function (buf, ...r) {
        ecritures.push(Buffer.from(buf).toString("utf8"));
        return orig.call(this, buf, ...r);
      };
      try {
        const args = pieceJson({ claim_id: "Z" });
        await coeur.ecrirePiece(args);
        ecritures.length = 0;
        await coeur.preparerRelais(appelEcriture(args), { reponse: autorise, argumentsEnClair: { claim_id: "Z" }, upstream_id: "e-000000000003" });
        const intention = ecritures.filter((t) => t.includes('"intent_id"') || t.includes('"intent_context"'));
        expect(intention).to.have.length(1);
        expect(intention[0].split("\n").filter(Boolean).map((l) => Object.keys(JSON.parse(l))[0])).to.deep.equal(["arguments", "event"]);
      } finally {
        Proto.write = orig;
        await coeur.arreter();
      }
    });

    it("EX-12.5 : un répertoire de pièces créé est suivi du fsync de son parent", async function () {
      const { config } = preparer("fsync-parent");
      const coeur = await Coeur.demarrer({ config, secrets: secretsDev() });
      const ouvrir = fsp.open;
      const synchronises = [];
      fsp.open = async function (p, ...r) {
        const x = await ouvrir.call(this, p, ...r);
        const sync = x.sync.bind(x);
        x.sync = async () => {
          synchronises.push(String(p));
          return sync();
        };
        return x;
      };
      try {
        const piece = pieceJson({ nouvelle: "pièce" });
        await coeur.ecrirePiece(piece);
        const xx = piece.sha256.slice(2, 4);
        expect(synchronises, "fsync de pieces/ après la création de pieces/<xx>").to.include(path.join(coeur.repertoire, "pieces"));
        expect(synchronises).to.include(path.join(coeur.repertoire, "pieces", xx));
      } finally {
        fsp.open = ouvrir;
        await coeur.arreter();
      }
    });

    it("fichiers temporaires .tmp-* laissés par un arrêt brutal : supprimés au démarrage", async function () {
      const { config } = preparer("tmp");
      const c1 = await Coeur.demarrer({ config, secrets: secretsDev() });
      const piece = pieceJson({ t: 1 });
      await c1.ecrirePiece(piece);
      await c1.arreter();
      const rep = repertoireJournal(config);
      const tmpM = path.join(rep, "manifestes", ".tmp-periode-1794304800.json-0123456789ab");
      const tmpP = path.join(rep, "pieces", piece.sha256.slice(2, 4), `.tmp-${piece.sha256.slice(2)}-0123456789ab`);
      fs.writeFileSync(tmpM, "{");
      fs.writeFileSync(tmpP, "x");
      const c2 = await Coeur.demarrer({ config, secrets: secretsDev() });
      try {
        expect(fs.existsSync(tmpM)).to.equal(false);
        expect(fs.existsSync(tmpP)).to.equal(false);
      } finally {
        await c2.arreter();
      }
    });

    it("EX-12.10 pas 2 : dernier segment dont la clé de signature est inconnue → les lignes ne sont pas tenues pour valides (segment_corrupted, intervention), jamais acceptées sans vérification", async function () {
      const { config } = preparer("cle-inconnue");
      const c1 = await Coeur.demarrer({ config, secrets: secretsDev() });
      await echange(c1, 1);
      await c1.arreter();
      // Le signataire ne connaît plus rec-test-01 (clé de l'en-tête et des lignes du dernier segment).
      const config2 = structuredClone(config);
      config2.signer.key_id = "rec-test-02";
      config2.signer.backend.path = config.signer.backend.path.replace("rec-test-01", "rec-test-02");
      config2.signer.rotation.next_key_id = null;
      const c2 = await Coeur.demarrer({ config: config2, secrets: secretsDev() });
      try {
        expect(c2.journal.trouver("segment_corrupted").map((l) => l.data.raison)).to.deep.equal(["cle_inconnue"]);
        expect(c2.sante().corps.reasons).to.deep.equal(["stockage"]);
      } finally {
        await c2.arreter();
      }
    });
  });
});
