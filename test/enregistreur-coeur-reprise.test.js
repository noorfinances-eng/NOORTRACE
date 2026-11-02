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
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as N from "@noortrace/noyau";
import { Coeur, ErreurEnregistreur, lireEvenements, validerConfiguration, pieceJson } from "@noortrace/enregistreur";
import { configurationDev, repertoireTemporaire, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";

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
