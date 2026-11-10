// Pièces d'événements en attente perdues (CT-2 révision 0.7) : EX-14.18
// (nouvelle), EX-8.9 (exception unique), EX-14.10 (pièces écrites avant le
// scellement, pièce de remplacement à deux membres retirée), EX-17.2 et 17.4
// (`pending_pieces_lost`), §14.2 ligne « Pièces d'événements en attente
// perdues » (matrice des pannes, TE-16 au catalogue de CT-9), 13.5 (bascule).
//
// Scénario commun : un démon garde en mémoire, pendant un mode dégradé, les
// pièces d'événements en attente (EX-14.8) ; seules les lignes du fichier
// `attente/attente-<epoch>.ndjson` atteignent le disque ; le démon s'arrête
// (la file en mémoire est perdue avec lui) ; au redémarrage, le rejeu du
// fichier d'attente trouve des références à des pièces qui n'existent plus.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import {
  Coeur, HorlogeReglable, ErreurConstruction, ErreurEnregistreur, lireEvenements, validerConfiguration, resoudreSecrets,
  pieceJson, pieceNonJson, partielAppelOutil, partielEchange, VERSION_ENREGISTREUR, MagasinPieces,
} from "@noortrace/enregistreur";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { RACINE, configurationDev, repertoireTemporaire, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";
import { configurationHa, ClientMcpHttp, demarrerDemon, sante } from "./fixtures/enregistreur-ha/outils.mjs";
import { portLibre } from "./fixtures/enregistreur-worm/outils.mjs";

const ms = (t) => N.decoderHorodatage(t);
const T0 = ms("2026-11-10T10:14:00.000Z");
const VERIFICATEUR_JS = path.join(RACINE, "scripts", "verify", "dossier.mjs");
const TEXTE_ATTENTE = "pieces perdues pendant le mode degrade";
const delegation = { launched_by: "agent-sinistres", on_behalf_of: null, scope: "sinistres:lecture", run_id: null };
const autorise = { rule: null, decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null };
const dormir = (x) => new Promise((r) => setTimeout(r, x));

let racine;
let k = 0;

/** Configuration de développement validée (magasin de bail `file`). */
function preparer(nom, o = {}) {
  const d = path.join(racine, `${nom}-${++k}`);
  const { config } = configurationDev(d, { journal_id: N.octetsVersHex(N.keccak256(N.utf8(`journal-pieces-perdues-${process.pid}-${nom}-${k}`))), instance_id: o.instance_id ?? "inst-a" });
  const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(config)));
  expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
  return { d, config: v.config };
}
const autreInstance = (config, instance_id) => ({ ...config, recorder: { ...config.recorder, instance_id } });

function clesJournal(config, clePublique) {
  return {
    version: 0,
    org_id: config.recorder.org_id,
    journal_id: config.recorder.journal_id,
    keys: [{ key_id: "rec-test-01", algorithm: "ed25519", public_key: clePublique, valid_from: "2020-01-01T00:00:00.000Z", valid_to: null, source: "clé de test de CT-1 §13" }],
  };
}

/** Événement partiel d'un appel d'outil de lecture relayé (section 7). */
function partielLecture(coeur, { args, result, context = [], intent = null }) {
  return partielAppelOutil({
    delegation,
    code: { model: null, prompt_version: null, policy_version: coeur.versionPolitique, recorder: VERSION_ENREGISTREUR },
    intent,
    policy: { rule: null, decision: "autorise", ticket: null },
    approval: null,
    tool: "sap__claims.get",
    arguments: args,
    status: "executee",
    result,
    duration_ms: 3,
    is_error: false,
    effects: [],
    context,
    nomRedaction: coeur.nomRedaction,
  });
}

/** Événement partiel d'un échange de modèle (9.1, 5.3). */
function partielModele(coeur, { requete, reponse }) {
  return partielEchange({
    delegation,
    code: { model: "fournisseur/modele@2026-09", prompt_version: null, policy_version: coeur.versionPolitique, recorder: VERSION_ENREGISTREUR },
    intent: null,
    requete,
    reponse,
    duration_ms: 11,
    is_error: false,
    context: [],
    nomRedaction: coeur.nomRedaction,
  });
}

const fichiersAttente = (rep) => (fs.existsSync(path.join(rep, "attente")) ? fs.readdirSync(path.join(rep, "attente")).filter((n) => /^attente-[0-9]{20}\.ndjson$/.test(n)).sort() : []);
const lignesAttente = (rep) => fichiersAttente(rep).flatMap((n) => fs.readFileSync(path.join(rep, "attente", n), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)));

/**
 * Met des événements en attente, pièces gardées en mémoire seulement
 * (EX-14.8), attend que leurs lignes atteignent le fichier d'attente, puis
 * arrête le démon : la file en mémoire est perdue avec lui (EX-14.18, 13.5).
 * @returns {object[]} lignes du fichier d'attente
 */
async function arreterAvecAttente(coeur, entrees) {
  for (const x of entrees) coeur.mettreEnAttente(x.partiel, x.pieces, { captured_at: x.captured_at, host: "agent-sinistres-stdio", genre: x.genre ?? "appel" });
  const limite = Date.now() + 10000;
  while (lignesAttente(coeur.repertoire).length < entrees.length) {
    if (Date.now() > limite) throw new Error("lignes d'attente non écrites");
    await dormir(20);
  }
  // Les lignes sont ajoutées au mieux, sans ordre garanti entre elles : rendues dans l'ordre de captured_at.
  const lignes = lignesAttente(coeur.repertoire).sort((a, b) => ms(a.captured_at) - ms(b.captured_at));
  coeur.attente.length = 0;
  await coeur.arreter();
  return lignes;
}

/** Démarre un cœur ; rend { coeur } ou { erreur } (le refus de démarrer est un résultat observé). */
async function demarrer(o) {
  try {
    return { coeur: await Coeur.demarrer(o), erreur: null };
  } catch (e) {
    return { coeur: null, erreur: e };
  }
}

/** Les huit membres d'un événement (CT-1 §5.1). */
const huit = (e) => ({ delegation: e.delegation, code: e.code, intent: e.intent, policy: e.policy, approval: e.approval, execution: e.execution, effects: e.effects, context: e.context });

/** Membres d'un événement scellé selon EX-14.18 attendus égaux à ceux de l'événement partiel. */
function horsRemplacement(e) {
  const x = structuredClone(huit(e));
  delete x.execution.is_error;
  delete x.execution.result;
  delete x.policy.redaction;
  return x;
}

/** Octets JCS intégral attendus de la pièce de remplacement (EX-14.18 pas 3), écrits à la main. */
function remplacementAttendu(pendingId, manquantes, resultat) {
  const tri = [...manquantes].sort((a, b) => (a.sha256 < b.sha256 ? -1 : 1));
  const mp = tri.map((p) => `{"length":${p.length},"sha256":"${p.sha256}"}`).join(",");
  const r = `{"length":${resultat.length},${resultat.media_type ? `"media_type":"${resultat.media_type}",` : ""}"redacted":${resultat.redacted},"sha256":"${resultat.sha256}"}`;
  return `{"missing_pieces":[${mp}],"noortrace_attente":"${TEXTE_ATTENTE}","pending_id":"${pendingId}","result":${r}}`;
}

describe("enregistreur, cœur : pièces d'événements en attente perdues (CT-2 révision 0.7, EX-14.18, EX-8.9, EX-14.10, §14.2, 13.5)", function () {
  this.timeout(180000);

  before(function () {
    racine = repertoireTemporaire("noortrace-pieces-perdues-");
  });

  after(function () {
    if (racine) fs.rmSync(racine, { recursive: true, force: true });
  });

  // ---------------------------------------------------------------- trois événements, deux avec pièces manquantes

  describe("CT-2 EX-14.18 pas 1 à 6 et §14.2 ligne « Pièces d'événements en attente perdues » : trois événements en attente, deux dont des pièces manquent, une pièce manquante partagée", function () {
    const ev = {};

    before(async function () {
      const { d, config } = preparer("trois");
      ev.d = d;
      ev.config = config;
      ev.horloge = new HorlogeReglable(T0);
      const c1 = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: ev.horloge });
      // Pièces gardées en mémoire (jamais écrites) : A (arguments de E1, requête de E3), R1 (résultat de E1).
      ev.A = pieceJson({ claim_id: "2026-77812" });
      ev.R1 = pieceJson({ content: [{ type: "text", text: "sinistre ouvert" }], isError: false });
      // Pièces durables avant l'arrêt : C1 (contexte de E1), P2 et R2 (E2), R3 (réponse de E3, non JSON).
      ev.C1 = pieceJson({ document: "contrat 2026-01" }, { media_type: "application/json" });
      ev.P2 = pieceJson({ claim_id: "2026-77813" });
      ev.R2 = pieceJson({ content: [{ type: "text", text: "clos" }], isError: false });
      ev.R3 = pieceNonJson(N.utf8("data: {\"texte\":\"bonjour\"}\n\n"), { content_type: "text/event-stream" });
      for (const p of [ev.C1, ev.P2, ev.R2, ev.R3]) await c1.ecrirePiece(p);
      // Référence en ligne (`value`) sans fichier : jamais comptée manquante (pas 2).
      ev.enLigne = N.creerReferenceEnLigne({ motif: "controle" });
      ev.p1 = partielLecture(c1, { args: ev.A.reference, result: ev.R1.reference, context: [ev.C1.referenceContexte("document")] });
      ev.p2 = partielLecture(c1, { args: ev.P2.reference, result: ev.R2.reference, intent: ev.enLigne });
      ev.p3 = partielModele(c1, { requete: ev.A.reference, reponse: ev.R3.reference });
      ev.captures = [T0 + 1000, T0 + 2000, T0 + 3000];
      ev.dernierSeqAvant = c1.ecrivain.lastSeq;
      ev.lignes = await arreterAvecAttente(c1, [
        { partiel: ev.p1, pieces: [ev.A, ev.R1, ev.C1], captured_at: ev.captures[0] },
        { partiel: ev.p2, pieces: [ev.P2, ev.R2], captured_at: ev.captures[1] },
        { partiel: ev.p3, pieces: [ev.A, ev.R3], captured_at: ev.captures[2], genre: "echange" },
      ]);
      ev.horloge.aller(T0 + 60000);
      const r = await demarrer({ config: autreInstance(config, "inst-a"), secrets: secretsDev(), horloge: ev.horloge });
      ev.coeur = r.coeur;
      ev.erreur = r.erreur;
      if (ev.coeur) ev.evts = await lireEvenements(ev.coeur.repertoire);
    });

    after(async function () {
      await ev.coeur?.arreter();
    });

    const demarre = () => expect(ev.erreur, `refus de démarrer : ${ev.erreur?.message}`).to.equal(null);
    const scelles = () => ev.evts.filter((e) => e.seq > ev.dernierSeqAvant && e.seq <= ev.dernierSeqAvant + 3);

    it("CT-2 EX-14.18 pas 1, §14.2 ligne nouvelle : le démon démarre, santé « ok » sans mode dégradé, un appel d'écriture suivant est relayé et scellé", async function () {
      demarre();
      expect(ev.coeur.sante().corps).to.deep.equal({ status: "ok" });
      expect(ev.coeur.degrade.enModeDegrade).to.equal(false);
      const args = pieceJson({ claim_id: "suivant" });
      await ev.coeur.ecrirePiece(args);
      const appel = { host: { id: "agent-sinistres-stdio" }, delegation, tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", class: "ecriture", arguments: args.reference, context: [], intent: null, code: {} };
      const relais = await ev.coeur.preparerRelais(appel, { reponse: autorise, argumentsEnClair: { claim_id: "suivant" }, upstream_id: "e-000000000077" });
      const e = await ev.coeur.terminerRelais(relais, { resultat: pieceJson({ content: [], isError: false }), resultatRedige: {}, argumentsRediges: {}, duration_ms: 4, is_error: false });
      expect(e.execution).to.deep.include({ tool: "sap__payments.create", is_error: false });
      expect(e.seq).to.be.greaterThan(ev.dernierSeqAvant + 3);
    });

    it("CT-2 EX-14.18 pas 3 : place dans la chaîne (après le dernier événement d'avant l'arrêt, ordre de captured_at, ts = max(captured_at, ts précédent), policy_version de capture)", function () {
      demarre();
      const s = scelles();
      expect(s.map((e) => e.execution.tool)).to.deep.equal(["sap__claims.get", "sap__claims.get", "noortrace.modele.echange"]);
      expect(s.map((e) => ms(e.ts))).to.deep.equal(ev.captures);
      for (const e of s) expect(e.code.policy_version).to.equal(ev.p1.code.policy_version);
    });

    it("CT-2 EX-14.18 pas 3 : E1 (arguments et résultat manquants) — is_error vrai, résultat remplacé par la pièce JCS intégral exacte, deux pièces manquantes triées par sha256", async function () {
      demarre();
      const [e1] = scelles();
      expect(e1.execution.is_error).to.equal(true);
      const ligne = ev.lignes[0];
      const attendu = remplacementAttendu(ligne.pending_id, [ev.A.reference, ev.R1.reference], ev.R1.reference);
      const octets = await ev.coeur.pieces.lire(e1.execution.result.sha256);
      expect(N.decoderUtf8(octets)).to.equal(attendu);
      expect(e1.execution.result).to.deep.equal({ length: N.utf8(attendu).length, redacted: false, sha256: N.sha256Hex(N.utf8(attendu)) });
      const mp = JSON.parse(attendu).missing_pieces.map((p) => p.sha256);
      expect(mp).to.deep.equal([...mp].sort());
      expect(mp).to.have.length(2);
    });

    it("CT-2 EX-14.18 pas 3 : E3 (échange de modèle, requête manquante, réponse présente) — la pièce « réponse » est remplacée quand même ; l'originale reste dans pieces/ et sa référence (media_type compris) est dans result", async function () {
      demarre();
      const e3 = scelles()[2];
      expect(e3.execution.is_error).to.equal(true);
      const attendu = remplacementAttendu(ev.lignes[2].pending_id, [ev.A.reference], ev.R3.reference);
      expect(N.decoderUtf8(await ev.coeur.pieces.lire(e3.execution.result.sha256))).to.equal(attendu);
      expect(JSON.parse(attendu).result).to.deep.equal({ length: ev.R3.reference.length, media_type: "text/event-stream", redacted: false, sha256: ev.R3.sha256 });
      expect(fs.existsSync(ev.coeur.pieces.chemin(ev.R3.sha256)), "pièce « réponse » d'origine gardée").to.equal(true);
    });

    it("CT-2 EX-14.18 pas 2 et 4 : E2 (toutes pièces présentes, référence en ligne sans fichier) scellé comme avant ; E1 et E3 égaux membre à membre à l'événement partiel de la ligne hors is_error, result, policy.redaction", function () {
      demarre();
      const [e1, e2, e3] = scelles();
      expect(huit(e2)).to.deep.equal(ev.lignes[1].event);
      expect(e2.intent).to.deep.equal(ev.enLigne);
      expect(fs.existsSync(ev.coeur.pieces.chemin(ev.enLigne.sha256))).to.equal(false);
      expect(horsRemplacement(e1)).to.deep.equal(horsRemplacement(ev.lignes[0].event));
      expect(horsRemplacement(e3)).to.deep.equal(horsRemplacement(ev.lignes[2].event));
      // Autres références gardées telles quelles, présentes ou manquantes (sha256, length, redacted, media_type).
      expect(e1.execution.arguments).to.deep.equal(ev.A.reference);
      expect(e1.context).to.deep.equal([ev.C1.referenceContexte("document")]);
      expect(e3.execution.arguments).to.deep.equal(ev.A.reference);
      expect([e1.policy.redaction, e3.policy.redaction]).to.deep.equal([null, null]);
    });

    it("CT-2 EX-14.18 pas 5 : les pièces manquantes ne sont pas écrites ; les autres sont présentes ; le journal passe E-1 à E-8 (N.verifierJournal)", async function () {
      demarre();
      expect(fs.existsSync(ev.coeur.pieces.chemin(ev.A.sha256))).to.equal(false);
      expect(fs.existsSync(ev.coeur.pieces.chemin(ev.R1.sha256))).to.equal(false);
      const r = N.verifierJournal(ev.evts, clesJournal(ev.config, await ev.coeur.signataire.clePubliqueHex("rec-test-01")));
      expect(r.valide, JSON.stringify(r.diagnostics)).to.equal(true);
      expect(fichiersAttente(ev.coeur.repertoire).filter((n) => Number(n.slice(8, 28)) < ev.coeur.ecrivain.epoque), "fichier d'attente repris supprimé").to.deep.equal([]);
    });

    it("CT-2 EX-14.18 pas 6, EX-17.2 : une ligne pending_pieces_lost (noyau, error, seq nul ; events 2, seqs croissants, pieces 2 — la pièce A partagée comptée une fois), sans aucun sha256", function () {
      demarre();
      const l = ev.coeur.journal.trouver("pending_pieces_lost");
      expect(l).to.have.length(1);
      expect({ level: l[0].level, component: l[0].component, seq: l[0].seq, data: l[0].data }).to.deep.equal({
        level: "error", component: "noyau", seq: null, data: { events: 2, seqs: [ev.dernierSeqAvant + 1, ev.dernierSeqAvant + 3], pieces: 2 },
      });
      expect(JSON.stringify(l[0].data)).to.not.match(/[0-9a-f]{64}/);
      expect(ev.coeur.journal.trouver("pending_flushed").at(-1).data).to.include({ count: 3 });
    });

    it("CT-2 EX-14.18 pas 5 (EX-8.10, CT-1 §11.4, CT-6 EX-4.6) : dossier exporté de E1 vérifié par le binaire Go et par scripts/verify/dossier.mjs (boîte noire), pièces manquantes lues comme purgées", async function () {
      demarre();
      const [e1] = scelles();
      ev.horloge.aller(ms("2026-11-10T11:00:00.300Z"));
      await ev.coeur.tic();
      const dossier = path.join(ev.d, "dossier-e1");
      await ev.coeur.exporterDossier(e1.seq, dossier);
      // Pièces fournies à part (CT-6 EX-4.6) : celles qui existent (remplacement, contexte) ; A et R1 n'existent plus.
      const pieces = path.join(ev.d, "pieces-fournies");
      fs.mkdirSync(pieces, { recursive: true });
      for (const s of [e1.execution.result.sha256, ev.C1.sha256]) fs.copyFileSync(ev.coeur.pieces.chemin(s), path.join(pieces, s.slice(2)));
      // Témoin : une pièce fournie sous le nom d'une pièce manquante, mais fausse, est vérifiée (et refusée).
      const falsifiees = path.join(ev.d, "pieces-falsifiees");
      fs.cpSync(pieces, falsifiees, { recursive: true });
      fs.writeFileSync(path.join(falsifiees, ev.A.sha256.slice(2)), '{"claim_id":"autre"}');
      // Deux vérificateurs en boîte noire, sans pièces puis avec les pièces qui existent.
      const verificateurs = [["js", process.execPath, [VERIFICATEUR_JS]]];
      const bin = process.env.NOORTRACE_VERIFIER_BIN ?? null;
      if (bin && fs.existsSync(bin)) verificateurs.push(["go", bin, []]);
      else this.test.title += " — binaire Go en attente : NOORTRACE_VERIFIER_BIN absent (vérification JavaScript faite)";
      const rapports = [];
      for (const [nom, programme, prefixe] of verificateurs) {
        for (const [variante, options] of [["sans", []], ["avec", ["--pieces", pieces]], ["falsifiee", ["--pieces", falsifiees]]]) {
          const x = spawnSync(programme, [...prefixe, dossier, "--json", ...options], { cwd: RACINE, encoding: "utf8" });
          rapports.push([`${nom}-${variante}`, x.status, JSON.parse(x.stdout)]);
        }
      }
      const e6 = (r) => r.checks.find((c) => c.id === "E-6");
      for (const [nom, code, r] of rapports) {
        if (nom.endsWith("-falsifiee")) {
          // Témoin : la pièce fournie est bien lue et hachée ; fausse, elle fait échouer E-6.
          expect([code, r.verdict, r.failed_checks, e6(r).status], nom).to.deep.equal([1, "invalide", ["E-6"], "echoue"]);
          expect(e6(r).detail, nom).to.include(ev.A.sha256.slice(2));
        } else {
          // Pièces absentes (non fournies), lues comme des pièces purgées : aucune erreur, verdict inchangé.
          expect([code, r.verdict, r.failed_checks, e6(r).status], nom).to.deep.equal([0, "valide", [], "reussi"]);
        }
      }
      expect(rapports.find((x) => x[0] === "js-avec")[2].inputs.pieces.files).to.equal(2);
      expect(e6(rapports.find((x) => x[0] === "js-avec")[2]).detail).to.equal("2 pièce(s) fournie(s) à part vérifiée(s)");
      ev.rapports = rapports;
    });
  });

  // ---------------------------------------------------------------- rejeu complet : rien ne change

  it("CT-2 EX-14.18 pas 2 et 6 : rejeu d'un fichier d'attente dont toutes les pièces existent — scellé à l'identique, is_error inchangé, aucune ligne pending_pieces_lost", async function () {
    const { config } = preparer("complet");
    const h = new HorlogeReglable(T0);
    const c1 = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: h });
    const a = pieceJson({ claim_id: "complet" });
    const r = pieceJson({ content: [], isError: false });
    await c1.ecrirePiece(a);
    await c1.ecrirePiece(r);
    const p = partielLecture(c1, { args: a.reference, result: r.reference });
    const lignes = await arreterAvecAttente(c1, [{ partiel: p, pieces: [a, r], captured_at: T0 + 500 }]);
    h.aller(T0 + 60000);
    const c2 = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: h });
    try {
      const e = (await lireEvenements(c2.repertoire)).find((x) => x.execution.tool === "sap__claims.get");
      expect(huit(e)).to.deep.equal(lignes[0].event);
      expect(e.execution.is_error).to.equal(false);
      expect(c2.journal.trouver("pending_pieces_lost")).to.deep.equal([]);
    } finally {
      await c2.arreter();
    }
  });

  // ---------------------------------------------------------------- policy.redaction recalculé

  it("CT-2 EX-14.18 pas 4 (EX-10.16) : policy.redaction recalculé — résultat seule pièce rédigée remplacé → null ; arguments rédigés gardés → nom gardé", async function () {
    const { config } = preparer("redaction");
    const h = new HorlogeReglable(T0);
    const c1 = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: h });
    const nom = c1.nomRedaction;
    expect(nom, "nom de la version des règles de rédaction").to.be.a("string");
    const a4 = pieceJson({ claim_id: "r4" });
    const r4 = pieceJson({ content: [{ type: "text", text: "[REDIGE:iban]" }], isError: false }, { redacted: true });
    const a5 = pieceJson({ iban: "[REDIGE:iban]" }, { redacted: true });
    const r5 = pieceJson({ content: [], isError: false });
    await c1.ecrirePiece(r5);
    const p4 = partielLecture(c1, { args: a4.reference, result: r4.reference });
    const p5 = partielLecture(c1, { args: a5.reference, result: r5.reference });
    expect([p4.policy.redaction, p5.policy.redaction]).to.deep.equal([nom, nom]);
    await arreterAvecAttente(c1, [{ partiel: p4, pieces: [a4, r4], captured_at: T0 + 100 }, { partiel: p5, pieces: [a5, r5], captured_at: T0 + 200 }]);
    h.aller(T0 + 60000);
    const r = await demarrer({ config, secrets: secretsDev(), horloge: h });
    expect(r.erreur, String(r.erreur)).to.equal(null);
    try {
      const [e4, e5] = (await lireEvenements(r.coeur.repertoire)).filter((x) => x.execution.tool === "sap__claims.get");
      expect([e4.execution.is_error, e5.execution.is_error]).to.deep.equal([true, true]);
      expect(e4.policy.redaction, "seule pièce rédigée remplacée").to.equal(null);
      expect(e5.policy.redaction, "arguments rédigés gardés").to.equal(nom);
      expect(e5.execution.arguments).to.deep.equal(a5.reference);
      const piece4 = JSON.parse(N.decoderUtf8(await r.coeur.pieces.lire(e4.execution.result.sha256)));
      expect(piece4.result).to.deep.equal(r4.reference);
      expect(piece4.missing_pieces).to.deep.equal([a4.reference, r4.reference].map((x) => ({ length: x.length, sha256: x.sha256 })).sort((x, y) => (x.sha256 < y.sha256 ? -1 : 1)));
      const piece5 = JSON.parse(N.decoderUtf8(await r.coeur.pieces.lire(e5.execution.result.sha256)));
      expect(piece5.missing_pieces).to.deep.equal([{ length: a5.reference.length, sha256: a5.sha256 }]);
      expect(r.coeur.journal.trouver("pending_pieces_lost")[0].data).to.deep.equal({ events: 2, seqs: [e4.seq, e5.seq], pieces: 3 });
      const evts = await lireEvenements(r.coeur.repertoire);
      expect(N.verifierJournal(evts, clesJournal(config, await r.coeur.signataire.clePubliqueHex("rec-test-01"))).valide).to.equal(true);
    } finally {
      await r.coeur.arreter();
    }
  });

  // ---------------------------------------------------------------- hors de ce cas, le refus demeure

  it("CT-2 EX-8.9 (exception unique) : hors du rejeu du fichier d'attente, une pièce manquante garde le refus — intention ouverte dont la pièce « arguments » a disparu (refus de démarrer), échange scellé sans sa pièce (refus)", async function () {
    const { config } = preparer("refus");
    const h = new HorlogeReglable(T0);
    const c1 = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: h });
    const sansPiece = pieceJson({ k: "jamais ecrite" });
    let refus = null;
    try {
      await c1.scellerEchange({ delegation, code: { model: null, prompt_version: null }, intent: null, requete: sansPiece.reference, reponse: sansPiece.reference, duration_ms: 1, is_error: false });
    } catch (e) {
      refus = e;
    }
    expect(refus).to.be.instanceOf(ErreurConstruction);
    expect(refus.message).to.match(/EX-8\.9/);
    const args = pieceJson({ claim_id: "en-vol" });
    await c1.ecrirePiece(args);
    const appel = { host: { id: "agent-sinistres-stdio" }, delegation, tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", class: "ecriture", arguments: args.reference, context: [], intent: null, code: {} };
    await c1.preparerRelais(appel, { reponse: autorise, argumentsEnClair: { claim_id: "en-vol" }, upstream_id: "e-000000000005" });
    await c1.arreter();
    fs.rmSync(c1.pieces.chemin(args.sha256));
    h.aller(T0 + 60000);
    const r = await demarrer({ config, secrets: secretsDev(), horloge: h });
    await r.coeur?.arreter();
    expect(r.coeur, "démarrage refusé").to.equal(null);
    expect(String(r.erreur?.message)).to.match(/EX-8\.9/);
  });

  // ---------------------------------------------------------------- EX-14.10 : écrire puis sceller

  it("CT-2 EX-14.10 (révision 0.7) : à la sortie du mode dégradé sans redémarrage, une écriture de pièce qui échoue laisse l'événement (et les suivants) en attente, sans scellement ni pièce de remplacement ; une fois écrites, chaque événement est scellé après ses pièces", async function () {
    const { config } = preparer("ecrire-puis-sceller");
    const h = new HorlogeReglable(T0);
    const c = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: h });
    try {
      const a1 = pieceJson({ claim_id: "m1" });
      const r1 = pieceJson({ content: [{ type: "text", text: "m1" }], isError: false });
      const a2 = pieceJson({ claim_id: "m2" });
      const r2 = pieceJson({ content: [{ type: "text", text: "m2" }], isError: false });
      c.mettreEnAttente(partielLecture(c, { args: a1.reference, result: r1.reference }), [a1, r1], { captured_at: T0 + 10 });
      c.mettreEnAttente(partielLecture(c, { args: a2.reference, result: r2.reference }), [a2, r2], { captured_at: T0 + 20 });
      const avant = c.ecrivain.lastSeq;
      // Panne du stockage des pièces sur le résultat du premier événement.
      const ecrire = c.pieces.ecrire.bind(c.pieces);
      c.pieces.ecrire = async (p) => {
        if (p.sha256 === r1.sha256) throw new ErreurEnregistreur("stockage", "noortrace: stockage indisponible");
        return ecrire(p);
      };
      // Ordre observé : au moment de chaque scellement, toutes les pièces référencées existent (EX-8.9).
      const sceller = c.ecrivain.sceller.bind(c.ecrivain);
      const absentesAuScellement = [];
      c.ecrivain.sceller = async (partiel, o) => {
        for (const { reference } of N.referencesEvenement(partiel)) if (!("value" in reference) && !fs.existsSync(c.pieces.chemin(reference.sha256))) absentesAuScellement.push(reference.sha256);
        return sceller(partiel, o);
      };
      await c.viderAttente();
      expect(c.ecrivain.lastSeq, "aucun événement scellé").to.equal(avant);
      expect(c.attente.map((x) => x.captured_at), "les deux événements restent en attente, dans l'ordre").to.deep.equal([T0 + 10, T0 + 20]);
      expect(fs.existsSync(c.pieces.chemin(r1.sha256))).to.equal(false);
      // Le stockage répond de nouveau : sortie du mode, scellement après écriture des pièces.
      c.pieces.ecrire = ecrire;
      h.avancer(1000);
      for (let n = 0; n < 5 && c.attente.length; n++) await c.tic();
      expect(c.attente).to.have.length(0);
      const evts = (await lireEvenements(c.repertoire)).filter((e) => e.execution.tool === "sap__claims.get");
      expect(evts.map((e) => [e.execution.is_error, e.execution.result.sha256])).to.deep.equal([[false, r1.sha256], [false, r2.sha256]]);
      expect(absentesAuScellement).to.deep.equal([]);
      for (const e of evts) expect(JSON.stringify(N.decoderUtf8(await c.pieces.lire(e.execution.result.sha256)))).to.not.include("noortrace_attente");
    } finally {
      await c.arreter();
    }
  });

  it("CT-2 EX-14.10 et EX-14.18 : arrêt injecté entre l'écriture des pièces et le scellement — rien n'est scellé sans ses pièces ; au redémarrage, pièces présentes, événement scellé tel quel, aucune ligne pending_pieces_lost", async function () {
    const { config } = preparer("arret-injecte");
    const h = new HorlogeReglable(T0);
    const c1 = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: h });
    const a = pieceJson({ claim_id: "inj" });
    const r = pieceJson({ content: [{ type: "text", text: "inj" }], isError: false });
    const p = partielLecture(c1, { args: a.reference, result: r.reference });
    c1.mettreEnAttente(p, [a, r], { captured_at: T0 + 10 });
    await dormir(200);
    const avant = c1.ecrivain.lastSeq;
    c1.ecrivain.sceller = async () => {
      throw new ErreurEnregistreur("stockage", "arret injecte");
    };
    await c1.viderAttente();
    expect(c1.ecrivain.lastSeq).to.equal(avant);
    expect([a, r].map((x) => fs.existsSync(c1.pieces.chemin(x.sha256))), "pièces écrites avant le scellement").to.deep.equal([true, true]);
    c1.attente.length = 0;
    await c1.arreter();
    h.aller(T0 + 60000);
    const c2 = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: h });
    try {
      const e = (await lireEvenements(c2.repertoire)).find((x) => x.execution.tool === "sap__claims.get");
      expect(huit(e)).to.deep.equal(p);
      expect(c2.journal.trouver("pending_pieces_lost")).to.deep.equal([]);
    } finally {
      await c2.arreter();
    }
  });

  // ---------------------------------------------------------------- 13.5 : bascule

  it("CT-2 13.5 (révision 0.7) : bascule — B, repreneur d'un bail rendu par A, scelle selon EX-14.18 les événements en attente de A dont les pièces sont perdues (même oracles côté B)", async function () {
    const { config } = preparer("bascule");
    const A = await Coeur.demarrer({ config, secrets: secretsDev() });
    let B = null;
    try {
      const args = pieceJson({ claim_id: "bascule" });
      const res = pieceJson({ content: [{ type: "text", text: "bascule" }], isError: false });
      const p = partielLecture(A, { args: args.reference, result: res.reference });
      A.mettreEnAttente(p, [args, res], { host: "agent-sinistres-stdio" });
      const limite = Date.now() + 10000;
      while (lignesAttente(A.repertoire).length < 1 && Date.now() < limite) await dormir(20);
      const [ligne] = lignesAttente(A.repertoire);
      // A perd la file en mémoire avec son processus ; son bail est rendu (13.4 pas 2).
      A.attente.length = 0;
      await A.bail.liberer();
      const r = await demarrer({ config: autreInstance(config, "inst-b"), secrets: secretsDev() });
      B = r.coeur;
      expect(r.erreur, String(r.erreur)).to.equal(null);
      expect(B.ecrivain.epoque).to.be.greaterThan(A.ecrivain.epoque);
      expect(B.sante().corps).to.deep.equal({ status: "ok" });
      const e = (await lireEvenements(B.repertoire)).find((x) => x.execution.tool === "sap__claims.get");
      expect(e.execution.is_error).to.equal(true);
      expect(N.decoderUtf8(await B.pieces.lire(e.execution.result.sha256))).to.equal(remplacementAttendu(ligne.pending_id, [args.reference, res.reference], res.reference));
      expect(horsRemplacement(e)).to.deep.equal(horsRemplacement(ligne.event));
      expect(B.journal.trouver("pending_pieces_lost").map((l) => l.data)).to.deep.equal([{ events: 1, seqs: [e.seq], pieces: 2 }]);
      const evts = await lireEvenements(B.repertoire);
      expect(N.verifierJournal(evts, clesJournal(config, await B.signataire.clePubliqueHex("rec-test-01"))).valide).to.equal(true);
    } finally {
      await A.arreter();
      await B?.arreter();
    }
  });
});

// ------------------------------------------------------------------ démon réel (TE-16, ligne de §14.2)

describe("CT-9 TE-16, ligne « Pièces d'événements en attente perdues » de la matrice de CT-2 §14.2 (révision 0.7), rejouée sur le démon réel bin/noortrace : il démarre, /healthz « ok », appels relayés, pending_pieces_lost au journal d'exploitation", function () {
  this.timeout(180000);
  let dir;
  let service;
  let serveur;
  let demon;

  before(async function () {
    dir = repertoireTemporaire("noortrace-pieces-perdues-demon-");
    service = new ServiceApprobationFactice({ org_id: "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab", journal_id: null });
    serveur = await service.servir(0);
  });

  after(async function () {
    if (demon && demon.exitCode === null && demon.signalCode === null) {
      demon.kill("SIGTERM");
      await demon.fin;
    }
    serveur?.close();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("démarrage avec un fichier d'attente dont les pièces manquent : santé ok (pas degraded), lecture et écriture relayées, événement scellé is_error, ligne pending_pieces_lost", async function () {
    const journal_id = N.octetsVersHex(N.keccak256(N.utf8(`journal-pieces-perdues-demon-${process.pid}`)));
    service.journal_id = journal_id;
    const x = configurationHa(dir, { journal_id, instance: "inst-a", store: { type: "file", path: path.join(dir, "bail", "verrou") }, approbation: serveur.address().port, portHttp: await portLibre(), portSante: await portLibre() });
    const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(x.config)));
    expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
    x.config = v.config;
    x.fichier = path.join(dir, "configuration.json");
    x.port = Number(x.config.supervision.health_listen.split(":")[1]);
    // Premier démon (cœur seul, même stockage) : un événement en attente, pièces en mémoire, puis arrêt.
    const s = resoudreSecrets(v.config, { env: x.env });
    const c1 = await Coeur.demarrer({ config: v.config, secrets: s.secrets });
    const args = pieceJson({ id: "perdu" });
    const res = pieceJson({ content: [{ type: "text", text: "perdu" }], isError: false });
    const p = partielAppelOutil({
      delegation: { launched_by: "agent-ha", on_behalf_of: null, scope: "s", run_id: null },
      code: { model: null, prompt_version: null, policy_version: c1.versionPolitique, recorder: VERSION_ENREGISTREUR },
      intent: null, policy: { rule: null, decision: "autorise", ticket: null }, approval: null, tool: "demo__lire",
      arguments: args.reference, status: "executee", result: res.reference, duration_ms: 2, is_error: false, effects: [], context: [], nomRedaction: c1.nomRedaction,
    });
    const [ligne] = await arreterAvecAttente(c1, [{ partiel: p, pieces: [args, res], captured_at: Date.now() }]);
    // Le démon réel redémarre sur ce stockage.
    demon = await demarrerDemon(x, "ok").catch((e) => {
      throw new Error(`démon : ${e.message}`);
    });
    expect((await sante(x.port)).corps).to.deep.equal({ status: "ok" });
    const h = new ClientMcpHttp(x.config.mcp.http.listen);
    await h.ouvrir();
    const lecture = await h.appeler("demo__lire", { id: "apres" });
    expect(lecture.result?.isError, JSON.stringify(lecture)).to.equal(false);
    const ecriture = await h.appeler("demo__ecrire", { id: "apres", montant: "1" });
    expect(ecriture.result?.isError, JSON.stringify(ecriture)).to.equal(false);
    const l = demon.lignes().filter((y) => y.event === "pending_pieces_lost");
    expect(l.map((y) => [y.level, y.component, y.seq])).to.deep.equal([["error", "noyau", null]]);
    expect(l[0].data).to.deep.include({ events: 1, pieces: 2 });
    demon.kill("SIGTERM");
    expect((await demon.fin).code).to.equal(0);
    const repertoire = path.join(x.config.storage.root, x.config.recorder.org_id.slice(2), journal_id.slice(2));
    const evts = await lireEvenements(repertoire);
    const e = evts.find((y) => y.seq === l[0].data.seqs[0]);
    expect(e.execution).to.deep.include({ tool: "demo__lire", is_error: true });
    const magasin = new MagasinPieces(repertoire);
    expect(JSON.parse(N.decoderUtf8(await magasin.lire(e.execution.result.sha256)))).to.deep.include({ noortrace_attente: TEXTE_ATTENTE, pending_id: ligne.pending_id });
    expect(evts.filter((y) => y.execution.tool === "demo__lire" || y.execution.tool === "demo__ecrire").map((y) => y.execution.is_error)).to.deep.equal([true, false, false]);
  });
});
