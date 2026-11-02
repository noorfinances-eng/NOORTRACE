// Rejeu des vecteurs de CT-2 (spec/vecteurs/ct-2) par le cœur de
// l'enregistreur (@noortrace/enregistreur), écrit d'après le seul texte de la
// spécification. Familles rejouées :
//   - jcs-integral : JCS intégral de §8.1, cas par cas ;
//   - evenements/journal-demo : la démonstration reconstruite par l'écrivain
//     unique, octet pour octet (segment, journal d'intention, pièces, effets,
//     reprise d'EX-7.12, décision, manifeste de clôture) ;
//   - pieces-mcp/appels, pieces-modele, redaction/cas.json : la part de §8
//     (sérialisation et référence de chaque pièce publiée ; pièces de
//     définition, de liste et d'arguments non rédigés dérivées des
//     transcriptions) ; la dérivation des autres pièces relève des frontaux
//     (lots suivants) ;
//   - redaction/ (politiques, motifs, cas) : rejoués par le rédacteur du lot
//     « rédaction » (§10), détail dans enregistreur-redaction.test.js.
//   - pieces-mcp/agregation : rejoués par l'agrégation du lot « frontal MCP »
//     (§4.3) ; les transcriptions de pieces-mcp/appels sont rejouées de bout
//     en bout par le frontal dans enregistreur-mcp-vecteurs.test.js ;
//   - pieces-mcp/appels/approbation-* et journal-demo (seq 5 à 7) : rejoués
//     de bout en bout par le moteur de politique (section d d'INTERFACES.md)
//     dans enregistreur-politique-vecteurs.test.js ;
//   - pieces-modele : formes consolidées rejouées ici par le réassemblage du
//     lot « frontal modèle » (§5.4) ; chaque cas, et les échanges de seq 2, 4
//     et 8 de journal-demo, rejoués de bout en bout par la passerelle
//     (dérivation des pièces depuis la requête et la réponse, section b)
//     dans enregistreur-modele-vecteurs.test.js.
// Le dernier bloc est l'inventaire : il dit, fichier par fichier, ce qui est
// rejoué et ce qui relève d'un lot suivant, et échoue si un fichier de
// vecteur n'est ni consommé ni attribué.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as N from "@noortrace/noyau";
import {
  Ecrivain, IndexChaine, MagasinPieces, JournalExploitation, EtatDegrade, ControleurHorloge, HorlogeReglable,
  SignataireFichier, SignataireVerifie, MagasinBailMemoire, ZERO32, canoniserTexteIntegral, jcsIntegral,
  analyserJsonIntegral, pieceJson, pieceTexte, pieceNonJson, pieceDefinitionOutil, pieceListeAnnoncee,
  pieceErreurJsonRpc, piecePolitique, empreintePolitique, partielPolitique, partielEchange, partielAppelOutil,
  partielDecision, repriseDeRetenue, evaluerEffets, Piece, PolitiqueCompilee, produirePiece, validerPolitiqueRedaction,
  controlerMotif, premiereCorrespondance, agreger, paginer, consoliderFlux,
} from "@noortrace/enregistreur";
import { VECTEURS_CT2, graine, repertoireTemporaire, lireVecteur } from "./fixtures/enregistreur-coeur/outils.mjs";

const consommes = new Set();
const lire = (rel) => {
  consommes.add(rel);
  return fs.readFileSync(path.join(VECTEURS_CT2, rel));
};
const json = (rel) => JSON.parse(lire(rel).toString("utf8"));
const ms = (t) => N.decoderHorodatage(t);
const octetsUtf8 = (s) => new Uint8Array(Buffer.from(s, "utf8"));

function egalRef(piece, attendu) {
  expect(piece.reference.sha256, "sha256").to.equal(attendu.sha256);
  expect(piece.reference.length, "length").to.equal(attendu.length);
  expect(piece.reference.redacted, "redacted").to.equal(attendu.redacted);
  if (attendu.media_type) expect(piece.reference.media_type).to.equal(attendu.media_type);
  else expect(piece.reference).to.not.have.property("media_type");
}

/** Reconstitue une pièce publiée par la sérialisation de §8 (8.1, 8.2, 8.3). */
function pieceDepuisPubliee(p) {
  const octets = octetsUtf8(p.bytes);
  if (p.media_type === "text/plain") return pieceTexte(p.bytes, { redacted: p.redacted });
  if (p.media_type === undefined || p.media_type === null) {
    return pieceJson(analyserJsonIntegral(octets), { redacted: p.redacted });
  }
  if (p.media_type === "application/json") {
    const v = canoniserTexteIntegral(octets);
    if (v === p.bytes) return pieceJson(analyserJsonIntegral(octets), { redacted: p.redacted, media_type: "application/json" });
  }
  return pieceNonJson(octets, { content_type: p.media_type, redacted: p.redacted });
}

describe("enregistreur, cœur : vecteurs CT-2", function () {
  this.timeout(60000);

  describe("jcs-integral (§8.1, EX-8.1)", function () {
    it("chaque cas a la forme canonique publiée, ou est refusé", function () {
      const cas = json("jcs-integral/cas.json");
      expect(cas.length).to.be.greaterThan(60);
      for (const c of cas) {
        expect(canoniserTexteIntegral(c.input), c.name).to.equal(c.canonical);
      }
    });
  });

  describe("evenements/journal-demo (B.6) reconstruit par l'écrivain unique", function () {
    const R = "evenements/journal-demo";
    let attendu;
    let evenements;
    let pieces;
    let politique;
    let dir;
    let repertoire;
    let produits;
    let horloge;
    let ecrivain;
    let index;
    let intentionEcrite;

    before(async function () {
      attendu = json(`${R}/attendu.json`);
      evenements = json(`${R}/evenements.json`);
      pieces = json(`${R}/pieces.json`);
      politique = json(`${R}/politique.json`);
      dir = repertoireTemporaire();
      repertoire = path.join(dir, "journal");
      fs.mkdirSync(repertoire, { recursive: true });
      horloge = new HorlogeReglable(ms("2026-11-10T10:14:02.100Z"));
      const journal = new JournalExploitation({ murale: () => horloge.murale() });
      const degrade = new EtatDegrade(journal, null, () => horloge.murale());
      const signataire = new SignataireVerifie(new SignataireFichier({ environment: "developpement", cles: new Map([["rec-test-01", graine("rec-test-01")]]) }));
      index = new IndexChaine();
      const magasin = new MagasinPieces(repertoire);
      for (const p of pieces) await magasin.ecrire(new Piece(octetsUtf8(p.bytes), { redacted: p.redacted, media_type: p.media_type ?? undefined }));
      ecrivain = new Ecrivain({
        repertoire,
        org_id: attendu.org_id,
        journal_id: attendu.journal_id,
        instance_id: "enregistreur-demo",
        recorder: "0.1.0",
        signataire,
        bail: Object.assign(new MagasinBailMemoire(1), { detenu: true, epoque: 1 }),
        horloge: new ControleurHorloge(horloge, {}, degrade, journal),
        degrade,
        journal,
        index,
        pieces: magasin,
        fsync: { group_max_events: 1, group_max_wait_ms: 0 },
        nonce: () => attendu.period.nonce,
      });
      await ecrivain.demarrer({ lastSeq: 0, lastHash: ZERO32, lastTs: null, cleCourante: "rec-test-01", epoqueMax: null, periode: null, prevPeriodHash: ZERO32, serie: null }, 1);
      produits = [];
      const v = (seq) => evenements[seq - 1];
      const champs = (e) => ({ delegation: e.delegation, code: e.code, intent: e.intent, context: e.context });
      const aller = (seq) => horloge.aller(ms(v(seq).ts));
      // seq 1 : politique (EX-9.1), policy_sha256 du JCS intégral de politique.json (EX-8.11).
      aller(1);
      const emp = empreintePolitique(politique);
      produits.push(await ecrivain.sceller(partielPolitique({ ...emp, recorder: "0.1.0" })));
      // seq 2, 4, 8 : échanges de modèle (pièces publiées).
      const echange = async (seq) => {
        aller(seq);
        const e = v(seq);
        produits.push(
          await ecrivain.sceller(
            partielEchange({ ...champs(e), requete: e.execution.arguments, reponse: e.execution.result, duration_ms: e.execution.duration_ms, is_error: e.execution.is_error, nomRedaction: "pii-v1" }),
          ),
        );
      };
      const valeurPiece = (ref) => analyserJsonIntegral(octetsUtf8(pieces.find((p) => p.sha256 === ref.sha256).bytes));
      const gabarit = (nom) => politique.servers.demo.tools[nom].effects;
      await echange(2);
      // seq 3 : lecture relayée, effets du gabarit évalués sur les valeurs rédigées (EX-7.6).
      aller(3);
      const e3 = v(3);
      const eff3 = evaluerEffets({ gabarit: gabarit("claims.get"), classe: "lecture", alias: "demo", nomOrigine: "claims.get", arguments: valeurPiece(e3.execution.arguments), resultat: valeurPiece(e3.execution.result) });
      produits.push(
        await ecrivain.sceller(
          partielAppelOutil({ ...champs(e3), policy: { rule: null, decision: "autorise", ticket: null }, approval: null, tool: e3.execution.tool, arguments: e3.execution.arguments, status: "executee", result: e3.execution.result, duration_ms: 184, is_error: false, effects: eff3.effets, nomRedaction: "pii-v1" }),
        ),
      );
      await echange(4);
      // seq 5 : retenue.
      aller(5);
      const e5 = v(5);
      produits.push(
        await ecrivain.sceller(
          partielAppelOutil({ ...champs(e5), policy: { rule: e5.policy.rule, decision: "a_approuver", ticket: e5.policy.ticket }, approval: null, tool: e5.execution.tool, arguments: e5.execution.arguments, status: "retenue", nomRedaction: "pii-v1" }),
        ),
      );
      // seq 6 : décision ; approval.at posé par l'écrivain (EX-7.11).
      aller(6);
      const { at, ...sansAt } = v(6).approval;
      void at;
      produits.push(
        await ecrivain.sceller(partielDecision({ retenue: produits[4], approval: sansAt, policy_version: emp.policy_version, recorder: "0.1.0", org_id: attendu.org_id, journal_id: attendu.journal_id }), {
          completer: (evt, ts) => {
            evt.approval.at = ts;
          },
        }),
      );
      // seq 7 : relais après approbation ; reprise de la retenue (EX-7.12), intention (EX-12.12).
      const rep = repriseDeRetenue(produits[4], produits[5]);
      const e7 = v(7);
      const base7 = { delegation: e7.delegation, code: { ...rep.code, policy_version: emp.policy_version, recorder: "0.1.0" }, intent: rep.intent, context: e7.context };
      horloge.aller(ms("2026-11-10T10:21:35.014Z"));
      const partielIntention = partielAppelOutil({ ...base7, policy: rep.policy, approval: rep.approval, tool: e7.execution.tool, arguments: e7.execution.arguments, status: "executee", result: null, duration_ms: 0, is_error: false, nomRedaction: "pii-v1" });
      const intention = await ecrivain.inscrireIntention({ upstream_id: "e-000000000004", host: "agent-demo", tool: e7.execution.tool, arguments: e7.execution.arguments, ticket: rep.policy.ticket }, partielIntention);
      intentionEcrite = intention;
      aller(7);
      const eff7 = evaluerEffets({ gabarit: gabarit("payments.create"), classe: "ecriture", alias: "demo", nomOrigine: "payments.create", arguments: valeurPiece(e7.execution.arguments), resultat: valeurPiece(e7.execution.result) });
      produits.push(
        await ecrivain.sceller(
          partielAppelOutil({ ...base7, policy: rep.policy, approval: rep.approval, tool: e7.execution.tool, arguments: e7.execution.arguments, status: "executee", result: e7.execution.result, duration_ms: 412, is_error: false, effects: eff7.effets, nomRedaction: "pii-v1" }),
          { leverIntention: intention.intent_id },
        ),
      );
      await echange(8);
      // Clôture de la période (CT-1 §10, CT-2 3.1) à l'instant du manifeste publié.
      horloge.aller(ms("2026-11-10T11:00:00.300Z"));
      await ecrivain.tic();
      await ecrivain.fermer();
    });

    it("chaque événement a le hash, la sig, le prev_hash et la longueur canonique publiés", function () {
      expect(produits.map((e) => e.seq)).to.deep.equal([1, 2, 3, 4, 5, 6, 7, 8]);
      attendu.events.forEach((a, k) => {
        const e = produits[k];
        expect(e.execution.tool, `seq ${a.seq}`).to.equal(a.tool);
        expect(e.prev_hash).to.equal(a.prev_hash);
        expect(e.hash, `hash seq ${a.seq}`).to.equal(a.hash);
        expect(e.sig).to.equal(a.sig);
        expect(N.utf8(N.formeCanoniqueEvenement(e)).length).to.equal(a.canonical_length);
        expect(N.egaliteJson(e, evenements[k]), `seq ${a.seq} clé pour clé`).to.equal(true);
      });
      const r = N.verifierJournal(produits, json(`${R}/cles.json`));
      expect(r.valide, JSON.stringify(r.diagnostics ?? r)).to.equal(true);
    });

    it("politique : policy_version, policy_sha256 et longueur du JCS intégral (EX-8.11)", function () {
      const emp = empreintePolitique(politique);
      expect(emp.policy_version).to.equal(attendu.policy_version);
      expect(emp.policy_sha256).to.equal(attendu.policy_sha256);
      expect(emp.length).to.equal(attendu.policy_length);
      const p = pieces.find((x) => x.sha256 === attendu.policy_sha256);
      egalRef(piecePolitique(politique), p);
    });

    it("décision : objet A et D_A (CT-1 §6.3)", function () {
      const A = N.objetApprobation(produits[5]);
      expect(A).to.deep.equal(attendu.A);
      expect(N.octetsVersHex(N.condenseApprobation(A))).to.equal(attendu.D_A);
    });

    it("segment : en-tête et huit lignes JCS v0, octets exacts (12.2)", function () {
      const segs = fs.readdirSync(path.join(repertoire, "segments")).sort();
      expect(segs[0]).to.equal("seg-0000000000000001-00000000000000000001.ndjson");
      const ecrit = fs.readFileSync(path.join(repertoire, "segments", segs[0]));
      const publie = lire(`${R}/segment.ndjson`);
      expect(Buffer.compare(ecrit, publie)).to.equal(0);
      expect(ecrit.length).to.equal(attendu.segment_length);
      expect(N.sha256Hex(new Uint8Array(ecrit))).to.equal(attendu.segment_sha256);
    });

    it("journal d'intention : ligne intention, ligne contexte, levée, octets exacts (12.5)", function () {
      const ecrit = fs.readFileSync(path.join(repertoire, "intentions", "intentions-00000000000000000001.ndjson"));
      expect(Buffer.compare(ecrit, lire(`${R}/intentions.ndjson`))).to.equal(0);
      expect(intentionEcrite.intent_id).to.equal(attendu.intent_id);
      expect(intentionEcrite.intention_sha256).to.equal(attendu.intention_sha256);
      const premiere = ecrit.toString("utf8").split("\n")[0];
      expect(N.sha256Hex(octetsUtf8(premiere))).to.equal(attendu.intention_sha256);
    });

    it("pièces : sérialisation de §8 et référence de chaque pièce publiée ; définitions et liste dérivées de la liste servie (EX-4.45)", function () {
      for (const p of pieces) egalRef(pieceDepuisPubliee(p), p);
      const entrees = json(`${R}/entrees.json`);
      const liste = pieceListeAnnoncee(entrees.served_list);
      const defs = Object.fromEntries(entrees.served_list.map((d) => [d.name, pieceDefinitionOutil(d)]));
      for (const seq of [3, 5, 7]) {
        const e = evenements[seq - 1];
        expect(e.context).to.deep.equal([defs[e.execution.tool].referenceContexte(), liste.referenceContexte()]);
      }
      // Arguments non rédigés de seq 3 : JCS intégral de params.arguments (8.2).
      const ligne3 = JSON.parse(entrees.calls.find((c) => c.seq === 3).host_line);
      egalRef(pieceJson(ligne3.params.arguments), evenements[2].execution.arguments);
    });

    it("période : manifeste et signature de clôture égaux à ceux du dossier de seq 7 (CT-1 §10)", function () {
      const m = JSON.parse(fs.readFileSync(path.join(repertoire, "manifestes", "periode-1794304800.json"), "utf8"));
      const s = JSON.parse(fs.readFileSync(path.join(repertoire, "manifestes", "periode-1794304800.sig"), "utf8"));
      expect(m).to.deep.equal(json(`${R}/dossier-seq-7/manifeste.json`));
      expect(s).to.deep.equal(json(`${R}/dossier-seq-7/manifeste.sig`));
      expect(m.root).to.equal(attendu.period.root);
      expect(N.hacherManifeste(m)).to.equal(attendu.period.period_hash);
      expect(m.nonce).to.equal(attendu.period.nonce);
      expect([m.period_start, m.period_end]).to.deep.equal([attendu.period.period_start, attendu.period.period_end]);
      // Point de clôture : il engage exactement les feuilles du manifeste (CT-1 §10.5 règle 4).
      const serie = fs.readFileSync(path.join(repertoire, "points", "periode-1794304800.ndjson"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
      const r = N.verifierSeriePointsDeControle(serie, m, produits, json(`${R}/cles.json`));
      expect(r.valide, r.errors.join(" ; ")).to.equal(true);
    });

    it("le dossier publié de seq 7 a les événements reconstruits (evenement, voisins, approbations)", function () {
      const D = `${R}/dossier-seq-7`;
      expect(json(`${D}/evenement.json`)).to.deep.equal(produits[6]);
      const vs = json(`${D}/voisins.json`);
      expect(vs.previous).to.deep.equal(produits[5]);
      expect(vs.next).to.deep.equal(produits[7]);
      expect(json(`${D}/approbations.json`).events).to.deep.equal([produits[5]]);
      const chemin = json(`${D}/chemin.json`);
      expect(chemin).to.deep.equal(N.preuveInclusion(6, produits.map((e) => e.hash)));
      for (const f of ["dossier.json", "cles.json", "attendu.json"]) lire(`${D}/${f}`);
    });
  });

  describe("pieces-mcp/appels (B.4) : part de §8", function () {
    const dirs = fs.readdirSync(path.join(VECTEURS_CT2, "pieces-mcp", "appels")).sort();
    for (const cas of dirs) {
      it(cas, function () {
        const R = `pieces-mcp/appels/${cas}`;
        const a = json(`${R}/attendu.json`);
        const hote = lire(`${R}/hote.jsonl`).toString("utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
        const amont = lire(`${R}/amont.jsonl`).toString("utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
        if (a.rejected) {
          // Refus au pas 1 de 4.4 : ni pièce ni événement (frontal MCP, lot suivant).
          expect(a.context).to.deep.equal([]);
          return;
        }
        for (const [nom, p] of Object.entries(a.pieces)) if (p) egalRef(pieceDepuisPubliee(p), p);
        // Liste servie (dernière réponse tools/list de hote.jsonl) : pièces de définition et de liste.
        const reponsesListe = hote.filter((x) => x.dir === "out" && x.line).map((x) => JSON.parse(x.line)).filter((m) => Array.isArray(m.result?.tools));
        const servie = reponsesListe[reponsesListe.length - 1].result.tools;
        const def = pieceDefinitionOutil(servie.find((t) => t.name === a.tool_announced));
        const liste = pieceListeAnnoncee(servie);
        egalRef(def, a.pieces.definition);
        egalRef(liste, a.pieces.list);
        const contexte = [def.referenceContexte()];
        if (a.pieces.definition_current) contexte.push(new Piece(octetsUtf8(a.pieces.definition_current.bytes), { media_type: "application/json" }).referenceContexte());
        contexte.push(liste.referenceContexte());
        expect(a.context).to.deep.equal(contexte);
        // Arguments non rédigés : JCS intégral de params.arguments (8.2), nombres non entiers compris (8.1).
        const appel = hote.filter((x) => x.dir === "in" && x.line).map((x) => JSON.parse(x.line)).find((m) => m.method === "tools/call");
        if (!a.pieces.arguments.redacted) egalRef(pieceJson(analyserJsonIntegral(JSON.stringify(appel.params.arguments ?? {}))), a.pieces.arguments);
        // Résultat reçu de l'amont (pas 12) : `result` objet, ou erreur JSON-RPC.
        // L'issue sans réponse (délai, taille, perte : codes -31011, -31013, -31014) a la forme
        // d'erreur de l'enregistreur, fixée par le frontal MCP (lot suivant).
        const sortant = amont.filter((x) => x.dir === "out" && x.line).map((x) => analyserJsonIntegral(x.line)).find((m) => m.method === "tools/call");
        const reponse = amont.filter((x) => x.dir === "in" && x.line).map((x) => analyserJsonIntegral(x.line)).find((m) => m.id === sortant?.id && ("result" in m || "error" in m));
        const issueEnregistreur = [-31010, -31011, -31013, -31014, -31017].includes(analyserJsonIntegral(a.pieces.result?.bytes ?? "{}")?.noortrace_jsonrpc_error?.code);
        if (a.pieces.result && reponse && !a.pieces.result.redacted && !issueEnregistreur) {
          if (reponse.result !== null && typeof reponse.result === "object" && !Array.isArray(reponse.result)) egalRef(pieceJson(reponse.result), a.pieces.result);
          else if (reponse.error) egalRef(pieceErreurJsonRpc(reponse.error), a.pieces.result);
          else {
            const type = reponse.result === null ? "null" : Array.isArray(reponse.result) ? "array" : typeof reponse.result;
            egalRef(pieceErreurJsonRpc({ code: -32603, message: "noortrace: resultat amont invalide", data: { result_type: type } }), a.pieces.result);
          }
        }
      });
    }
  });

  describe("pieces-modele (B.5) : part de §8 ; formes consolidées par le frontal modèle (§5.4)", function () {
    const dirs = fs.readdirSync(path.join(VECTEURS_CT2, "pieces-modele")).sort();
    for (const cas of dirs) {
      it(cas, function () {
        const R = `pieces-modele/${cas}`;
        for (const f of fs.readdirSync(path.join(VECTEURS_CT2, R))) if (f !== "attendu.json") lire(`${R}/${f}`);
        const a = json(`${R}/attendu.json`);
        // Réassemblage du flux publié (EX-5.14 à EX-5.17, EX-5.34, EX-5.35) ; le reste
        // de la dérivation est rejoué de bout en bout par enregistreur-modele-vecteurs.test.js.
        if (fs.existsSync(path.join(VECTEURS_CT2, R, "reponse.sse")) && json(`${R}/reponse-entetes.json`).status < 400) {
          expect(jcsIntegral(consoliderFlux(a.format, new Uint8Array(lire(`${R}/reponse.sse`))).forme)).to.equal(jcsIntegral(a.consolidated));
        }
        if (!a.pieces) return;
        for (const p of Object.values(a.pieces)) if (p) egalRef(pieceDepuisPubliee(p), p);
        // code.prompt_version = SHA-256 de la pièce « prompt système » (EX-8.6).
        if (a.pieces.system_prompt) expect(a.prompt_version).to.equal(a.pieces.system_prompt.sha256);
      });
    }
  });

  describe("redaction/cas.json (B.3) : part de §8", function () {
    it("chaque pièce rédigée publiée a la sérialisation et la référence de §8", function () {
      for (const c of json("redaction/cas.json")) {
        const e = c.expected;
        const p = e.media_type === "text/plain" ? pieceTexte(e.piece, { redacted: e.redacted }) : pieceJson(analyserJsonIntegral(e.piece), { redacted: e.redacted });
        expect(N.decoderUtf8(p.octets), c.name).to.equal(e.piece);
        expect(p.reference.sha256, c.name).to.equal(e.sha256);
        expect(p.reference.length).to.equal(e.length);
      }
    });
  });

  describe("redaction/ (B.3) : rejeu par le rédacteur (lot « rédaction », §10)", function () {
    it("politiques (schéma, EX-10.6) ; cas.json rédigé octet pour octet, comptes compris", function () {
      const cle = N.sha256(N.utf8("noortrace/vecteurs/v0/cle-pseudonyme/test"));
      const pol = {};
      for (const f of ["politique-pii-v1.json", "politique-pseudonyme-test.json", "politique-regles-test.json"]) {
        const d = json(`redaction/${f}`);
        expect(validerPolitiqueRedaction(d).erreurs, f).to.deep.equal([]);
        pol[d.name] = new PolitiqueCompilee(d, { cle: d.pseudonym_key ? cle : null });
      }
      for (const c of json("redaction/cas.json")) {
        const d = typeof c.input === "string" ? { genre: "texte", portee: c.scope, outil: c.tool, texte: c.input } : { genre: "json", portee: c.scope, outil: c.tool, valeur: c.input };
        const r = produirePiece(pol[c.policy], d, { budgetMs: 1000 });
        expect(N.decoderUtf8(r.piece.octets), c.name).to.equal(c.expected.piece);
        expect(r.piece.reference.sha256, c.name).to.equal(c.expected.sha256);
        expect(r.redacted, c.name).to.equal(c.expected.redacted);
        expect(r.comptes, c.name).to.deep.equal(c.expected.matches);
      }
    });

    it("motifs.json : admis et refusés, première correspondance (EX-10.6)", function () {
      for (const m of json("redaction/motifs.json")) {
        const c = controlerMotif(m.pattern);
        expect(c.admis, m.pattern).to.equal(m.admis);
        for (const x of m.matches ?? []) expect(premiereCorrespondance(c.regexp, x.input, { entiere: true })).to.equal(x.first);
      }
    });
  });

  describe("pieces-mcp/agregation (B.4) : rejeu par l'agrégation du frontal MCP (§4.3)", function () {
    it("noms annoncés, rejets d'EX-4.11, classes, empreintes, pages ; sans préfixe à deux serveurs : refus", function () {
      for (const d of ["", "/normalisation", "/sans-prefixe-un-serveur"]) {
        const s = json(`pieces-mcp/agregation${d}/serveurs.json`);
        const a = json(`pieces-mcp/agregation${d}/attendu.json`);
        const r = agreger({ serveurs: s, prefixe: a.prefix, normalisations: a.normalisations ?? [] });
        expect(r.annonces.map((x) => ({ server_alias: x.server_alias, original: x.original, announced: x.announced, class: x.class, definition_sha256: x.definition_sha256 })), d).to.deep.equal(a.announced);
        expect(r.rejets, d).to.deep.equal(a.rejected);
        expect(paginer(r.annonces, a.page_size).map((p) => p.map((x) => x.announced)), d).to.deep.equal(a.pages);
      }
      // Refus de configuration (EX-4.10) : vérifié par enregistreur-mcp-vecteurs.test.js.
      expect(json("pieces-mcp/agregation/sans-prefixe/serveurs.json").length).to.equal(2);
      expect(json("pieces-mcp/agregation/sans-prefixe/attendu.json").configuration_refusee).to.equal(true);
    });
  });

  describe("inventaire", function () {
    // Familles et fichiers du générateur (B.1) ; verificateur-independant/ et
    // confrontation/ ne sont pas des données et ne sont pas ouverts.
    const LOTS_SUIVANTS = {
      otel: "ingestion OpenTelemetry (§6.8)",
      worm: "WORM et gel juridique (§12.6, §12.11)",
      "cout-agent": "coût annuel par agent (§16.4)",
      "INDEX.md": "index lisible, sans donnée à rejouer",
    };
    const IGNORES = new Set(["verificateur-independant", "confrontation"]);

    function lister(rel) {
      const p = path.join(VECTEURS_CT2, rel);
      if (fs.statSync(p).isFile()) return [rel];
      return fs.readdirSync(p).sort().flatMap((n) => lister(rel ? `${rel}/${n}` : n));
    }

    // Vecteurs que la part de §8 rejoue ici et qu'un lot rejoue aussi de bout
    // en bout (frontal, moteur de politique, cœur) : fichier de test du lot.
    const REJOUES_DE_BOUT_EN_BOUT = {
      "pieces-mcp/appels/approbation-en-attente": "enregistreur-politique-vecteurs.test.js",
      "pieces-mcp/appels/approbation-refus": "enregistreur-politique-vecteurs.test.js",
      "evenements/journal-demo": "enregistreur-politique-vecteurs.test.js",
    };

    it("les vecteurs du moteur de politique (section d) sont rejoués de bout en bout par son test", function () {
      for (const [rel, test] of Object.entries(REJOUES_DE_BOUT_EN_BOUT)) {
        expect(lister(rel).every((f) => consommes.has(f) || f.startsWith("evenements/journal-demo/dossier-seq-7/")), rel).to.equal(true);
        const source = fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), test), "utf8");
        expect(source, `${test} rejoue ${rel}`).to.contain(rel.startsWith("pieces-mcp/appels/") ? rel.slice("pieces-mcp/appels/".length) : rel);
      }
    });

    // Frontal modèle (section b) : vecteurs rejoués de bout en bout par la passerelle.
    const REJOUES_PAR_LE_FRONTAL_MODELE = { "pieces-modele": "enregistreur-modele-vecteurs.test.js", "evenements/journal-demo": "enregistreur-modele-vecteurs.test.js" };

    it("les vecteurs du frontal modèle (section b) sont rejoués de bout en bout par son test", function () {
      for (const [rel, test] of Object.entries(REJOUES_PAR_LE_FRONTAL_MODELE)) {
        expect(lister(rel).every((f) => consommes.has(f) || f.startsWith("evenements/journal-demo/dossier-seq-7/")), rel).to.equal(true);
        const source = fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), test), "utf8");
        expect(source, `${test} rejoue ${rel}`).to.contain(`"${rel}`);
      }
    });

    it("chaque fichier de vecteur est rejoué ou attribué à un lot suivant", function () {
      const fichiers = fs.readdirSync(VECTEURS_CT2).filter((n) => !IGNORES.has(n)).sort().flatMap((n) => lister(n));
      const nonAttribues = [];
      const rejoues = [];
      const suivants = [];
      for (const f of fichiers) {
        if (consommes.has(f)) rejoues.push(f);
        else if (Object.keys(LOTS_SUIVANTS).some((k) => f === k || f.startsWith(`${k}/`))) suivants.push(f);
        else nonAttribues.push(f);
      }
      expect(nonAttribues, "fichiers ni rejoués ni attribués").to.deep.equal([]);
      expect(rejoues.length).to.be.greaterThan(150);
      this.test.title += ` (${rejoues.length} rejoués, ${suivants.length} pour les lots suivants)`;
    });
  });
});
