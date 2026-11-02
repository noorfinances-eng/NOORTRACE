// Annexe A de CT-2 rejouée octet par octet par le cœur : un appel d'écriture
// traverse l'enregistreur (pièces de définition, de liste, d'arguments et de
// résultat ; événement `retenue` ; décision ; ligne intention ; événement
// relayé ; ligne de segment). Les valeurs attendues sont lues dans le texte
// de la spécification ; la chaîne est ancrée sur l'événement seq 1 de CT-1
// annexe A, repris inchangé (A, préambule).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as N from "@noortrace/noyau";
import {
  Ecrivain, IndexChaine, MagasinPieces, JournalExploitation, EtatDegrade, ControleurHorloge, HorlogeReglable,
  SignataireFichier, SignataireVerifie, MagasinBailMemoire, analyserJsonIntegral, pieceJson, pieceDefinitionOutil,
  pieceListeAnnoncee, partielAppelOutil, partielDecision, repriseDeRetenue, evaluerEffets, ligneSegment,
  objetIntention, ligneIntention,
} from "@noortrace/enregistreur";
import { SPEC, blocApres, graine, repertoireTemporaire, texteCT2 } from "./fixtures/enregistreur-coeur/outils.mjs";
import { CLES_HARDHAT } from "@noortrace/enregistreur/factice";

const ms = (t) => N.decoderHorodatage(t);
const u8 = (s) => new Uint8Array(Buffer.from(s, "utf8"));

describe("enregistreur, cœur : annexe A de CT-2, octet par octet", function () {
  this.timeout(30000);
  const T = texteCT2();
  const debutA = T.split("\n").findIndex((l) => l.startsWith("## Annexe A"));
  const bloc = (marqueur) => blocApres(T, marqueur, debutA).texte;
  const T1 = fs.readFileSync(path.join(SPEC, "CT-1-evenements-et-formats.md"), "utf8");
  const seq1 = JSON.parse(blocApres(T1, "Seq 1 — échange avec le modèle").texte);

  let ecrivain;
  let horloge;
  let repertoire;
  const res = {};

  before(async function () {
    const dir = repertoireTemporaire();
    repertoire = path.join(dir, "journal");
    fs.mkdirSync(repertoire, { recursive: true });
    horloge = new HorlogeReglable(ms("2026-11-03T13:41:07.000Z"));
    const journal = new JournalExploitation({ murale: () => horloge.murale() });
    const degrade = new EtatDegrade(journal, null, () => horloge.murale());
    const index = new IndexChaine();
    // La version de politique de l'annexe est tenue pour annoncée (chaîne illustrative, A préambule).
    index.politiques.set("2026-11-01", N.ZERO32);
    ecrivain = new Ecrivain({
      repertoire,
      org_id: seq1.org_id,
      journal_id: seq1.journal_id,
      instance_id: "enregistreur-sinistres-1",
      recorder: "0.1.0",
      signataire: new SignataireVerifie(new SignataireFichier({ environment: "developpement", cles: new Map([["rec-test-01", graine("rec-test-01")]]) })),
      bail: Object.assign(new MagasinBailMemoire(1), { detenu: true, epoque: 1 }),
      horloge: new ControleurHorloge(horloge, {}, degrade, journal),
      degrade,
      journal,
      index,
      pieces: new MagasinPieces(repertoire),
      fsync: { group_max_events: 1, group_max_wait_ms: 0 },
    });
    await ecrivain.demarrer(
      {
        lastSeq: 1,
        lastHash: seq1.hash,
        lastTs: ms(seq1.ts),
        cleCourante: "rec-test-01",
        epoqueMax: null,
        periode: { start: 1793710800, firstSeq: 1, hashAvant: N.ZERO32, evenements: [{ seq: 1, ts: ms(seq1.ts), hash: seq1.hash }] },
        prevPeriodHash: N.ZERO32,
        serie: { prev: N.ZERO32, dernierTs: null, dernierTreeSize: 0, prochainJ: 60 },
      },
      1,
    );

    // A.1 : ligne reçue, définition courante, pièces de contexte et pièce « arguments ».
    res.ligneHote = bloc("Ligne reçue de l'hôte");
    const appel = JSON.parse(res.ligneHote);
    const definition = JSON.parse(bloc("La définition courante de l'outil"));
    res.definition = pieceDefinitionOutil(definition);
    res.liste = pieceListeAnnoncee([definition]);
    // Rédaction (lot suivant) : la valeur rédigée par la règle iban de pii-v1 est celle du pas 4.
    const redigee = { ...appel.params.arguments, beneficiary_iban: "[REDIGE:iban]" };
    res.arguments = pieceJson(redigee, { redacted: true });
    for (const p of [res.definition, res.liste, res.arguments]) await new MagasinPieces(repertoire).ecrire(p);
    const contexte = [res.definition.referenceContexte(), res.liste.referenceContexte()];
    const base = {
      delegation: seq1.delegation,
      code: { model: seq1.code.model, prompt_version: seq1.code.prompt_version, policy_version: "2026-11-01", recorder: "0.1.0" },
      intent: seq1.intent,
      tool: "sap.payments.create",
      arguments: res.arguments.reference,
      context: contexte,
      nomRedaction: "pii-v1",
    };

    // A.2 : retenue (seq 2), décision (seq 3).
    horloge.aller(ms("2026-11-03T13:41:07.218Z"));
    res.retenue = await ecrivain.sceller(partielAppelOutil({ ...base, policy: { rule: "paiement > 5000 CHF", decision: "a_approuver", ticket: "apr-1192" }, approval: null, status: "retenue" }));
    const A = { decision: "approuve", journal_id: seq1.journal_id, org_id: seq1.org_id, request_hash: res.retenue.hash, ticket: "apr-1192" };
    res.A = A;
    res.signatures = [N.signerApprobation(N.hexVersOctets(CLES_HARDHAT[0], 32), A), N.signerApprobation(N.hexVersOctets(CLES_HARDHAT[1], 32), A)];
    horloge.aller(ms("2026-11-03T13:52:40.511Z"));
    res.decision = await ecrivain.sceller(
      partielDecision({
        retenue: res.retenue,
        approval: {
          decision: "approuve",
          ticket: "apr-1192",
          request_hash: res.retenue.hash,
          threshold: { required: 2, size: 3 },
          approvers: ["0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"],
          signatures: res.signatures,
          reason: "Pièces validées",
        },
        policy_version: "2026-11-01",
        recorder: "0.1.0",
        org_id: seq1.org_id,
        journal_id: seq1.journal_id,
      }),
      { completer: (e, ts) => (e.approval.at = ts) },
    );

    // A.3 : intention (pas 8), réponse (pas 11), résultat (pas 12), effets, événement (pas 13).
    const rep = repriseDeRetenue(res.retenue, res.decision);
    const partiel = partielAppelOutil({ ...base, intent: rep.intent, policy: rep.policy, approval: rep.approval, status: "executee", result: null, duration_ms: 0, is_error: false });
    ecrivain.compteurIntention = 40;
    horloge.aller(ms("2026-11-03T13:52:40.678Z"));
    res.intention = await ecrivain.inscrireIntention({ upstream_id: "e-000000000041", host: "agent-sinistres-stdio", tool: "sap.payments.create", arguments: res.arguments.reference, ticket: "apr-1192" }, partiel);
    const reponse = analyserJsonIntegral(bloc("9. **Réponse**"));
    res.resultat = pieceJson(reponse.result);
    await new MagasinPieces(repertoire).ecrire(res.resultat);
    res.effets = evaluerEffets({
      gabarit: [{ system: "SAP", action: "ecriture", object: "/result/content/0/text", amount: "/arguments/amount", currency: "/arguments/currency", extract: "PAY-[0-9]{4}-[0-9]{5}" }],
      classe: "ecriture",
      alias: "sap",
      nomOrigine: "sap.payments.create",
      arguments: redigee,
      resultat: reponse.result,
    });
    horloge.aller(ms("2026-11-03T13:52:41.090Z"));
    res.relaye = await ecrivain.sceller(
      partielAppelOutil({ ...base, intent: rep.intent, policy: rep.policy, approval: rep.approval, status: "executee", result: res.resultat.reference, duration_ms: 412, is_error: false, effects: res.effets.effets }),
      { leverIntention: res.intention.intent_id },
    );
    await ecrivain.fermer();
  });

  it("A.1 : ligne reçue de 408 octets ; pièce de définition (406 octets) et liste annoncée (418 octets)", function () {
    expect(u8(res.ligneHote).length).to.equal(408);
    expect(N.decoderUtf8(res.definition.octets)).to.equal(bloc("Sa pièce (JCS intégral, 406 octets)"));
    expect(res.definition.reference).to.deep.equal({ sha256: "0x7d2ffcd2cba25dbd90b54926be79c845131109b2e1bc4ccc22389fb8a26a498a", length: 406, redacted: false, media_type: "application/json" });
    expect(res.liste.reference).to.deep.equal({ sha256: "0xbce6c768f26f72d7377fa3098262b61db83bcc740fc528be536acaa7f168033e", length: 418, redacted: false, media_type: "application/json" });
  });

  it("A.1 pas 4 : pièce « arguments » rédigée, JCS intégral, 96 octets", function () {
    expect(N.decoderUtf8(res.arguments.octets)).to.equal(bloc("rédigée, puis JCS intégral, 96 octets"));
    expect(res.arguments.reference).to.deep.equal({ sha256: "0x6cfc43b54a70eee0141d2fc7d1acc06003ee23354ac76f2097ef74958d91bbb4", length: 96, redacted: true });
    expect(N.encoderBase64(res.arguments.octets)).to.equal(
      "eyJhbW91bnQiOiI3NDAwLjAwIiwiYmVuZWZpY2lhcnlfaWJhbiI6IltSRURJR0U6aWJhbl0iLCJjbGFpbV9pZCI6IjIwMjYtNzc4MTIiLCJjdXJyZW5jeSI6IkNIRiJ9",
    );
  });

  it("A.2 pas 5 : événement `retenue` seq 2, clé pour clé, hash et sig", function () {
    const attendu = JSON.parse(bloc("5. **Événement `retenue`**"));
    expect(res.retenue).to.deep.equal(attendu);
    expect(res.retenue.hash).to.equal("0x793ab66aab9ca28f1176d8ff023ffe98f0eadb514aecb329fdffd7420e821bd6");
  });

  it("A.2 pas 6 : JCS(A), D_A, signatures EIP-191 des comptes Hardhat 1 et 2, décision seq 3", function () {
    const texte = bloc("6. **Décision**");
    expect(texte.split("\n")[0]).to.equal(`JCS(A) = ${N.jcs(res.A)}`);
    expect(N.octetsVersHex(N.condenseApprobation(res.A))).to.equal("0x411768329b8c16bdfe32c4a4b5f6993571c2e5d73b55fdf1f19d00fe408408a8");
    expect(res.signatures).to.deep.equal([
      "0xe6d383bce2a360d254823fd70827faef284269ba457832708c70e8956a6c2f4f6066998d2a083029d5816530d1c15b615c15de6504fc8c1a50a15f8bff131fbb1b",
      "0x64a98eee5687a9e5608b528200130c001414401543aaa01211b8b2666100dfbc3050be55d3d024d599e885424fbbd7ae1d05e050e259e1fd440a1e1c32f0fd1b1c",
    ]);
    expect(res.decision.execution.arguments.length).to.equal(287);
    expect(res.decision.execution.arguments.sha256).to.equal("0x6b5a72c84048bc9578e472c81185536afd446554b17d56ead46c39b717dc00be");
    expect(res.decision.hash).to.equal("0xa167496bc58e285bd1d1925e15b3d24c147bc9559e0a19065eade18ecf860371");
    expect(res.decision.sig).to.equal("0x3e086991193f3264ce7704946a14b60b638dbd039dcebab04afc079a1a1d5ee3c8f1ad0fdc4120abd9c6e3e728001eaeedb2e2792614f2d814524641e7b02c0d");
    expect(res.decision.approval.at).to.equal(res.decision.ts);
  });

  it("A.3 pas 7 : ligne intention de neuf clés, 482 octets, intention_sha256 ; ligne contexte de 1717 octets", function () {
    const attendue = bloc("7. **Préconditions et intention**");
    const ligne = N.decoderUtf8(ligneIntention(res.intention.intention)).replace(/\n$/, "");
    expect(ligne).to.equal(attendue);
    expect(u8(ligne).length).to.equal(482);
    expect(res.intention.intention_sha256).to.equal("0xdd28b1c3e93808ddb24979a145ca1fe131ba0adc5390291b3287c0b329310b08");
    expect(Object.keys(objetIntention(res.intention.intention))).to.have.length(9);
    const lignes = fs.readFileSync(path.join(repertoire, "intentions", "intentions-00000000000000000001.ndjson"), "utf8").split("\n");
    expect(u8(lignes[1]).length).to.equal(1717);
    expect(JSON.parse(lignes[2])).to.deep.equal({ lifted: "i-00000000000000000001-000000000041", seq: 4 });
  });

  it("A.3 pas 10 et 11 : pièce « résultat » (109 octets) et effet tiré du gabarit sur les valeurs rédigées", function () {
    expect(N.decoderUtf8(res.resultat.octets)).to.equal(bloc("10. **Pièce « résultat »**"));
    expect(res.resultat.reference).to.deep.equal({ sha256: "0x850627f5a2216e1d592b9a6a21d5df8f5a9454e7330809ba6a4d070a7f633b8c", length: 109, redacted: false });
    expect(res.effets.effets).to.deep.equal([{ system: "SAP", action: "ecriture", object: "PAY-2026-55120", amount: "7400.00", currency: "CHF" }]);
  });

  it("A.3 pas 12 : événement relayé seq 4, forme canonique C (2249 octets), hash et sig", function () {
    expect(res.relaye).to.deep.equal(JSON.parse(bloc("12. **Événement**")));
    const C = N.formeCanoniqueEvenement(res.relaye);
    expect(C).to.equal(bloc("Forme canonique `C`"));
    expect(u8(C).length).to.equal(2249);
    expect(res.relaye.hash).to.equal("0x8e2f87b9398cab6229bf44a72cd05565d00c30eafd8e51fb14dfaf9074d05ca6");
  });

  it("A.3 pas 13 : ligne de segment de 2465 octets, \\n compris, octets exacts dans le segment", function () {
    const ligne = ligneSegment(res.relaye);
    expect(ligne.length).to.equal(2465);
    expect(N.decoderUtf8(ligne)).to.equal(bloc("13. **Ligne de segment**") + "\n");
    const seg = fs.readFileSync(path.join(repertoire, "segments", "seg-0000000000000002-00000000000000000001.ndjson"));
    expect(seg.subarray(seg.length - ligne.length).equals(Buffer.from(ligne))).to.equal(true);
  });

  it("A.4 : la chaîne seq 1 (CT-1) à seq 4 vérifie (CT-1 §7)", function () {
    const cles = { version: 0, org_id: seq1.org_id, journal_id: seq1.journal_id, keys: [{ key_id: "rec-test-01", algorithm: "ed25519", public_key: "0xe2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045", valid_from: "2026-11-01T00:00:00.000Z", valid_to: null, source: "clé de test de CT-1 §13" }] };
    const r = N.verifierJournal([seq1, res.retenue, res.decision, res.relaye], cles);
    expect(r.valide, JSON.stringify(r)).to.equal(true);
  });
});
