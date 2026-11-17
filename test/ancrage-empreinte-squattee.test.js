import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";
import * as A from "../scripts/lib/ancrage.mjs";
import { genererCt5, traceEmpreinteSquattee } from "../scripts/vecteurs/generer-ct5.mjs";

// Trace de planification « empreinte-squattee » (CT-5 §8.10, annexe A.3 ;
// menace MN-58 de CT-7) : l'empreinte d'ancre de la période est déjà ancrée
// par un autre émetteur (CT-4 OP-9, §8.3). CT-4 EX-8.4 et CT-5 EX-4.7 : l'ancre
// part au registre avant la requête RFC 3161 ; CT-4 EX-8.6 et CT-5 EX-8.10,
// EX-9.7 : aucun nouvel essai, demande refusee, alerte critique, incident
// consigné.
//
// La trace est construite par le générateur des vecteurs de CT-5
// (traceEmpreinteSquattee), rejouée par la bibliothèque de référence
// (scripts/lib/ancrage.mjs, verifierTrace) et publiée par défaut dans
// spec/vecteurs/ct-5/planification depuis la décision du porteur du
// 2026-11-16 (variante B) : après le refus de l'ancre, le jeton de clôture
// reste attente_registre et la période reste signalée registry_pending
// (EX-8.4 règle 2, AN-36, EX-9.7 ; CT-4 EX-8.6). Les mutants de la variante B
// sont dans test/ancrage-reference-revue.test.js.

describe("CT-5 §8.10 : trace de planification empreinte-squattee (ancre de période refusée sur empreinte_squattee ; CT-4 EX-8.4, EX-8.6 ; CT-5 EX-4.7, EX-8.10)", function () {
  this.timeout(300_000);
  let sortie;
  let trace;
  before(function () {
    sortie = fs.mkdtempSync(path.join(process.env.NOORTRACE_TMP ?? os.tmpdir(), "ct5-squat-"));
    trace = traceEmpreinteSquattee();
  });
  after(function () {
    fs.rmSync(sortie, { recursive: true, force: true });
  });
  const actions = (action, pred = () => true) => trace.expected.filter((a) => a.action === action && pred(a));
  const demande = (kind) => trace.queue_after.find((d) => d.kind === kind);

  it("la trace est conforme au schéma planificateur-ancrage-v0 et rejouée sans écart par verifierTrace ; la génération par défaut la publie (soixante-deux traces depuis le complément du 2026-11-16 ; décision du porteur du 2026-11-16), aux mêmes octets que traceEmpreinteSquattee et que spec/vecteurs/ct-5", function () {
    const schema = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "spec", "schemas", "planificateur-ancrage-v0.schema.json"), "utf8"));
    expect(J.validerSchema(trace, schema)).to.deep.equal([]);
    expect(A.verifierTrace(trace)).to.deep.equal([]);
    expect(trace.id).to.equal("empreinte-squattee");
    expect(trace.queue_before).to.deep.equal([]);
    expect(trace.inputs.map((e) => e.type).slice(0, 7)).to.deep.equal(["demarrage", "point_produit", "periode_close", "reponse_ots", "inclusion_registre", "reponse_rfc3161", "echec_registre"]);
    expect(trace.inputs.at(-1).type).to.equal("arret");
    const echec = trace.inputs.find((e) => e.type === "echec_registre");
    expect(echec.data).to.deep.equal({ request_id: demande("ancre_registre_periode").id, code: "empreinte_squattee" });
    const defaut = path.join(sortie, "defaut");
    genererCt5({ racine: defaut });
    const fichiers = fs.readdirSync(path.join(defaut, "planification")).sort();
    // CT-5 A.3 (complément du 2026-11-16, ordre du démarrage ; puis clé de chaîne du verrou d'EX-9.4 ; puis minuteries de deux journaux, EX-8.16 ; puis refus de l'ancre d'une période et ordre des ancres de points, EX-8.10 et EX-9.4 : deux de plus ; puis l'ancre de la période après celle de son point de clôture et l'âge d'abandon OpenTimestamps, EX-9.4 et EX-8.11 : deux de plus, dont une à file ; puis la clé retenue par l'ancre d'une période, la soumission OpenTimestamps tardive et l'alerte du refus après un redémarrage, EX-9.4, EX-8.11 et EX-8.10 : trois de plus, dont deux à file ; puis l'ancre d'un point en reprise quand le point suivant de sa période est admis, EX-9.5 et EX-9.4 : une de plus, sans file) : soixante-deux traces.
    expect(fichiers).to.have.length(62).and.to.include("empreinte-squattee.json");
    const ecrite = fs.readFileSync(path.join(defaut, "planification", "empreinte-squattee.json"), "utf8");
    expect(ecrite).to.equal(JSON.stringify(trace, null, 2) + "\n");
    expect(ecrite).to.equal(fs.readFileSync(path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-5", "planification", "empreinte-squattee.json"), "utf8"));
    expect(fs.readFileSync(path.join(defaut, "INDEX.md"), "utf8")).to.match(/^\| `empreinte-squattee\.json` \| \d+ \| \d+ \| 0 \| 5 \| /m);
  });

  it("ancre d'abord : aucune requête RFC 3161 sur periodHash ne part avant la transaction de l'ancre de la période, ni avant son refus (CT-4 EX-8.4, CT-5 EX-4.7)", function () {
    const ancre = demande("ancre_registre_periode").id;
    const jeton = demande("jeton_periode").id;
    const rang = (pred) => trace.expected.findIndex(pred);
    const envoiAncre = rang((a) => a.action === "envoyer_registre" && a.request_id === ancre);
    const refus = rang((a) => a.action === "journaliser" && a.request_id === ancre && a.detail.event === "anchor_refused");
    expect(envoiAncre).to.be.at.least(0);
    expect(envoiAncre).to.be.below(refus);
    expect(trace.expected.slice(0, refus).some((a) => a.action === "envoyer_rfc3161" && a.request_id === jeton)).to.equal(false);
    // Avant le refus, le jeton de clôture attend le registre.
    expect(trace.expected.slice(0, refus).filter((a) => a.action === "ecrire_file" && a.request_id === jeton).map((a) => a.detail.state)).to.deep.equal(["attente_registre"]);
  });

  it("aucun nouvel essai : une seule transaction pour l'ancre de la période, demande refusee, tentative en échec permanent empreinte_squattee, aucune action sur elle après le refus, même au-delà de deux fois inclusion_alert_s (CT-4 EX-8.6, CT-5 EX-8.10)", function () {
    const d = demande("ancre_registre_periode");
    expect(actions("envoyer_registre", (a) => a.request_id === d.id)).to.have.length(1);
    expect(d.state).to.equal("refusee");
    expect(d.result).to.equal(null);
    expect(d.attempts.map((x) => [x.n, x.outcome, x.error_code])).to.deep.equal([[1, "echec_permanente", "empreinte_squattee"]]);
    const refus = trace.expected.findIndex((a) => a.action === "journaliser" && a.request_id === d.id && a.detail.event === "anchor_refused");
    expect(trace.expected.slice(refus + 1).filter((a) => a.request_id === d.id)).to.deep.equal([]);
    expect(actions("journaliser", (a) => a.detail.event === "anchor_retry")).to.deep.equal([]);
    expect(trace.config.registry.inclusion_alert_s).to.equal(60);
    expect(trace.inputs.filter((e) => e.type === "tic").map((e) => e.t)).to.deep.equal(["2026-11-03T14:01:10.000Z", "2026-11-03T14:02:10.000Z"]);
  });

  it("incident consigné : alerte critique empreinte_squattee et ligne anchor_refused, une fois chacune, à l'instant du refus", function () {
    const d = demande("ancre_registre_periode");
    expect(actions("alerter", (a) => a.detail.code === "empreinte_squattee")).to.deep.equal([{ t: "2026-11-03T14:00:04.000Z", action: "alerter", request_id: d.id, detail: { code: "empreinte_squattee", severity: "critique" } }]);
    const lignes = actions("journaliser", (a) => a.detail.event === "anchor_refused");
    expect(lignes).to.have.length(1);
    expect([lignes[0].t, lignes[0].request_id, lignes[0].detail.error_code]).to.deep.equal(["2026-11-03T14:00:04.000Z", d.id, "empreinte_squattee"]);
  });

  it("trace publiée (spec/vecteurs/ct-5/planification/empreinte-squattee.json) : la période dont l'ancre est refusée reste signalée registry_pending (CT-4 EX-8.6 ; CT-5 EX-9.7) : jeton de clôture attente_registre sans tentative, examiné toutes les inclusion_alert_s après le refus (registry_pending à 14:01:00.250 et 14:02:00.250, âges 60 et 120 s), alerte majeure une fois, prochain examen programmé à 14:03:00.250 ; aucune requête RFC 3161 sur periodHash", function () {
    const publiee = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-5", "planification", "empreinte-squattee.json"), "utf8"));
    expect(A.verifierTrace(publiee)).to.deep.equal([]);
    const jeton = publiee.queue_after.find((d) => d.kind === "jeton_periode");
    expect([jeton.state, jeton.attempts.length, jeton.result, jeton.due_at]).to.deep.equal(["attente_registre", 0, null, "2026-11-03T14:03:00.250Z"]);
    const refus = publiee.expected.findIndex((a) => a.action === "journaliser" && a.detail.event === "anchor_refused");
    const apres = publiee.expected.slice(refus + 1).filter((a) => a.request_id === jeton.id);
    expect(apres.filter((a) => a.action === "journaliser").map((a) => [a.t, a.detail.event, a.detail.age_s])).to.deep.equal([["2026-11-03T14:01:00.250Z", "registry_pending", 60], ["2026-11-03T14:02:00.250Z", "registry_pending", 120]]);
    expect(apres.filter((a) => a.action === "alerter").map((a) => [a.t, a.detail.code, a.detail.severity])).to.deep.equal([["2026-11-03T14:01:00.250Z", "registry_pending", "majeure"]]);
    expect(apres.filter((a) => a.action === "programmer").map((a) => [a.detail.next_at, a.detail.reason]).at(-1)).to.deep.equal(["2026-11-03T14:03:00.250Z", "attente_registre"]);
    expect(publiee.expected.filter((a) => a.action === "envoyer_rfc3161" && a.request_id === jeton.id)).to.deep.equal([]);
  });

  it("les autres ancres ne sont pas touchées par le refus : preuve OpenTimestamps de la période en attente, ancre et jeton du point de clôture obtenus ; cinq demandes dans la file", function () {
    expect(demande("ots_periode").state).to.equal("en_attente");
    expect(demande("ancre_registre_point").state).to.equal("obtenue");
    expect(demande("jeton_point").state).to.equal("obtenue");
    expect(trace.queue_after).to.have.length(5);
  });
});
