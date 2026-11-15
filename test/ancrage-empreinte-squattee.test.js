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
// (traceEmpreinteSquattee ; option --avec-empreinte-squattee), puis rejouée
// par la bibliothèque de référence (scripts/lib/ancrage.mjs, verifierTrace).
// Elle n'est pas publiée parmi les vecteurs tant que le vérificateur Go
// indépendant de ct-5 ne la rejoue pas sans écart : la génération par défaut
// garde ses vingt-huit traces. Le sort du jeton de clôture après le refus de
// l'ancre est fixé par la (variante B : il reste
// attente_registre, EX-8.4 règle 2, AN-36, EX-9.7 ; CT-4 EX-8.6), éprouvée par
// test/ancrage-reference-revue.test.js ; ces essais portent sur ce que les
// textes cités fixent par ailleurs.

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

  it("la trace est conforme au schéma planificateur-ancrage-v0 et rejouée sans écart par verifierTrace ; la génération par défaut ne la publie pas (vingt-huit traces), l'option avecEmpreinteSquattee l'écrit en vingt-neuvième, aux mêmes octets", function () {
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
    const avec = path.join(sortie, "avec");
    genererCt5({ racine: defaut });
    genererCt5({ racine: avec, avecEmpreinteSquattee: true });
    const fichiers = (rep) => fs.readdirSync(path.join(rep, "planification")).sort();
    expect(fichiers(defaut)).to.have.length(28).and.to.not.include("empreinte-squattee.json");
    expect(fichiers(avec)).to.deep.equal([...fichiers(defaut), "empreinte-squattee.json"].sort());
    expect(fs.readFileSync(path.join(avec, "planification", "empreinte-squattee.json"), "utf8")).to.equal(JSON.stringify(trace, null, 2) + "\n");
    for (const f of fichiers(defaut)) expect(fs.readFileSync(path.join(avec, "planification", f)).equals(fs.readFileSync(path.join(defaut, "planification", f))), f).to.equal(true);
    expect(fs.readFileSync(path.join(avec, "INDEX.md"), "utf8")).to.match(/^\| `empreinte-squattee\.json` \| \d+ \| \d+ \| 0 \| 5 \| /m);
    expect(fs.readFileSync(path.join(defaut, "INDEX.md"), "utf8")).to.not.include("empreinte-squattee");
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

  it("les autres ancres ne sont pas touchées par le refus : preuve OpenTimestamps de la période en attente, ancre et jeton du point de clôture obtenus ; cinq demandes dans la file", function () {
    expect(demande("ots_periode").state).to.equal("en_attente");
    expect(demande("ancre_registre_point").state).to.equal("obtenue");
    expect(demande("jeton_point").state).to.equal("obtenue");
    expect(trace.queue_after).to.have.length(5);
  });
});
