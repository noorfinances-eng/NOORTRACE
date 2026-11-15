import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";
import * as S from "../scripts/lib/securite.mjs";
import * as K from "../scripts/vecteurs/ct7/ceremonies.mjs";

// CT-7 EX-5.11 (menace MN-93, risque accepté RA-77) : en production, D_C DOIT
// être ancré, par un jeton RFC 3161 sur D_C conservé avec le procès-verbal,
// hors de son condensé, ou par sa transmission au registre. Aucune CR- ne lit
// cette ancre : le vérificateur ne reçoit que le procès-verbal, dont la date
// n'est alors que déclarée. La bibliothèque de référence
// (scripts/lib/securite.mjs, verifierCeremonie) et la commande
// scripts/verify/ceremonie.mjs le disent au réviseur par la réserve
// « date_declaree_seulement », sans changer le verdict, le code de retour ni
// la forme de attendu.json.
//
// Les procès-verbaux viennent du générateur des vecteurs de CT-7
// (scripts/vecteurs/ct7/ceremonies.mjs), dont le cas
// « valide-production-sans-ancre » est celui de la menace MN-93.

const CLI = path.join(PROJECT_ROOT, "scripts", "verify", "ceremonie.mjs");
const CAS = K.casCeremonies();
const cas = (nom) => CAS.find((c) => c.nom === nom);
const RESERVE = "date_declaree_seulement";

describe("CT-7 EX-5.11 : réserve « daté par déclaration seulement » d'un procès-verbal de production (verifierCeremonie, scripts/verify/ceremonie.mjs)", function () {
  this.timeout(120_000);
  let dossier;
  before(function () {
    dossier = fs.mkdtempSync(path.join(process.env.NOORTRACE_TMP ?? os.tmpdir(), "ct7-reserve-"));
  });
  after(function () {
    fs.rmSync(dossier, { recursive: true, force: true });
  });
  const fichier = (c) => {
    const f = path.join(dossier, `${c.nom}.json`);
    fs.writeFileSync(f, c.octets);
    return f;
  };

  it("valide-production-sans-ancre : les douze CR- réussissent, le verdict est valide, et le rapport porte la réserve date_declaree_seulement ; attendu.json garde ses cinq membres", function () {
    const c = cas("valide-production-sans-ancre");
    expect(c, "cas du générateur").to.not.equal(undefined);
    expect(JSON.parse(c.octets).environment).to.equal("production");
    const r = S.verifierCeremonie(c.octets);
    expect(r.statuses.map((s) => s.status)).to.deep.equal(Array(12).fill("reussi"));
    expect([r.verdict, r.failed, r.not_executed]).to.deep.equal(["valide", [], []]);
    expect(S.RESERVE_DATE_DECLAREE).to.equal(RESERVE);
    expect(r.reserves).to.deep.equal([RESERVE]);
    const attendu = S.attenduCeremonie(r);
    expect(Object.keys(attendu)).to.deep.equal(["verdict", "digest", "failed", "not_executed", "signers"]);
    expect(J.validerSchema(attendu, S.schemaCeremonie(), { fragment: "#/$defs/attendu" })).to.deep.equal([]);
  });

  it("la réserve suit l'environnement et lui seul : présente pour chaque procès-verbal de production lu, quel que soit le verdict, qu'elle ne change pas ; absente en développement et quand CR-1 échoue", function () {
    let production = 0;
    for (const c of CAS) {
      const r = S.verifierCeremonie(c.octets);
      expect(r.failed, c.nom).to.deep.equal(c.echecs);
      expect(r.verdict, c.nom).to.equal(c.echecs.length ? "invalide" : "valide");
      if (c.echecs.includes("CR-1")) {
        expect(r.reserves, c.nom).to.deep.equal([]);
        continue;
      }
      const env = JSON.parse(c.octets).environment;
      expect(r.reserves, c.nom).to.deep.equal(env === "production" ? [RESERVE] : []);
      expect(r.reserves, c.nom).to.deep.equal(c.reserves);
      if (env === "production") production++;
    }
    expect(production).to.be.above(30);
    expect(S.verifierCeremonie(cas("valide-developpement-classe-d").octets).reserves).to.deep.equal([]);
    expect(S.verifierCeremonie(cas("invalide-cr6-classe-d-en-production").octets)).to.include({ verdict: "invalide" }).and.to.deep.include({ reserves: [RESERVE] });
    // Le même procès-verbal, en préproduction : aucune réserve (EX-5.11 n'exige l'ancre qu'en production).
    const pv = JSON.parse(cas("valide-production-sans-ancre").octets);
    delete pv.signatures;
    pv.environment = "preproduction";
    const signe = S.signerCeremonie(pv, Object.fromEntries(Object.entries({ p1: 1, p2: 2, p3: 4 }).map(([p, i]) => [p, K.COMPTES[i].cle])));
    const r = S.verifierCeremonie(J.texteJSON(signe));
    expect([r.verdict, r.reserves]).to.deep.equal(["valide", []]);
  });

  it("commande de référence : --json rend reserves en plus de la forme de attendu.json et de statuses ; la sortie lisible imprime la phrase de la réserve après la phrase fixe de §5.8 ; code 0 inchangé", function () {
    const c = cas("valide-production-sans-ancre");
    const f = fichier(c);
    const j = spawnSync(process.execPath, [CLI, f, "--json"], { encoding: "utf8" });
    expect(j.status).to.equal(0);
    const rapport = JSON.parse(j.stdout);
    expect(Object.keys(rapport)).to.deep.equal(["verdict", "digest", "failed", "not_executed", "signers", "statuses", "reserves"]);
    expect(rapport.reserves).to.deep.equal([RESERVE]);
    const lisible = spawnSync(process.execPath, [CLI, f], { encoding: "utf8" });
    expect(lisible.status).to.equal(0);
    const lignes = lisible.stdout.trimEnd().split("\n");
    expect(lignes.at(-2)).to.equal(S.phraseCeremonie(JSON.parse(c.octets), S.verifierCeremonie(c.octets)));
    expect(lignes.at(-1)).to.equal(S.PHRASES_RESERVES_CEREMONIE[RESERVE]);
    expect(lignes.at(-1)).to.match(/^Réserve : procès-verbal de production daté par déclaration seulement\. .*CT-7 EX-5\.11, RA-77\)\.$/);
    expect(lisible.stdout.match(/^Réserve : /gm)).to.have.length(1);
  });

  it("commande de référence : aucune réserve imprimée en développement ni quand CR-1 échoue ; un procès-verbal de production invalide garde le code 1 et porte la réserve ; --condense n'imprime que D_C", function () {
    const dev = spawnSync(process.execPath, [CLI, fichier(cas("valide-developpement-classe-d"))], { encoding: "utf8" });
    expect([dev.status, /Réserve/.test(dev.stdout)]).to.deep.equal([0, false]);
    const cr1 = spawnSync(process.execPath, [CLI, fichier(cas("invalide-cr1-schema")), "--json"], { encoding: "utf8" });
    expect([cr1.status, JSON.parse(cr1.stdout).reserves]).to.deep.equal([1, []]);
    const invalide = spawnSync(process.execPath, [CLI, fichier(cas("invalide-cr9-sans-video-ni-auditeur"))], { encoding: "utf8" });
    expect(invalide.status).to.equal(1);
    expect(invalide.stdout).to.match(/^Verdict : invalide$/m).and.to.include(S.PHRASES_RESERVES_CEREMONIE[RESERVE]);
    const condense = spawnSync(process.execPath, [CLI, fichier(cas("valide-production-sans-ancre")), "--condense"], { encoding: "utf8" });
    expect(condense.status).to.equal(0);
    expect(condense.stdout).to.match(/^0x[0-9a-f]{64}\n$/);
  });
});
