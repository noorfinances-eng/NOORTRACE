// Enregistreur + ancrage, lot H1 : non-régression de la correction R-G-1 de la
// relecture adversariale de l'étape 5. La copie WORM d'`acquisitions.ndjson`
// (ajout seul, CT-5 EX-5.15, EX-8.14 ; CT-2 EX-12.16, lecture 93 : un fichier
// modifié après sa copie n'est pas recopié) n'a lieu qu'une fois le fichier
// fermé : période close, jeton de clôture obtenu et promu (enregistrement
// `obtenue` `promoted` non révoqué d'objet `manifeste`, EX-4.5), T-10
// différée décidée pour chaque jeton promu quand la capture des CRL est
// activée ; après une révocation, la nouvelle promotion est attendue. Aucun
// réseau ; tout fichier va sous `os.tmpdir()`.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ServiceCopiesWorm } from "@noortrace/enregistreur";

const PERIODE = "1793710800";
const REPERTOIRES = [];

function journalFactice(crlEnabled) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-h1-copies-"));
  REPERTOIRES.push(dir);
  for (const d of ["manifestes", "segments", "points", `ancres/periode-${PERIODE}/rfc3161`, `ancres/periode-${PERIODE}/ots`]) fs.mkdirSync(path.join(dir, d), { recursive: true });
  const service = new ServiceCopiesWorm({ worm: { prefix: "p/", type: "s3-object-lock", mode: "compliance", retain_days: 3650 }, operations: {} });
  service.lier({
    repertoire: dir, journal: null, metriques: null, horlogeBrute: { murale: () => 0 },
    ecrivain: { epoque: 1, segment: null },
    o: { ancrage: { configuration: { rfc3161: { crl_capture: { enabled: crlEnabled } } } } },
  });
  const acquisitions = path.join(dir, "ancres", `periode-${PERIODE}`, "acquisitions.ndjson");
  return {
    dir,
    service,
    clore: () => {
      fs.writeFileSync(path.join(dir, "manifestes", `periode-${PERIODE}.json`), "{}\n");
      fs.writeFileSync(path.join(dir, "manifestes", `periode-${PERIODE}.sig`), "{}\n");
    },
    ecrire: (lignes, { tronquee = false } = {}) => fs.writeFileSync(acquisitions, lignes.map((l) => JSON.stringify(l)).join("\n") + (tronquee ? "\n{\"a\":" : "\n")),
    copiee: async () => (await service.fichiersACopier()).some((f) => f.cle === `p/ancres/periode-${PERIODE}/acquisitions.ndjson`),
  };
}

const point = (n, t10, extra = {}) => ({ attempt_id: `jeton_point:abcd:${n}`, object: "point", outcome: "obtenue", promoted: true, revoked: false, checks: { "T-10": t10 }, ...extra });
const manifeste = (n, outcome, t10, extra = {}) => ({ attempt_id: `jeton_periode:ef01:${n}`, object: "manifeste", outcome, promoted: outcome === "obtenue", revoked: false, checks: { "T-10": t10 }, ...extra });

describe("enregistreur + ancrage, lot H1 — R-G-1 : acquisitions.ndjson n'est copié vers le WORM qu'après la promotion du jeton de clôture de la période (EX-4.5, EX-5.15, EX-8.14)", function () {
  after(function () {
    for (const d of REPERTOIRES) fs.rmSync(d, { recursive: true, force: true });
  });

  it("période close, jeton de point promu avec T-10 décidée, jeton de période encore en échec transitoire : pas copié ; une fois le jeton de période obtenu et sa T-10 décidée : copié", async function () {
    const j = journalFactice(true);
    j.clore();
    j.ecrire([point(1, "reussi"), manifeste(1, "echec_transitoire", "non_execute")]);
    expect(await j.copiee()).to.equal(false, "le jeton de clôture n'est pas obtenu : sa ligne vient après");
    j.ecrire([point(1, "reussi"), manifeste(1, "echec_transitoire", "non_execute"), manifeste(2, "obtenue", "non_execute")]);
    expect(await j.copiee()).to.equal(false, "la T-10 différée du jeton de période n'est pas décidée");
    j.ecrire([point(1, "reussi"), manifeste(1, "echec_transitoire", "non_execute"), manifeste(2, "obtenue", "non_execute"), manifeste(2, "obtenue", "reussi")]);
    expect(await j.copiee()).to.equal(true);
  });

  it("période non close : jamais copié, même avec un jeton de période promu ; fichier à dernière ligne tronquée : pas copié ; ligne illisible : pas copié", async function () {
    const j = journalFactice(false);
    j.ecrire([manifeste(1, "obtenue", "non_execute")]);
    expect(await j.copiee()).to.equal(false);
    j.clore();
    expect(await j.copiee()).to.equal(true);
    j.ecrire([manifeste(1, "obtenue", "non_execute")], { tronquee: true });
    expect(await j.copiee()).to.equal(false, "une écriture est en cours");
    fs.writeFileSync(path.join(j.dir, "ancres", `periode-${PERIODE}`, "acquisitions.ndjson"), `${JSON.stringify(manifeste(1, "obtenue", "non_execute"))}\nnull\n`);
    expect(await j.copiee()).to.equal(false);
  });

  it("capture des CRL désactivée : copié dès que le manifeste existe et que le jeton de période est promu, sans attendre T-10", async function () {
    const j = journalFactice(false);
    j.clore();
    j.ecrire([point(1, "non_execute"), manifeste(1, "echec_transitoire", "non_execute")]);
    expect(await j.copiee()).to.equal(false);
    j.ecrire([point(1, "non_execute"), manifeste(1, "echec_transitoire", "non_execute"), manifeste(2, "obtenue", "non_execute")]);
    expect(await j.copiee()).to.equal(true);
  });

  it("après une révocation (T-10 échoue, revoked, relève), la nouvelle promotion est attendue, puis sa T-10 ; sans configuration d'ancrage lisible, la capture des CRL est tenue pour activée", async function () {
    const j = journalFactice(true);
    j.clore();
    const avant = [point(1, "reussi"), manifeste(1, "obtenue", "non_execute")];
    j.ecrire([...avant, manifeste(1, "obtenue", "echoue", { revoked: true })]);
    expect(await j.copiee()).to.equal(false, "le jeton promu est révoqué : un nouveau jeton est attendu");
    j.ecrire([...avant, manifeste(1, "obtenue", "echoue", { revoked: true }), manifeste(2, "obtenue", "non_execute")]);
    expect(await j.copiee()).to.equal(false, "T-10 du nouveau jeton promu non décidée");
    j.ecrire([...avant, manifeste(1, "obtenue", "echoue", { revoked: true }), manifeste(2, "obtenue", "non_execute"), manifeste(2, "obtenue", "reussi")]);
    expect(await j.copiee()).to.equal(true);
    // Sans configuration (`o.ancrage` absent) : prudence, T-10 exigée.
    const j2 = journalFactice(true);
    j2.service.coeur.o = {};
    j2.clore();
    j2.ecrire([manifeste(1, "obtenue", "non_execute")]);
    expect(await j2.copiee()).to.equal(false);
    j2.ecrire([manifeste(1, "obtenue", "non_execute"), manifeste(1, "obtenue", "reussi")]);
    expect(await j2.copiee()).to.equal(true);
  });

  it("les autres fichiers d'ancres/ (pièces en création exclusive) sont copiés sans condition ; la file d'une époque antérieure aussi", async function () {
    const j = journalFactice(true);
    fs.writeFileSync(path.join(j.dir, "ancres", `periode-${PERIODE}`, "rfc3161", "manifeste-qtsa-principal-jeton_periode:0000:1.tsq"), "x");
    fs.mkdirSync(path.join(j.dir, "ancres", "file"), { recursive: true });
    fs.writeFileSync(path.join(j.dir, "ancres", "file", "file-0.ndjson"), "");
    fs.writeFileSync(path.join(j.dir, "ancres", "file", "file-1.ndjson"), "");
    j.ecrire([manifeste(1, "echec_transitoire", "non_execute")]);
    const cles = (await j.service.fichiersACopier()).map((f) => f.cle);
    expect(cles).to.include(`p/ancres/periode-${PERIODE}/rfc3161/manifeste-qtsa-principal-jeton_periode:0000:1.tsq`);
    expect(cles).to.include("p/ancres/file/file-0.ndjson");
    expect(cles).to.not.include("p/ancres/file/file-1.ndjson");
    expect(cles).to.not.include(`p/ancres/periode-${PERIODE}/acquisitions.ndjson`);
  });
});
