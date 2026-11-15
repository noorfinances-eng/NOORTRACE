// Revue de sécurité interne de l'étape 8 : correction de la bibliothèque
// de référence de CT-2 scripts/lib/worm.mjs, d'après le texte de CT-2 seul.
//
//   (part référence)  règle de garde EX-12.38 : un `kind` au nom d'une
//   propriété d'Object.prototype n'est pas une succession admise ; la garde
//   rend ordre_invalide (et premier_non_pose au rang 1), jamais une TypeError.
import { expect } from "chai";
import * as W from "../scripts/lib/worm.mjs";

const BASE = { version: 0, gel_id: "gel-20261110T110005Z-0a0b0c0d", org_id: "0x" + "11".repeat(32), journal_id: "0x" + "33".repeat(32), periods: { from: 0, to: 3600 }, support: { type: "s3-object-lock", bucket: "b", prefix: "p/" }, objects: { key: "p/gels/gel-20261110T110005Z-0a0b0c0d/objets-0001.ndjson", count: 1, sha256: "0x" + "22".repeat(32) }, reason: null, reference: null, results: null, anomalies: [] };
/** Chaîne une suite (n, prev_sha256) à partir des seuls kind, actor, at. */
function suite(liste) {
  const out = [];
  let prev = null;
  liste.forEach((x, i) => {
    const r = { ...BASE, n: i + 1, prev_sha256: prev, request_sha256: null, ...x };
    out.push(r);
    prev = W.empreinteEnregistrement(r);
  });
  return out;
}
const PROTOTYPAUX = ["constructor", "toString", "valueOf", "hasOwnProperty", "__proto__", "__defineGetter__"];
/** La garde, ou l'exception qu'elle lève, comme valeur : les oracles comparent des valeurs. */
const garde = (records) => {
  try {
    return W.verifierGarde(records);
  } catch (e) {
    return { exception: `${e.constructor.name}: ${e.message}` };
  }
};

describe("revue de sécurité de l'étape 8 : worm.mjs, règle de garde EX-12.38", function () {
  it("CT-2 EX-12.38 : un kind prototypal au rang 1 suivi d'un pose_resultat : premier_non_pose au rang 1 et ordre_invalide au rang 2, comme pour tout kind inconnu, sans exception", function () {
    const attendu = garde(suite([{ kind: "autre", actor: "a", at: "2026-11-10T11:00:00.000Z" }, { kind: "pose_resultat", actor: "a", at: "2026-11-10T11:00:01.000Z" }])).errors;
    expect(attendu).to.deep.equal([{ n: 1, code: "premier_non_pose" }, { n: 2, code: "ordre_invalide" }]);
    for (const kind of PROTOTYPAUX) {
      const r = garde(suite([{ kind, actor: "a", at: "2026-11-10T11:00:00.000Z" }, { kind: "pose_resultat", actor: "a", at: "2026-11-10T11:00:01.000Z" }]));
      expect([r.exception, r.valid, r.errors, r.record_sha256?.length], kind).to.deep.equal([undefined, false, attendu, 2]);
    }
  });

  it("CT-2 EX-12.38 : un kind prototypal au milieu d'une suite valide : ordre_invalide à son rang et au rang suivant, les autres règles inchangées", function () {
    const valide = [{ kind: "pose", actor: "a", at: "2026-11-10T11:00:00.000Z" }, { kind: "pose_resultat", actor: "a", at: "2026-11-10T11:00:01.000Z", results: { ok: 1, failed: [] } }, { kind: "demande_levee", actor: "a", at: "2026-11-11T11:00:00.000Z" }];
    expect(W.verifierGarde(suite(valide)).valid).to.equal(true);
    for (const kind of PROTOTYPAUX) {
      const r = garde(suite([valide[0], { kind, actor: "a", at: "2026-11-10T11:00:00.500Z" }, valide[1], valide[2]]));
      expect([r.exception, r.errors], kind).to.deep.equal([undefined, [{ n: 2, code: "ordre_invalide" }, { n: 3, code: "ordre_invalide" }]]);
    }
  });

  it("CT-2 EX-12.38 : une suite dont les enregistrements n'ont ni at, ni n, ni prev_sha256 et un kind prototypal rend des erreurs au rang fautif, jamais une exception", function () {
    for (const kinds of [["toString", "pose"], ["constructor"], ["pose", "__proto__"]]) {
      const r = garde(kinds.map((kind) => ({ ...BASE, kind })));
      expect([r.exception, r.valid], kinds.join()).to.deep.equal([undefined, false]);
      expect(r.errors.every((e) => W.CODES_GARDE.includes(e.code) && Number.isInteger(e.n) && e.n >= 1 && e.n <= kinds.length), kinds.join()).to.equal(true);
    }
  });
});
