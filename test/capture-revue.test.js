// Revue de sécurité interne de l'étape 8 : corrections de la bibliothèque
// de référence de CT-2 scripts/lib/capture.mjs, d'après le texte de CT-2 seul.
//
//    contrôle EX-4.44 des nombres en temps linéaire (retrait des zéros de queue sans /0+$/)
//              EX-10.9 : la fin d'une correspondance remplacée vaut début de chaîne pour le candidat
//                      qui suit, pour les ancres ^, \b et \B des motifs nommés comme pour les détecteurs nommés
//              analyseur SSE : aucun étalement d'arguments, 400 000 événements dans un fragment
//              EX-10.14 : le nombre de passages n'est borné que par la finitude (et EX-10.23), jamais par 64
//
// Chaque essai échoue sur le code d'avant la correction et passe
// après ; les mutants (règle retirée) sont rejoués
// hors du dépôt.
import { expect } from "chai";
import * as C from "../scripts/lib/capture.mjs";

const POLITIQUE = (named_patterns, detectors) => ({
  version: 0,
  name: "revue-l2",
  pseudonym_key: null,
  named_patterns,
  rules: [{ id: "r1", scopes: ["arguments"], tools: "*", detectors, action: { kind: "remplacer" } }],
});
/** Résultat d'une opération, ou l'exception qu'elle lève, comme valeur : les oracles ci-dessous comparent des valeurs, jamais un « ne lève pas ». */
const tenter = (f) => {
  try {
    return f();
  } catch (e) {
    return { exception: `${e.constructor.name}: ${e.message}` };
  }
};
const rediger = (named_patterns, detectors, s) =>
  tenter(() => {
    const politique = C.chargerPolitique(POLITIQUE(named_patterns, detectors));
    const r = C.rediger(politique, { v: s }, { portee: "arguments", outil: "a__b" });
    return { valeur: r.valeur.v, correspondances: r.correspondances.map((c) => [c.detector, c.count]), depasse: r.depasse };
  });

describe("revue de sécurité de l'étape 8 : capture.mjs, contrôle EX-4.44 des nombres", function () {
  this.timeout(60000);

  it("CT-2 EX-4.44 : lireRequeteHote refuse nombre_non_representable un argument 1.0…01 de 100 000 zéros en moins d'une seconde (seuil écrit : 1 000 ms ; avant la correction : plusieurs secondes, quadratique)", function () {
    const nombre = "1." + "0".repeat(100000) + "1";
    const requete = `{"jsonrpc":"2.0","id":"appel-01","method":"tools/call","params":{"name":"demo__claims.get","arguments":{"x":${nombre}}}}`;
    const debut = process.hrtime.bigint();
    const r = C.lireRequeteHote(requete);
    const ms = Number(process.hrtime.bigint() - debut) / 1e6;
    expect(r.erreur).to.deep.equal({ code: -32602, message: "Invalid params", data: { reason: "nombre_non_representable" } });
    expect(r.id).to.equal("appel-01");
    expect(ms, `durée ${ms.toFixed(0)} ms`).to.be.below(1000);
  });

  it("CT-2 EX-4.44 : nombreExact garde ses verdicts (0.75, 1.0, 1e3, 1.000 admis ; 12345678901234567890, 0.10000000000000000001, 1e400 refusés) et reste linéaire sur 1 suivi de 200 000 zéros", function () {
    for (const t of ["0.75", "1.0", "1e3", "1.000", "100", "-0.0", "0", "1e-7", "0.000001"]) expect(C.nombreExact(t), t).to.equal(true);
    for (const t of ["12345678901234567890", "0.10000000000000000001", "1e400", "1." + "0".repeat(30) + "1"]) expect(C.nombreExact(t), t).to.equal(false);
    const debut = process.hrtime.bigint();
    expect(C.nombreExact("1." + "0".repeat(200000))).to.equal(true);
    expect(C.nombreExact("1." + "0".repeat(200000) + "1")).to.equal(false);
    expect(Number(process.hrtime.bigint() - debut) / 1e6).to.be.below(1000);
  });
});

describe("revue de sécurité de l'étape 8 : capture.mjs, rédaction (CT-2 EX-10.9, CT-2 EX-10.14)", function () {
  this.timeout(60000);

  it("après une correspondance remplacée, \\B ne tient plus (frontière du jeton, EX-10.9) : \\Bz sur « zzz » rédige la seule lettre du milieu", function () {
    expect(rediger({ ref: { pattern: "\\Bz" } }, [{ type: "regex", name: "ref" }], "zzz")).to.deep.equal({ valeur: "z[REDIGE:ref]z", correspondances: [["regex", 1]], depasse: false });
    expect(rediger({ ref: { pattern: "\\Bz" } }, [{ type: "regex", name: "ref" }], "zzzz zz")).to.deep.equal({ valeur: "z[REDIGE:ref]z[REDIGE:ref] z[REDIGE:ref]", correspondances: [["regex", 3]], depasse: false });
  });

  it("CT-2 EX-10.9 : une alternative ancrée (x|\\b#) sur « x# » : # suit le jeton, \\b n'y tient pas, une seule correspondance", function () {
    expect(rediger({ ref: { pattern: "x|\\b#" } }, [{ type: "regex", name: "ref" }], "x#")).to.deep.equal({ valeur: "[REDIGE:ref]#", correspondances: [["regex", 1]], depasse: false });
  });

  it("CT-2 EX-10.9 : ^ et \\b tiennent après une correspondance remplacée (début de chaîne) : ^[0-9]{3} et \\b[A-Z]{2}[0-9]{4} rédigent tous les candidats adjacents en un passage, résultat idempotent (EX-10.15)", function () {
    expect(rediger({ ref: { pattern: "^[0-9]{3}" } }, [{ type: "regex", name: "ref" }], "123".repeat(3))).to.deep.equal({ valeur: "[REDIGE:ref]".repeat(3), correspondances: [["regex", 3]], depasse: false });
    const r = rediger({ ref: { pattern: "\\b[A-Z]{2}[0-9]{4}" } }, [{ type: "regex", name: "ref" }], "AB1234".repeat(70) + " fin");
    expect(r).to.deep.equal({ valeur: "[REDIGE:ref]".repeat(70) + " fin", correspondances: [["regex", 70]], depasse: false });
    expect(rediger({ ref: { pattern: "\\b[A-Z]{2}[0-9]{4}" } }, [{ type: "regex", name: "ref" }], r.valeur)).to.deep.equal({ valeur: r.valeur, correspondances: [], depasse: false });
  });

  it("CT-2 EX-10.9 : correspondances() suit la même règle (chaque recherche voit le reste comme une chaîne)", function () {
    expect(C.correspondances("regex", "zzz", "\\Bz")).to.deep.equal([{ debut: 1, fin: 2, valeur: "z" }]);
    expect(C.correspondances("regex", "x#", "x|\\b#")).to.deep.equal([{ debut: 0, fin: 1, valeur: "x" }]);
    expect(C.correspondances("telephone", "+41441234567+41441234567").map((m) => [m.debut, m.fin])).to.deep.equal([[0, 12], [12, 24]]);
  });

  it("une cascade de 65 passages (A\\b puis B$ sur 65 A suivis de B) est rédigée entière, sans erreur ni dépassement (EX-10.14 : nombre de passages fini, aucune borne à 64)", function () {
    const r = rediger({ a: { pattern: "A\\b" }, b: { pattern: "B$" } }, [{ type: "regex", name: "a" }, { type: "regex", name: "b" }], "A".repeat(65) + "B");
    expect(r).to.deep.equal({ valeur: "[REDIGE:a]".repeat(65) + "[REDIGE:b]", correspondances: [["regex", 1], ["regex", 65]], depasse: false });
  });

  it("CT-2 EX-10.14 : la même cascade sur une pièce texte (racine chaîne, redigerChaineParDetecteurs) passe aussi", function () {
    const politique = C.chargerPolitique({ ...POLITIQUE({ a: { pattern: "A\\b" }, b: { pattern: "B$" } }, [{ type: "regex", name: "a" }, { type: "regex", name: "b" }]), rules: [{ id: "r1", scopes: ["prompt_systeme"], tools: "*", detectors: [{ type: "regex", name: "a" }, { type: "regex", name: "b" }], action: { kind: "remplacer" } }] });
    const p = tenter(() => C.pieceTexte("A".repeat(65) + "B", { politique, portee: "prompt_systeme" }));
    expect(p.exception).to.equal(undefined);
    expect([p.octets.toString("utf8"), p.reference.redacted]).to.deep.equal(["[REDIGE:a]".repeat(65) + "[REDIGE:b]", true]);
  });
});

describe("revue de sécurité de l'étape 8 : capture.mjs, analyseur SSE", function () {
  this.timeout(60000);

  it("analyserSSE rend 400 000 événements d'un seul fragment, et consoliderFlux les compte (avant : RangeError dès 150 000)", function () {
    const octets = Buffer.from("data:x\n\n".repeat(400000));
    const r = tenter(() => C.analyserSSE(octets));
    expect([r.exception, r.evenements?.length, r.evenements?.[399999]]).to.deep.equal([undefined, 400000, { type: "message", data: "x" }]);
    expect(tenter(() => C.consoliderFlux("anthropic-messages", octets).evenements)).to.equal(400000);
  });
});
