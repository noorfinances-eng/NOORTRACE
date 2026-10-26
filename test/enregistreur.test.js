import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { Wallet } from "ethers";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";
import * as C from "../scripts/lib/capture.mjs";
import * as AP from "../scripts/lib/approbation.mjs";

// L'IMPLÉMENTATION DE RÉFÉRENCE DE CT-2 (scripts/lib/capture.mjs, et
// canonicaliserJCSIntegral de scripts/lib/journal.mjs) : JCS intégral des
// pièces (RFC 8785), détecteurs et politique de rédaction, pièces d'un
// tools/call relayé, agrégation de tools/list, analyseur SSE et formes
// consolidées des trois formats de modèle, extraction, corrélation,
// construction et scellement des événements CT-1, segments, journal
// d'intention et reprise. Les valeurs attendues viennent de la RFC 8785
// (annexe B, exemples des sections 3.2.2 à 3.2.4), de la spécification
// (sections 8.1, 10.3, 10.6, 10.9 et annexe A, lues dans
// spec/CT-2-enregistreur.md) et des vecteurs de spec/vecteurs/ct-2, rejoués
// un par un. La génération déterministe et le vérificateur de dossier sont
// testés en bout de chaîne.

const SPEC = path.join(PROJECT_ROOT, "spec");
const VECTEURS = path.join(SPEC, "vecteurs", "ct-2");
const SCHEMAS = J.registreSchemas(["evenement", "manifeste", "dossier", "politique-redaction", "politique-approbation", "ticket", "configuration-enregistreur", "worm", "cout-agent"].map((n) => JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", `${n}-v0.schema.json`), "utf8"))));
const lireJSON = (...p) => C.analyserJSONIntegral(fs.readFileSync(path.join(VECTEURS, ...p)));
const lireTexte = (...p) => fs.readFileSync(path.join(VECTEURS, ...p), "utf8");
const graine = (id) => J.sha256(Buffer.from(`noortrace/vecteurs/v0/cle-enregistreur/${id}`, "utf8"));
const CLE_01 = J.cleEd25519DepuisGraine(graine("rec-test-01"));
const CLE_PSEUDO = Buffer.from(J.sha256(Buffer.from("noortrace/vecteurs/v0/cle-pseudonyme/test", "utf8")).slice(2), "hex");
const HARDHAT = {
  1: new Wallet("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"),
  2: new Wallet("0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"),
};

/** Les blocs JSON annotés `<!-- schema: … -->` d'une spécification, texte exact. */
function blocs(fichier, marque) {
  const md = fs.readFileSync(path.join(SPEC, fichier), "utf8");
  const re = new RegExp(`<!-- schema: ${marque} -->\\n\`\`\`json\\n([\\s\\S]*?)\\n\`\`\``, "g");
  const out = [];
  let m;
  while ((m = re.exec(md))) out.push(m[1]);
  return out;
}
/** Le premier bloc ```json qui suit un repère dans une spécification, texte exact. */
function blocsTexte(fichier, repere) {
  const md = fs.readFileSync(path.join(SPEC, fichier), "utf8");
  const i = md.indexOf(repere);
  const j = md.indexOf("```json\n", i) + "```json\n".length;
  return md.slice(j, md.indexOf("\n```", j));
}
const PII_DOC = C.analyserJSONIntegral(blocs("CT-2-enregistreur.md", "politique-redaction")[0]);
const CONFIG = C.analyserJSONIntegral(blocs("CT-2-enregistreur.md", "configuration-enregistreur")[0]);
const PII = C.chargerPolitique(PII_DOC, { schemas: SCHEMAS });

function lancer(script, args) {
  const r = spawnSync(process.execPath, [path.join(PROJECT_ROOT, "scripts", ...script), ...args], { encoding: "utf8", cwd: PROJECT_ROOT });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

/** Générateur pseudo-aléatoire déterministe (xorshift32), pour les découpages de flux. */
function pseudoAleatoire(graineEntiere) {
  let x = graineEntiere >>> 0 || 1;
  return () => {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    return x / 0x100000000;
  };
}

// ---------------------------------------------------------------------------
describe("CT-2 : JCS intégral (RFC 8785, CT-2 §8.1)", function () {
  // RFC 8785, annexe B, table 1 : IEEE 754 (hexadécimal) → représentation JSON.
  const TABLE = [
    ["0000000000000000", "0"],
    ["8000000000000000", "0"],
    ["0000000000000001", "5e-324"],
    ["8000000000000001", "-5e-324"],
    ["7fefffffffffffff", "1.7976931348623157e+308"],
    ["ffefffffffffffff", "-1.7976931348623157e+308"],
    ["4340000000000000", "9007199254740992"],
    ["c340000000000000", "-9007199254740992"],
    ["4430000000000000", "295147905179352830000"],
    ["7fffffffffffffff", null],
    ["7ff0000000000000", null],
    ["44b52d02c7e14af5", "9.999999999999997e+22"],
    ["44b52d02c7e14af6", "1e+23"],
    ["44b52d02c7e14af7", "1.0000000000000001e+23"],
    ["444b1ae4d6e2ef4e", "999999999999999700000"],
    ["444b1ae4d6e2ef4f", "999999999999999900000"],
    ["444b1ae4d6e2ef50", "1e+21"],
    ["3eb0c6f7a0b5ed8c", "9.999999999999997e-7"],
    ["3eb0c6f7a0b5ed8d", "0.000001"],
    ["41b3de4355555553", "333333333.3333332"],
    ["41b3de4355555554", "333333333.33333325"],
    ["41b3de4355555555", "333333333.3333333"],
    ["41b3de4355555556", "333333333.3333334"],
    ["41b3de4355555557", "333333333.33333343"],
    ["becbf647612f3696", "-0.0000033333333333333333"],
    ["43143ff3c1cb0959", "1424953923781206.2"],
  ];

  it("la table des nombres de l'annexe B de la RFC 8785 (section 3.2.2.3) : 24 valeurs finies, NaN et Infinity refusés", function () {
    for (const [hexa, attendu] of TABLE) {
      const v = Buffer.from(hexa, "hex").readDoubleBE(0);
      if (attendu === null) expect(() => J.canonicaliserJCSIntegral(v), hexa).to.throw(J.ErreurFormat);
      else {
        expect(J.canonicaliserJCSIntegral(v), hexa).to.equal(attendu);
        expect(J.canonicaliserJCSIntegral([v]), hexa).to.equal(`[${attendu}]`);
      }
    }
    expect(TABLE.filter(([, a]) => a !== null)).to.have.length(24);
    expect(() => J.canonicaliserJCSIntegral(-Infinity)).to.throw(J.ErreurFormat);
    expect(J.canonicaliserJCSIntegral(-0)).to.equal("0");
  });

  it("l'exemple de la RFC 8785 §3.2.2 donne la forme canonique de §3.2.3 et les octets UTF-8 de §3.2.4", function () {
    const entree = '{\n "numbers": [333333333.33333329, 1E30, 4.50,\n             2e-3, 0.000000000000000000000000001],\n "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",\n "literals": [null, true, false]\n}';
    const canon = C.jcsIntegralDuTexte(entree);
    expect(canon).to.equal('{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}');
    const octets = "7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72 75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a 5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31 65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37 5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30 30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d";
    expect(C.octetsJCSIntegral(C.analyserJSONIntegral(entree)).toString("hex")).to.equal(octets.replace(/ /g, ""));
  });

  it("le tri des membres de la RFC 8785 §3.2.3 : unités de code UTF-16, non points de code", function () {
    const entree = '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}';
    const canon = C.jcsIntegralDuTexte(entree);
    expect([...canon.matchAll(/:"([^"]*)"/g)].map((m) => m[1])).to.deep.equal(["Carriage Return", "One", "Control", "Latin Small Letter O With Diaeresis", "Euro Sign", "Emoji: Grinning Face", "Hebrew Letter Dalet With Dagesh"]);
  });

  it("la table de CT-2 §8.1 : la valeur, pas le texte ; pertes au-delà de la double précision", function () {
    const cas = [
      ["1", "1"], ["1.0", "1"], ["1.50", "1.5"], ["1e3", "1000"], ["1E+2", "100"], ["1e21", "1e+21"], ["1e20", "100000000000000000000"],
      ["-0", "0"], ["-0.0", "0"], ["0.000001", "0.000001"], ["0.0000001", "1e-7"], ["5e-324", "5e-324"],
      ["9007199254740993", "9007199254740992"], ["123456789012345678901234567890", "1.2345678901234568e+29"], ["3.141592653589793238462643383279", "3.141592653589793"],
    ];
    for (const [texte, attendu] of cas) expect(C.jcsIntegralDuTexte(texte), texte).to.equal(attendu);
  });

  it("chaînes et membres comme JCS v0 ; refus des substituts isolés, des clés en double, des textes qui ne sont pas du JSON", function () {
    for (const v of [{ b: 1, a: [true, null, "x\u0001y", "\u007f/ "], é: { z: 2, Z: 3 } }, [0, -0, 9007199254740991, -9007199254740991], "a😀"]) expect(J.canonicaliserJCSIntegral(v)).to.equal(J.canonicaliserJCS(v));
    expect(() => J.canonicaliserJCSIntegral({ a: "\ud800" })).to.throw(J.ErreurFormat);
    expect(() => J.canonicaliserJCSIntegral({ ["\udc00"]: 1 })).to.throw(J.ErreurFormat);
    expect(() => J.canonicaliserJCSIntegral([undefined])).to.throw(J.ErreurFormat);
    expect(() => J.canonicaliserJCSIntegral(10n)).to.throw(J.ErreurFormat);
    for (const t of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"a":"\\ud800"}', "NaN", "Infinity", "1e400", "-1e400", "01", "1.", "+1", ".5", "[1,]"]) expect(() => C.jcsIntegralDuTexte(t), t).to.throw(J.ErreurFormat);
    expect(() => C.analyserJSONIntegral(Buffer.from([0xef, 0xbb, 0xbf, 0x31]))).to.throw(J.ErreurJSON);
    expect(() => C.analyserJSONIntegral(Buffer.from([0x22, 0xff, 0x22]))).to.throw(J.ErreurJSON);
    const v = C.analyserJSONIntegral('{"__proto__":{"x":1}}');
    expect(Object.keys(v)).to.deep.equal(["__proto__"]);
    expect(J.canonicaliserJCSIntegral(v)).to.equal('{"__proto__":{"x":1}}');
  });

  it("l'analyse relève l'étendue de chaque valeur dans le texte reçu (relais sans resérialisation, EX-4.20)", function () {
    const texte = '{"params": {"arguments" : {"x":1.0, "y":"é"} , "name":"t"}}';
    const { valeur, positions } = C.analyserJSONIntegral(texte, { positions: true });
    const e = positions.get("/params/arguments");
    expect(texte.slice(e.debut, e.fin)).to.equal('{"x":1.0, "y":"é"}');
    expect(valeur.params.arguments).to.deep.equal({ x: 1, y: "é" });
    expect(positions.get("")).to.deep.equal({ debut: 0, fin: texte.length });
  });
});

// ---------------------------------------------------------------------------
describe("CT-2 : détecteurs exacts (§10.3)", function () {
  const trouve = (type, s) => C.correspondances(type, s).map((m) => s.slice(m.debut, m.fin));
  const valeurs = (type, s) => C.correspondances(type, s).map((m) => m.valeur);

  it("IBAN : MOD 97-10 par blocs de neuf chiffres, onze pays, formes compacte et groupée, refus des sommes fausses", function () {
    expect(C.resteIban("CH9300762011623852957")).to.equal(1);
    expect(C.resteIban("CH9300762011623852958")).to.equal(28);
    expect(C.resteIban("GB19LOYD30961700709943")).to.equal(1);
    for (const [CC, L] of Object.entries(C.LONGUEURS_IBAN)) {
      const bban = "1".repeat(L - 4);
      const iban = `${CC}${C.cleIban(CC, bban)}${bban}`;
      expect(C.resteIban(iban), CC).to.equal(1);
      expect(valeurs("iban", `x ${iban} y`), CC).to.deep.equal([iban]);
      expect(valeurs("iban", `x ${iban.match(/.{1,4}/g).join(" ")} y`), CC).to.deep.equal([iban]);
      expect(valeurs("iban", `x ${iban.slice(0, -1)} y`), `${CC} tronqué`).to.deep.equal([]);
    }
    expect(trouve("iban", "IBAN CH93 0076 2011 6238 5295 7, merci")).to.deep.equal(["CH93 0076 2011 6238 5295 7"]);
    expect(trouve("iban", "CH93 0076 2011 6238 5295 7")).to.have.length(1);
    for (const s of ["CH9300762011623852958", "ch9300762011623852957", "XCH9300762011623852957", "CH93007620116238529570", "CH93  0076 2011 6238 5295 7", "CH 9300762011623852957", "NO9386011117947"]) expect(trouve("iban", s), s).to.deep.equal([]);
  });

  it("AVS : clé de l'ordonnance du DFI, séparateurs identiques ou absents", function () {
    expect(C.cleAvs("756123456789")).to.equal(7);
    for (const s of ["756.1234.5678.97", "7561234567897", "756 1234 5678 97", "756.12345678.97", "756 1234 5678 97"]) expect(valeurs("avs", `n° ${s}.`), s).to.deep.equal(["7561234567897"]);
    for (const s of ["756.1234.5678.90", "756.1234 5678.97", "756..1234.5678.97", "1756.1234.5678.97", "756.1234.5678.971", "757.1234.5678.97"]) expect(trouve("avs", s), s).to.deep.equal([]);
  });

  it("carte : 12 à 19 chiffres passant Luhn, espaces et traits d'union isolés, jamais de point", function () {
    expect(C.luhnValide("378282246310005")).to.equal(true);
    expect(C.luhnValide("378282246310006")).to.equal(false);
    for (const s of ["378282246310005", "3782 822463 10005", "3782-822463-10005"]) expect(valeurs("carte", `carte ${s}.`), s).to.deep.equal(["378282246310005"]);
    const n12 = "12345678901" + C.chiffreLuhn("12345678901");
    const n19 = "123456789012345678" + C.chiffreLuhn("123456789012345678");
    const n11 = "1234567890" + C.chiffreLuhn("1234567890");
    const n20 = "1234567890123456789" + C.chiffreLuhn("1234567890123456789");
    expect(valeurs("carte", n12)).to.deep.equal([n12]);
    expect(valeurs("carte", n19)).to.deep.equal([n19]);
    for (const s of [n11, n20, "3782.822463.10005", "AB378282246310005", "378282246310005X", "3782  822463 10005", "378282246310006"]) expect(trouve("carte", s), s).to.deep.equal([]);
  });

  it("adresse électronique : Dot-string@Domain, partie locale de 64 octets au plus, frontières", function () {
    expect(trouve("email", "Écrire à j.dupont@example.ch ; merci")).to.deep.equal(["j.dupont@example.ch"]);
    expect(valeurs("email", "a J.Dupont@Example.CH b")).to.deep.equal(["J.Dupont@example.ch"]);
    const l64 = "a".repeat(64);
    expect(valeurs("email", `${l64}@example.ch`)).to.have.length(1);
    expect(valeurs("email", `${l64}a@example.ch`)).to.deep.equal([]);
    for (const s of ["x@exemple.c", "x@exemple", "x@exemple.c1", ".j@example.ch", "j@-example.ch", "a..b@example.ch", "j.@example.ch"]) expect(valeurs("email", s), s).to.deep.equal([]);
    // Le point final d'une phrase n'appartient pas au domaine (10.3.5) : l'adresse est rédigée.
    expect(trouve("email", "Écrire à j.dupont@example.ch.")).to.deep.equal(["j.dupont@example.ch"]);
    expect(trouve("email", "j.dupont@example.ch- suite")).to.deep.equal(["j.dupont@example.ch"]);
    expect(C.rediger(PII, "Écrire à j.dupont@example.ch.", { portee: "prompt_systeme" }).valeur).to.equal("Écrire à [REDIGE:email].");
  });

  it("adresse électronique : recherche bornée autour de chaque @, coût linéaire (10.3.5)", function () {
    for (const texte of ["a@".repeat(64000), "a".repeat(128000) + "@", ("a".repeat(60) + "@").repeat(2000), "@" + "a.".repeat(64000)]) {
      const t0 = process.hrtime.bigint();
      C.correspondances("email", texte);
      expect(Number(process.hrtime.bigint() - t0) / 1e6, `${texte.length} caractères`).to.be.below(1500);
    }
  });

  it("téléphone : forme internationale, 8 à 15 chiffres, séparateurs isolés, une paire de parenthèses", function () {
    for (const [s, n] of [["+41 44 123 45 67", "+41441234567"], ["+41441234567", "+41441234567"], ["+41 (0)44 123 45 67", "+410441234567"], ["+41-44-123.45.67", "+41441234567"], ["+1 212 555 0100", "+12125550100"]]) expect(valeurs("telephone", `tél. ${s} !`), s).to.deep.equal([n]);
    expect(valeurs("telephone", "+41 44 123 45 67 8902")).to.deep.equal(["+414412345678902"]);
    for (const s of ["+41 44 123", "+41 44 123 45 67 89021", "044 123 45 67", "+0 44 123 45 67", "a+41441234567", "+41441234567a", "+41 (44 123 45 67"]) expect(valeurs("telephone", s), s).to.deep.equal([]);
  });

  it("faux positifs évités : montants, dates, heures, numéros de dossier, nombres JSON", function () {
    const texte = "7400.00 CHF le 2026-11-10 à 10:14:05, dossier 2026-77812, paiement PAY-2026-55120, code CH93, 1234567890123456";
    for (const type of C.DETECTEURS_NOMMES) expect(trouve(type, texte), type).to.deep.equal([]);
    const r = C.rediger(PII, { n: 378282246310005, ok: true }, { portee: "arguments", outil: "x" });
    expect(r.redacted).to.equal(false);
  });
});

// ---------------------------------------------------------------------------
describe("CT-2 : politique de rédaction (§10)", function () {
  const politique = (regles, extra = {}) => ({ version: 0, name: "essai-v1", pseudonym_key: null, rules: regles, ...extra });
  const regle = (extra) => ({ id: "r1", scopes: ["arguments"], tools: "*", detectors: [{ type: "iban" }], action: { kind: "remplacer" }, ...extra });

  it("pii-v1 (§10.9) est recevable ; son empreinte et celle de l'ensemble de politique de §15.3 sont celles de §10.6", function () {
    expect(C.erreursPolitiqueRedaction(PII_DOC, { schemas: SCHEMAS })).to.deep.equal([]);
    const e1 = C.empreinteEnsemblePolitique(PII_DOC);
    expect([e1.octets.length, e1.policy_sha256]).to.deep.equal([1462, "0x9116aac6ee1d124d155ffb22acd39b1cf2270cac07b30b239e9996012d787f4e"]);
    const e2 = C.empreinteEnsemblePolitique(CONFIG.policy);
    // Révision 0.5 : l'exemple de 15.3 porte la route Gemini, otel, policy.otel et les membres facultatifs du support WORM (EX-10.21, valeurs de 10.6).
    expect([e2.octets.length, e2.policy_sha256, e2.policy_version]).to.deep.equal([6533, "0xd68bb713d14538549a347529a1f927a13ceffd444b351fe1b644242b2574e75c", "2026-11-01"]);
    const enLigne = J.referenceEnLigne({ policy_version: e2.policy_version, policy_sha256: e2.policy_sha256 });
    expect([enLigne.length, enLigne.sha256]).to.deep.equal([116, "0xad8d1179be58a4670d01873b45479c8269b1f18c77cfb0e515ad86ef81aa246d"]);
    // Les valeurs imprimées en EX-10.21 sont celles-ci.
    const md = fs.readFileSync(path.join(SPEC, "CT-2-enregistreur.md"), "utf8");
    for (const v of [e2.policy_sha256, enLigne.sha256]) expect(md, v).to.include(v);
    expect(J.canonicaliserJCSIntegral(CONFIG.policy.redaction)).to.equal(J.canonicaliserJCSIntegral(PII_DOC));
  });

  it("les règles qu'un schéma n'exprime pas sont vérifiées (EX-10.6)", function () {
    const cas = [
      [politique([regle({ detectors: [{ type: "champ", label: "x" }] })]), "exige path"],
      [politique([regle({ path: "/a", action: { kind: "supprimer" } })]), "supprimer"],
      [politique([regle({ action: { kind: "pseudonyme" } })]), "pseudonym_key"],
      [politique([regle({ detectors: [{ type: "regex", name: "absent" }] })]), "motif nommé inconnu"],
      [politique([regle({ detectors: [{ type: "regex", name: "m" }] })], { named_patterns: { m: { pattern: "(a)\\1" } } }), "échappement \\1"],
      [politique([regle({ detectors: [{ type: "regex", name: "m" }] })], { named_patterns: { m: { pattern: "a(?=b)" } } }), "recherches avant"],
      [politique([regle({ detectors: [{ type: "regex", name: "m" }] })], { named_patterns: { m: { pattern: "(?i)abc" } } }), "drapeaux"],
      [politique([regle({ detectors: [{ type: "regex", name: "m" }] })], { named_patterns: { m: { pattern: "\\p{L}+" } } }), "échappement \\p"],
      [politique([regle({ detectors: [{ type: "regex", name: "m" }] })], { named_patterns: { m: { pattern: "a{2,1001}" } } }), "quantificateur"],
      [politique([regle({ detectors: [{ type: "regex", name: "m" }] })], { named_patterns: { m: { pattern: "x{,3}" } } }), "n'ouvre pas un quantificateur"],
      [politique([regle({ action: { kind: "pseudonyme" } })], { pseudonym_key: { env: "CLE_ESSAI" } }), "/pseudonym_key"],
      [politique([regle({ detectors: [{ type: "regex", name: "m" }] })], { named_patterns: { m: { pattern: "REDIGE" } } }), "jeton"],
      [politique([regle({ detectors: [{ type: "regex", name: "m" }] })], { named_patterns: { m: { pattern: "[0-9]{12}" } } }), "jeton"],
      [politique([regle(), regle()]), "id en double"],
    ];
    for (const [doc, motif] of cas) {
      const e = C.erreursPolitiqueRedaction(doc, { schemas: SCHEMAS });
      expect(e.join(" | "), motif).to.include(motif);
      expect(() => C.chargerPolitique(doc, { schemas: SCHEMAS }), motif).to.throw(C.ErreurConfiguration);
    }
    expect(C.erreursPolitiqueRedaction(politique([regle()], { name: "Majuscules" }), { schemas: SCHEMAS }).join(" ")).to.include("/name");
    expect(C.erreursMotifRE2("\\b20[0-9]{2}-[0-9]{5}\\b")).to.deep.equal([]);
    expect(C.erreursMotifRE2("(?<annee>20[0-9]{2})-(?P<num>[0-9]{5})")).to.deep.equal([]);
    // Encodage de la clé de pseudonymisation (15.2) : hex (0x facultatif), base64 avec remplissage, utf8.
    expect(C.decoderSecret("0x00ff", "hex")).to.deep.equal(Buffer.from([0, 255]));
    expect(C.decoderSecret("00ff", "hex")).to.deep.equal(Buffer.from([0, 255]));
    expect(C.decoderSecret("AP8=", "base64")).to.deep.equal(Buffer.from([0, 255]));
    expect(C.decoderSecret("clé", "utf8")).to.deep.equal(Buffer.from("clé", "utf8"));
    for (const [val, enc] of [["0x0", "hex"], ["zz", "hex"], ["AP8", "base64"], ["", "base64"], ["x", "latin1"]]) expect(() => C.decoderSecret(val, enc), `${enc} ${val}`).to.throw(C.ErreurConfiguration);
  });

  it("rédaction jusqu'au point fixe : un passage qui change la valeur est suivi d'un autre (EX-10.14)", function () {
    const doc = politique(
      [
        { id: "iban", scopes: ["arguments"], tools: "*", detectors: [{ type: "iban" }], action: { kind: "remplacer" } },
        { id: "q", scopes: ["arguments"], tools: "*", detectors: [{ type: "regex", name: "lettre" }], action: { kind: "remplacer" } },
      ],
      { named_patterns: { lettre: { pattern: "Q" } } },
    );
    const P = C.chargerPolitique(doc, { schemas: SCHEMAS });
    // Premier passage : l'IBAN collé à « Q » n'a pas de frontière ; « Q » devient un jeton ; le second passage trouve l'IBAN.
    const r = C.rediger(P, { t: "QCH9300762011623852957" }, { portee: "arguments" });
    expect(r.valeur).to.deep.equal({ t: "[REDIGE:lettre][REDIGE:iban]" });
    expect(r.correspondances).to.deep.equal([{ rule: "q", detector: "regex", count: 1 }, { rule: "iban", detector: "iban", count: 1 }]);
    const encore = C.rediger(P, r.valeur, { portee: "arguments" });
    expect([encore.redacted, encore.correspondances]).to.deep.equal([false, []]);
  });

  it("les deux exemples de §10.9 : octets, longueur, sha256 ; pseudonymes de la clé de test", function () {
    const a = C.pieceArguments({ arguments: { claim_id: "2026-77812", amount: "7400.00", currency: "CHF", beneficiary_iban: "CH9300762011623852957" } }, { politique: PII, outil: "sap.payments.create" });
    expect(a.octets.toString()).to.equal('{"amount":"7400.00","beneficiary_iban":"[REDIGE:iban]","claim_id":"2026-77812","currency":"CHF"}');
    expect(a.reference).to.deep.equal({ sha256: "0x6cfc43b54a70eee0141d2fc7d1acc06003ee23354ac76f2097ef74958d91bbb4", length: 96, redacted: true });
    const n = C.pieceJSON({ note: "Virement au bénéficiaire CH93 0076 2011 6238 5295 7, assuré 756.1234.5678.97, joignable au +41 44 123 45 67 ou j.dupont@example.ch ; carte 3782 822463 10005." }, { politique: PII, portee: "resultat", outil: "x" });
    expect(n.octets.toString()).to.equal('{"note":"Virement au bénéficiaire [REDIGE:iban], assuré [REDIGE:avs], joignable au [REDIGE:telephone] ou [REDIGE:email] ; carte [REDIGE:carte]."}');
    expect([n.reference.length, n.reference.sha256]).to.deep.equal([148, "0x89a34ad286014dee1e1030caf6d50d32327a77da216dfb4a19154f15b73d5f8e"]);
    expect(n.correspondances.map((c) => c.detector)).to.deep.equal(["iban", "avs", "carte", "email", "telephone"]);
    expect(C.pseudonyme(CLE_PSEUDO, "iban", "CH9300762011623852957")).to.equal("[PSEUDO:iban:50d46ea9a82b]");
    expect(C.pseudonyme(CLE_PSEUDO, "email", "j.dupont@example.ch")).to.equal("[PSEUDO:email:b8ac789204a6]");
  });

  it("ordre des règles, idempotence, redacted ssi les octets changent, sélecteurs d'outils et de portées", function () {
    const doc = politique(
      [
        { id: "regex", scopes: ["resultat"], tools: ["demo__*"], detectors: [{ type: "regex", name: "dossier" }], action: { kind: "remplacer" } },
        { id: "id", scopes: ["resultat", "requete"], tools: "*", detectors: [{ type: "iban" }, { type: "email" }], action: { kind: "remplacer" } },
        { id: "seul", scopes: ["requete"], tools: ["demo__claims.get"], detectors: [{ type: "telephone" }], action: { kind: "remplacer" } },
      ],
      { named_patterns: { dossier: { pattern: "\\b20[0-9]{2}-[0-9]{5}\\b" } } },
    );
    const P = C.chargerPolitique(doc, { schemas: SCHEMAS });
    const v = { t: "2026-81044 / CH9300762011623852957 / x@exemple.ch / +41 44 123 45 67" };
    const r1 = C.rediger(P, v, { portee: "resultat", outil: "demo__claims.get" });
    expect(r1.valeur.t).to.equal("[REDIGE:dossier] / [REDIGE:iban] / [REDIGE:email] / +41 44 123 45 67");
    expect(r1.correspondances).to.deep.equal([{ rule: "regex", detector: "regex", count: 1 }, { rule: "id", detector: "iban", count: 1 }, { rule: "id", detector: "email", count: 1 }]);
    expect(v.t).to.include("CH93", "l'entrée n'est pas modifiée");
    const r2 = C.rediger(P, r1.valeur, { portee: "resultat", outil: "demo__claims.get" });
    expect(r2.redacted).to.equal(false);
    expect(J.canonicaliserJCSIntegral(r2.valeur)).to.equal(J.canonicaliserJCSIntegral(r1.valeur));
    expect(C.rediger(P, v, { portee: "resultat", outil: "autre__x" }).valeur.t).to.match(/^2026-81044/);
    expect(C.rediger(P, v, { portee: "requete", outil: "demo__claims.get" }).valeur.t).to.equal("2026-81044 / [REDIGE:iban] / [REDIGE:email] / +41 44 123 45 67", "requete : seule une règle à tools \"*\" s'applique");
    const sans = C.rediger(P, { t: "rien à rédiger" }, { portee: "resultat", outil: "demo__x" });
    expect([sans.redacted, sans.correspondances]).to.deep.equal([false, []]);
    expect(() => C.rediger(P, v, { portee: "inconnue" })).to.throw();
  });

  it("champ, supprimer et pseudonyme sur une valeur désignée par pointeur JSON (RFC 6901)", function () {
    const doc = politique(
      [
        { id: "nombre", scopes: ["arguments"], tools: "*", path: "/m~1n/0", detectors: [{ type: "champ", label: "montant" }], action: { kind: "remplacer" } },
        { id: "membre", scopes: ["arguments"], tools: "*", path: "/secret", detectors: [{ type: "champ", label: "secret" }], action: { kind: "supprimer" } },
        { id: "element", scopes: ["arguments"], tools: "*", path: "/liste/1", detectors: [{ type: "champ", label: "copie" }], action: { kind: "supprimer" } },
        { id: "pseudo", scopes: ["arguments"], tools: "*", path: "/client", detectors: [{ type: "champ", label: "client" }], action: { kind: "pseudonyme" } },
        { id: "absent", scopes: ["arguments"], tools: "*", path: "/introuvable", detectors: [{ type: "champ", label: "x" }], action: { kind: "remplacer" } },
      ],
      { pseudonym_key: { env: "CLE_ESSAI", encoding: "hex" } },
    );
    const P = C.chargerPolitique(doc, { schemas: SCHEMAS, clePseudonyme: CLE_PSEUDO });
    const r = C.rediger(P, { "m/n": [740000, 2], secret: "x", liste: ["a", "b", "c"], client: { nom: "Dupont" } }, { portee: "arguments", outil: "x" });
    expect(r.valeur).to.deep.equal({ "m/n": ["[REDIGE:montant]", 2], liste: ["a", "[REDIGE:copie]", "c"], client: C.pseudonyme(CLE_PSEUDO, "client", '{"nom":"Dupont"}') });
    expect(r.notes.join(" ")).to.include("/introuvable");
    const racine = C.chargerPolitique(politique([{ id: "tout", scopes: ["prompt_systeme"], tools: "*", path: "", detectors: [{ type: "champ", label: "prompt-systeme" }], action: { kind: "remplacer" } }]), { schemas: SCHEMAS });
    const p = C.pieceTexte("prompt sans donnée", { politique: racine, portee: "prompt_systeme" });
    expect([p.octets.toString(), p.reference.redacted, p.reference.media_type]).to.deep.equal(["[REDIGE:prompt-systeme]", true, "text/plain"]);
    expect(() => C.chargerPolitique(doc, { schemas: SCHEMAS })).to.throw(C.ErreurConfiguration, /clé de pseudonymisation/);
    expect(C.resoudrePointeur({ a: [1] }, "/a/-").trouve).to.equal(false);
    expect(C.resoudrePointeur({ a: [1] }, "/a/01").trouve).to.equal(false);
    expect(C.resoudrePointeur({ "~": 1 }, "/~0").valeur).to.equal(1);
  });
});

// ---------------------------------------------------------------------------
describe("CT-2 : analyseur SSE (§5.4.1)", function () {
  it("champs, commentaires, data sur plusieurs lignes, type par défaut, fins de ligne CRLF, LF, CR, marque d'ordre d'octets", function () {
    const flux = "﻿event: a\r\ndata: x\r\ndata:  y\r\nid: 7\r\nretry: 10\r\n\r\n: commentaire\n\ndata\n\nevent: vide\n\ndata: z\rinconnu: q\r\rdata: perdu";
    const { evenements, commentaires } = C.analyserSSE(Buffer.from(flux, "utf8"));
    expect(evenements).to.deep.equal([{ type: "a", data: "x\n y" }, { type: "message", data: "" }, { type: "message", data: "z" }]);
    expect(commentaires).to.equal(1);
  });

  it("le résultat ne dépend pas du découpage des octets : chaque position, fragments d'un octet, découpages pseudo-aléatoires", function () {
    const sources = [];
    for (const d of fs.readdirSync(path.join(VECTEURS, "pieces-modele")).sort()) {
      const f = path.join(VECTEURS, "pieces-modele", d, "reponse.sse");
      if (fs.existsSync(f)) sources.push(fs.readFileSync(f));
    }
    sources.push(Buffer.from("event: é\r\ndata: 😀 €\r\n\r\ndata: a\rdata: b\r\r: c\n\ndata: ü\n\n", "utf8"));
    expect(sources.length).to.be.at.least(8);
    const alea = pseudoAleatoire(20261110);
    for (const o of sources) {
      const reference = C.analyserSSE(o);
      for (let k = 0; k <= o.length; k++) expect(C.analyserSSE(o, { fragments: [k] }), `coupure à ${k}`).to.deep.equal(reference);
      expect(C.analyserSSE(o, { fragments: Array(o.length).fill(1) })).to.deep.equal(reference);
      for (let essai = 0; essai < 50; essai++) {
        const fragments = [];
        let reste = o.length;
        while (reste > 0) {
          const t = Math.min(reste, 1 + Math.floor(alea() * 40));
          fragments.push(t);
          reste -= t;
        }
        expect(C.analyserSSE(o, { fragments })).to.deep.equal(reference);
      }
    }
  });
});

// ---------------------------------------------------------------------------
describe("CT-2 : formes consolidées des flux (§5.4.2 à 5.4.4)", function () {
  const sse = (evenements) => Buffer.from(evenements.map(([t, d]) => `event: ${t}\ndata: ${typeof d === "string" ? d : JSON.stringify(d)}\n\n`).join(""), "utf8");
  const debut = ["message_start", { type: "message_start", message: { id: "m", type: "message", role: "assistant", model: "x", content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 5, output_tokens: 1, cache_read_input_tokens: 3 } } }];

  it("Anthropic : blocs, deltas texte, raisonnement, signature, citations, usage remplacé membre par membre, deltas inconnus ignorés", function () {
    const c = C.consoliderFlux("anthropic-messages", sse([
      debut,
      ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "thinking", thinking: "" } }],
      ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "thinking_delta", thinking: "Je " } }],
      ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "thinking_delta", thinking: "réfléchis" } }],
      ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "signature_delta", signature: "sig" } }],
      ["content_block_stop", { type: "content_block_stop", index: 0 }],
      ["content_block_start", { type: "content_block_start", index: 1, content_block: { type: "text", text: "" } }],
      ["content_block_delta", { type: "content_block_delta", index: 1, delta: { type: "text_delta", text: "Bon" } }],
      ["content_block_delta", { type: "content_block_delta", index: 1, delta: { type: "citations_delta", citation: { cited_text: "a" } } }],
      ["content_block_delta", { type: "content_block_delta", index: 1, delta: { type: "futur_delta", x: 1 } }],
      ["content_block_delta", { type: "content_block_delta", index: 1, delta: { type: "text_delta", text: "jour" } }],
      ["content_block_stop", { type: "content_block_stop", index: 1 }],
      ["evenement_futur", { type: "evenement_futur" }],
      ["message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 9 } }],
      ["message_stop", { type: "message_stop" }],
      ["message_delta", { type: "message_delta", delta: { stop_reason: "apres" } }],
    ]));
    expect(c.forme.content).to.deep.equal([{ type: "thinking", thinking: "Je réfléchis", signature: "sig" }, { type: "text", text: "Bonjour", citations: [{ cited_text: "a" }] }]);
    expect(c.forme.usage).to.deep.equal({ input_tokens: 5, output_tokens: 9, cache_read_input_tokens: 3 });
    expect([c.forme.stop_reason, c.incomplet, c.is_error, c.ignores]).to.deep.equal(["end_turn", false, false, 3]);
  });

  it("Anthropic : entrée d'outil vide, JSON invalide, erreur en flux, événement avant message_start, flux coupé", function () {
    const outil = (index, parties) => [
      ["content_block_start", { type: "content_block_start", index, content_block: { type: "tool_use", id: `t${index}`, name: "f", input: {} } }],
      ...parties.map((p) => ["content_block_delta", { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: p } }]),
      ["content_block_stop", { type: "content_block_stop", index }],
    ];
    const c = C.consoliderFlux("anthropic-messages", sse([debut, ...outil(0, [""]), ...outil(1, ['{"a": ', "1.50}"]), ...outil(2, ['{"a":']), ["message_stop", { type: "message_stop" }]]));
    expect(c.forme.content.map((b) => b.input)).to.deep.equal([{}, { a: 1.5 }, {}]);
    expect(c.forme.content[2].noortrace_input_json_invalide).to.equal('{"a":');
    const e = C.consoliderFlux("anthropic-messages", sse([debut, ["error", { type: "error", error: { type: "overloaded_error", message: "Overloaded" } }], ["message_stop", { type: "message_stop" }]]));
    expect([e.forme.noortrace_erreur_flux, e.is_error, e.incomplet]).to.deep.equal([{ type: "error", error: { type: "overloaded_error", message: "Overloaded" } }, true, false]);
    const avant = C.consoliderFlux("anthropic-messages", sse([["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }], debut, ["message_stop", { type: "message_stop" }]]));
    expect([avant.forme.noortrace_flux_incomplet, avant.is_error]).to.deep.equal([true, true]);
    const coupe = C.consoliderFlux("anthropic-messages", sse([debut]));
    expect([coupe.forme.noortrace_flux_incomplet, coupe.is_error]).to.deep.equal([true, true]);
    expect(C.consoliderFlux("anthropic-messages", Buffer.from(": rien\n\n")).forme).to.equal(null);
  });

  it("Chat Completions : accumulation par index, refus, fin sans [DONE], identifiant différent", function () {
    const ch = (extra) => `data: ${JSON.stringify({ id: "c1", object: "chat.completion.chunk", created: 1, model: "m", ...extra })}\n\n`;
    const corps = ch({ choices: [{ index: 0, delta: { role: "assistant", refusal: "Je ne " } }] }) + ch({ choices: [{ index: 0, delta: { refusal: "peux pas." }, finish_reason: "stop" }] }) + "data: [DONE]\n\n";
    const c = C.consoliderFlux("openai-chat", Buffer.from(corps));
    expect(c.forme.choices).to.deep.equal([{ index: 0, message: { role: "assistant", content: null, refusal: "Je ne peux pas." }, finish_reason: "stop" }]);
    expect(c.is_error).to.equal(false);
    const sansFin = C.consoliderFlux("openai-chat", Buffer.from(ch({ choices: [{ index: 0, delta: { content: "a" } }] })));
    expect([sansFin.forme.noortrace_flux_incomplet, sansFin.is_error]).to.deep.equal([true, true]);
    const autreId = C.consoliderFlux("openai-chat", Buffer.from(ch({ choices: [] }) + `data: ${JSON.stringify({ id: "c2", choices: [{ index: 0, delta: { content: "x" } }] })}\n\ndata: [DONE]\n\n`));
    expect([autreId.incomplet, autreId.forme.choices]).to.deep.equal([true, []]);
  });

  it("Responses : réponse terminale, échec, erreur en flux, flux incomplet complété par les items terminés", function () {
    const ev = (o) => `data: ${JSON.stringify(o)}\n\n`;
    const rep = (status) => ({ id: "r", object: "response", status, model: "m", output: [] });
    const echec = C.consoliderFlux("openai-responses", Buffer.from(ev({ type: "response.created", response: rep("in_progress") }) + ev({ type: "error", code: "server_error", message: "panne" }) + ev({ type: "response.failed", response: rep("failed") })));
    expect([echec.forme.status, echec.forme.noortrace_erreur_flux, echec.is_error, echec.incomplet]).to.deep.equal(["failed", { code: "server_error", message: "panne" }, true, false]);
    const incomplet = C.consoliderFlux("openai-responses", Buffer.from(ev({ type: "response.in_progress", response: rep("in_progress") }) + ev({ type: "response.output_item.done", output_index: 1, item: { type: "message", id: "b" } }) + ev({ type: "response.output_item.done", output_index: 0, item: { type: "message", id: "a" } })));
    expect(incomplet.forme.output).to.deep.equal([{ type: "message", id: "a" }, { type: "message", id: "b" }]);
    expect([incomplet.forme.noortrace_flux_incomplet, incomplet.is_error]).to.deep.equal([true, true]);
    const fin = C.consoliderFlux("openai-responses", Buffer.from(ev({ type: "response.incomplete", response: rep("incomplete") })));
    expect([fin.is_error, fin.incomplet]).to.deep.equal([false, false]);
  });
});

// ---------------------------------------------------------------------------
describe("CT-2 : agrégation de tools/list et nommage (§4.3)", function () {
  it("préfixe alias__, rejets, classes, ordre déterministe, pagination, erreurs de configuration", function () {
    const r = C.agregerOutils(
      [
        { alias: "zeta", tools: [{ name: "b.x" }, { name: "a", annotations: { readOnlyHint: true } }] },
        { alias: "alpha", tools: [{ name: "noortrace.y" }, { name: "x".repeat(122) }, { name: "d" }, { name: "d" }, { name: "w" }], class_default: "lecture", tools_config: { w: { class: "ecriture" } } },
      ],
      { prefix: true, page_size: 2 },
    );
    expect(r.announced.map((a) => [a.announced, a.class])).to.deep.equal([["alpha__w", "ecriture"], ["zeta__a", "lecture"], ["zeta__b.x", "ecriture"]]);
    expect(r.rejected).to.deep.equal([
      { server_alias: "alpha", original: "d", reason: "collision" },
      { server_alias: "alpha", original: "d", reason: "collision" },
      { server_alias: "alpha", original: "noortrace.y", reason: "nom_reserve" },
      { server_alias: "alpha", original: "x".repeat(122), reason: "nom_invalide" },
    ]);
    expect(r.pages).to.deep.equal([["alpha__w", "zeta__a"], ["zeta__b.x"]]);
    expect(r.announced[2].definition).to.deep.equal({ name: "zeta__b.x" });
    for (const [alias, prefix] of [[["noortrace"], true], [["A"], true], [["a", "a"], true], [["a", "b"], false], [["a".repeat(33)], true]]) expect(() => C.agregerOutils(alias.map((x) => ({ alias: x, tools: [] })), { prefix }), alias.join(",")).to.throw(C.ErreurConfiguration);
    expect(C.resoudreNomAnnonce("demo__claims.get")).to.deep.equal({ alias: "demo", original: "claims.get" });
    expect(C.resoudreNomAnnonce("demo__a__b")).to.deep.equal({ alias: "demo", original: "a__b" });
    expect(C.resoudreNomAnnonce("claims.get", { prefix: false, aliasUnique: "demo" })).to.deep.equal({ alias: "demo", original: "claims.get" });
    expect(C.classeOutil({ annotations: { readOnlyHint: "true" } })).to.equal("ecriture");
  });

  it("nom vu par le modèle : gabarit et normalisation de la connexion d'hôte (EX-5.22)", function () {
    expect(C.nomVuParModele("demo__claims.get")).to.equal("demo__claims.get");
    expect(C.nomVuParModele("demo__claims.get", { sanitize: true })).to.equal("demo__claims_get");
    expect(C.nomVuParModele("demo__claims.get", { template: "mcp__noortrace__{tool_announced}", sanitize: true })).to.equal("mcp__noortrace__demo__claims_get");
    expect(C.nomVuParModele("demo__claims.get", { template: "{alias}_{tool}" })).to.equal("demo_claims.get");
  });
});

// ---------------------------------------------------------------------------
describe("CT-2 : annexe A recalculée (relais de tools/call, pièces, événements)", function () {
  const ev1 = blocs("CT-1-evenements-et-formats.md", "evenement").map((t) => J.analyserJSONStrict(t)).find((e) => e.seq === 1);
  const blocsA = blocs("CT-2-enregistreur.md", "evenement").map((t) => J.analyserJSONStrict(t));
  const hote = '{"jsonrpc":"2.0","id":"h-77812-4","method":"tools/call","params":{"name":"sap.payments.create","arguments":{"claim_id":"2026-77812","amount":"7400.00","currency":"CHF","beneficiary_iban":"CH9300762011623852957"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"agent-sinistres","version":"1.4.0"}}}}';
  const reponse = '{"jsonrpc":"2.0","id":"e-000000000041","result":{"resultType":"complete","content":[{"type":"text","text":"Paiement PAY-2026-55120 créé"}],"isError":false}}';
  const definition = { name: "sap.payments.create", description: "Cree un paiement de sinistre dans SAP", inputSchema: { type: "object", properties: { claim_id: { type: "string" }, amount: { type: "string" }, currency: { type: "string" }, beneficiary_iban: { type: "string" } }, required: ["claim_id", "amount", "currency", "beneficiary_iban"], additionalProperties: false }, annotations: { readOnlyHint: false, destructiveHint: false } };

  it("lignes relayées et pièces : 408, 420, 158 et 252 octets ; arguments, définition, résultat, intention", function () {
    expect(Buffer.byteLength(hote)).to.equal(408);
    const msg = C.analyserJSONIntegral(hote);
    const amont = C.ligneAmontToolsCall(hote, { idAmont: C.idAmont(41), nomOrigine: "sap.payments.create", protocolVersion: "2026-07-28" }).ligne;
    expect(amont).to.equal('{"jsonrpc":"2.0","id":"e-000000000041","method":"tools/call","params":{"name":"sap.payments.create","arguments":{"claim_id":"2026-77812","amount":"7400.00","currency":"CHF","beneficiary_iban":"CH9300762011623852957"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"noortrace-enregistreur","version":"0.1.0"}}}}');
    expect(Buffer.byteLength(amont)).to.equal(420);
    expect(Buffer.byteLength(reponse)).to.equal(158);
    const rendue = C.ligneHoteReponse(reponse, { idHote: "h-77812-4" });
    expect(rendue).to.equal('{"jsonrpc":"2.0","id":"h-77812-4","result":{"resultType":"complete","content":[{"type":"text","text":"Paiement PAY-2026-55120 créé"}],"isError":false,"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"noortrace-enregistreur","version":"0.1.0"}}}}');
    expect(Buffer.byteLength(rendue)).to.equal(252);
    expect(C.pieceArguments(msg.params, { politique: PII, outil: "sap.payments.create" }).reference).to.deep.equal({ sha256: "0x6cfc43b54a70eee0141d2fc7d1acc06003ee23354ac76f2097ef74958d91bbb4", length: 96, redacted: true });
    expect(C.pieceDefinitionOutil(definition).reference).to.deep.equal({ sha256: "0x7d2ffcd2cba25dbd90b54926be79c845131109b2e1bc4ccc22389fb8a26a498a", length: 406, redacted: false, media_type: "application/json" });
    const res = C.pieceResultatMCP(C.analyserJSONIntegral(reponse), { politique: PII, outil: "sap.payments.create" });
    expect([res.reference, res.is_error]).to.deep.equal([{ sha256: "0x850627f5a2216e1d592b9a6a21d5df8f5a9454e7330809ba6a4d070a7f633b8c", length: 109, redacted: false }, false]);
    const argsPiece = C.pieceArguments(msg.params, { politique: PII, outil: "sap.payments.create" });
    const intent_id = C.idIntention(1, 41);
    expect(intent_id).to.equal("i-00000000000000000001-000000000041");
    const li = C.ligneIntention({ intent_id, upstream_id: C.idAmont(41), host: "agent-sinistres-stdio", written_at: "2026-11-03T13:52:40.678Z", org_id: ev1.org_id, journal_id: ev1.journal_id, tool: "sap.payments.create", arguments: argsPiece.reference, ticket: "apr-1192" });
    expect(li).to.equal(blocsTexte("CT-2-enregistreur.md", "7. **Préconditions et intention**"));
    expect(Object.keys(JSON.parse(li))).to.have.length(9);
    expect([Buffer.byteLength(li), C.empreinteIntention(li)]).to.deep.equal([482, "0xdd28b1c3e93808ddb24979a145ca1fe131ba0adc5390291b3287c0b329310b08"]);
    expect(C.pieceListeAnnoncee([definition]).reference).to.deep.equal({ sha256: "0xbce6c768f26f72d7377fa3098262b61db83bcc740fc528be536acaa7f168033e", length: 418, redacted: false, media_type: "application/json" });
    const res2 = C.pieceResultatMCP(C.analyserJSONIntegral(reponse), { politique: PII, outil: "sap.payments.create" });
    const effets = C.evaluerGabaritsEffets([{ system: "SAP", action: "ecriture", object: "/result/content/0/text", extract: "PAY-[0-9]{4}-[0-9]{5}", amount: "/arguments/amount", currency: "/arguments/currency" }], { arguments: argsPiece.valeur, result: res2.valeur });
    expect(effets.effects).to.deep.equal([{ system: "SAP", action: "ecriture", object: "PAY-2026-55120", amount: "7400.00", currency: "CHF" }]);
  });

  it("seq 2, 3 et 4 rescellés par l'écrivain sont identiques, octet pour octet, aux événements imprimés ; ligne de segment de 2465 octets", function () {
    const ecr = new C.Ecrivain({ org_id: ev1.org_id, journal_id: ev1.journal_id, cles: { "rec-test-01": CLE_01.clePrivee }, schemas: SCHEMAS, dernier: ev1 });
    const delegation = { launched_by: "u.martin@assureur-demo.example", on_behalf_of: "service-sinistres", scope: "sinistres:lecture,paiement", run_id: "run-2026-11-03-0142" };
    const code = { model: ev1.code.model, prompt_version: ev1.code.prompt_version, policy_version: "2026-11-01", recorder: "0.1.0" };
    const intent = "Régler le sinistre 2026-77812 après validation des pièces";
    const msg = C.analyserJSONIntegral(hote);
    const args = C.pieceArguments(msg.params, { politique: PII, outil: "sap.payments.create" });
    const contexte = C.contexteAppel({ servie: C.pieceDefinitionOutil(definition), courante: C.pieceDefinitionOutil(definition), liste: C.pieceListeAnnoncee([definition]) });
    expect(contexte.map((c) => c.length)).to.deep.equal([406, 418]);
    const regle = { rule: "paiement > 5000 CHF", decision: "a_approuver", ticket: "apr-1192" };
    const s2 = ecr.sceller(C.partielAppelOutil({ delegation, code, intent, policy: regle, tool: "sap.payments.create", arguments: args.reference, status: "retenue", context: contexte, nomRedaction: "pii-v1" }), { ts_lu: "2026-11-03T13:41:07.218Z" });
    const A = { decision: "approuve", journal_id: ev1.journal_id, org_id: ev1.org_id, request_hash: s2.hash, ticket: "apr-1192" };
    expect(J.condenseApprobation(A)).to.equal("0x411768329b8c16bdfe32c4a4b5f6993571c2e5d73b55fdf1f19d00fe408408a8");
    const approval = { decision: "approuve", ticket: "apr-1192", request_hash: s2.hash, threshold: { required: 2, size: 3 }, approvers: [HARDHAT[1].address.toLowerCase(), HARDHAT[2].address.toLowerCase()], signatures: [J.signerApprobation(HARDHAT[1], A), J.signerApprobation(HARDHAT[2], A)], at: "2026-11-03T13:52:40.511Z", reason: "Pièces validées" };
    const s3 = ecr.sceller(C.partielDecision({ delegation, code, approval, org_id: ev1.org_id, journal_id: ev1.journal_id }), { ts_lu: approval.at });
    expect([s3.hash, s3.execution.arguments.length, s3.execution.arguments.sha256]).to.deep.equal(["0xa167496bc58e285bd1d1925e15b3d24c147bc9559e0a19065eade18ecf860371", 287, "0x6b5a72c84048bc9578e472c81185536afd446554b17d56ead46c39b717dc00be"]);
    const resultat = C.pieceResultatMCP(C.analyserJSONIntegral(reponse), { politique: PII });
    const effets = [{ system: "SAP", action: "ecriture", object: "PAY-2026-55120", amount: "7400.00", currency: "CHF" }];
    const s4 = ecr.sceller(C.partielAppelOutil({ delegation, code, intent, policy: regle, approval, tool: "sap.payments.create", arguments: args.reference, status: "executee", result: resultat.reference, duration_ms: 412, is_error: false, effects: effets, context: contexte, nomRedaction: "pii-v1" }), { ts_lu: "2026-11-03T13:52:41.090Z" });
    const imprimes = Object.fromEntries(blocsA.map((e) => [e.seq, e]));
    expect(s2).to.deep.equal(imprimes[2]);
    expect(s4).to.deep.equal(imprimes[4]);
    expect(J.texteJSON(s4)).to.equal(J.texteJSON(imprimes[4]), "ordre des clés de la spécification");
    expect(J.octetsJCS(J.corpsEvenement(s4)).length).to.equal(2249);
    expect(Buffer.byteLength(C.ligneSegment(s4))).to.equal(2465);
    expect(J.verifierChaine([ev1, s2, s3, s4], { clesPubliques: { "rec-test-01": CLE_01.clePublique } })).to.deep.equal({ valide: true, diagnostics: [] });
  });
});

// ---------------------------------------------------------------------------
describe("CT-2 : construction des événements, écrivain, segment, intention, reprise (§7, §9, §12)", function () {
  const ORG = "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab";
  const JOURNAL = "0x" + "11".repeat(32);
  const nouvelEcrivain = (dernier = null) => new C.Ecrivain({ org_id: ORG, journal_id: JOURNAL, recorder_key_id: "rec-test-01", cles: { "rec-test-01": CLE_01.clePrivee }, schemas: SCHEMAS, dernier });
  const politique = (v) => C.partielPolitique({ policy_version: v, policy_sha256: J.sha256(Buffer.from(v)) });

  it("chaque sorte construite valide contre le schéma de CT-1 et passe E-1 à E-11 ; la chaîne est valide", function () {
    const ecr = nouvelEcrivain();
    const deleg = { launched_by: "agent", on_behalf_of: null, scope: "s", run_id: null };
    const code = { model: "demo/m", prompt_version: null, policy_version: "v1", recorder: "0.1.0" };
    const a = C.pieceJSON({ x: 1.5 }, { politique: PII, portee: "arguments" });
    const r = C.pieceJSON({ content: [], isError: false }, { politique: PII, portee: "resultat" });
    const evs = [
      ecr.sceller(politique("v1"), { ts_lu: "2026-11-10T10:00:00.000Z" }),
      ecr.sceller(C.partielEchangeModele({ delegation: deleg, code, intent: "texte", requete: a.reference, reponse: r.reference, duration_ms: 5, is_error: false, nomRedaction: "pii-v1" }), { ts_lu: "2026-11-10T10:00:01.000Z" }),
      ecr.sceller(C.partielAppelOutil({ delegation: deleg, code, policy: { rule: null, decision: "autorise", ticket: null }, tool: "demo__x", arguments: a.reference, status: "executee", result: r.reference, duration_ms: 3, is_error: false, effects: C.effetsParDefaut({ classe: "ecriture", alias: "demo", original: "x" }), nomRedaction: "pii-v1" }), { ts_lu: "2026-11-10T10:00:02.000Z" }),
      ecr.sceller(C.partielAppelOutil({ delegation: deleg, code, policy: { rule: "r", decision: "refuse", ticket: null }, tool: "demo__x", arguments: a.reference, status: "refusee", nomRedaction: "pii-v1" }), { ts_lu: "2026-11-10T10:00:03.000Z" }),
    ];
    expect(evs[2].effects).to.deep.equal([{ system: "demo", action: "ecriture", object: "x", amount: null, currency: null }]);
    expect(evs[0].effects).to.deep.equal([{ system: "noortrace", action: "ecriture", object: "politique:v1", amount: null, currency: null }]);
    expect(evs[1].policy.redaction).to.equal(null, "aucune pièce rédigée");
    for (const ev of evs) {
      const echecs = Object.entries(J.controlesEvenement(ev, { schemas: SCHEMAS, cles: { "rec-test-01": CLE_01.clePublique } })).filter(([, x]) => x.ok === false);
      expect(echecs, `seq ${ev.seq}`).to.deep.equal([]);
    }
    expect(J.verifierChaine(evs, { clesPubliques: { "rec-test-01": CLE_01.clePublique } }).valide).to.equal(true);
  });

  it("ts = max(lu, précédent) sous le seuil ; mode dégradé horloge au-delà ; exception de l'événement en attente (EX-7.9, EX-14.10)", function () {
    const ecr = nouvelEcrivain();
    ecr.sceller(politique("v1"), { ts_lu: "2026-11-10T10:00:05.000Z" });
    expect(ecr.sceller(politique("v2"), { ts_lu: "2026-11-10T10:00:01.000Z" }).ts).to.equal("2026-11-10T10:00:05.000Z");
    expect(() => ecr.sceller(politique("v3"), { ts_lu: "2026-11-10T09:59:59.999Z" })).to.throw(C.ErreurModeDegrade).with.property("raison", "horloge");
    expect(ecr.sceller(politique("v3"), { captured_at: "2026-11-10T09:00:00.000Z" }).ts).to.equal("2026-11-10T10:00:05.000Z");
    expect(ecr.sceller(politique("v4"), { ts_lu: Date.UTC(2026, 10, 10, 10, 0, 6) }).seq).to.equal(4);
  });

  it("saut de l'horloge murale en avant au-delà de max_forward_ms, mesuré contre l'horloge monotone : mode dégradé horloge (EX-7.13)", function () {
    const ecr = nouvelEcrivain();
    ecr.sceller(politique("v1"), { ts_lu: "2026-11-10T10:00:00.000Z", mono: 1000 });
    expect(ecr.sceller(politique("v2"), { ts_lu: "2026-11-10T10:00:50.000Z", mono: 1000 + 1000 }).seq).to.equal(2, "50 s de mur contre 1 s de monotone : sous la tolérance de 60 s");
    expect(() => ecr.sceller(politique("v3"), { ts_lu: "2026-11-10T10:03:00.000Z", mono: 2000 + 1000 })).to.throw(C.ErreurModeDegrade).with.property("raison", "horloge");
    expect(ecr.sceller(politique("v3"), { ts_lu: "2026-11-10T10:00:51.000Z", mono: 2000 + 1000 }).seq).to.equal(3);
  });

  it("un événement invalide n'est pas signé (EX-7.1)", function () {
    const ecr = nouvelEcrivain();
    const p = politique("v1");
    p.execution.result = { sha256: J.HASH_NUL, length: 0, redacted: false };
    expect(() => ecr.sceller(p, { ts_lu: "2026-11-10T10:00:00.000Z" })).to.throw(/EX-7\.1/);
    expect(ecr.evenements).to.have.length(0);
  });

  it("segment : en-tête JCS v0, lignes JCS v0 ; relecture, troncature d'une fin incomplète, corruption détectée", function () {
    const ecr = nouvelEcrivain();
    for (let i = 1; i <= 3; i++) ecr.sceller(politique(`v${i}`), { ts_lu: `2026-11-10T10:00:0${i}.000Z` });
    const entete = { epoch: 2, first_seq: 1, instance_id: "i", org_id: ORG, journal_id: JOURNAL, opened_at: "2026-11-10T10:00:00.000Z", prev_hash: J.HASH_NUL, recorder_key_id: "rec-test-01" };
    const texte = C.segment(entete, ecr.evenements);
    expect(texte.split("\n")[0]).to.equal(J.canonicaliserJCS({ ...entete, noortrace_segment: 0, recorder: "0.1.0" }));
    const cles = { "rec-test-01": CLE_01.clePublique };
    expect(C.relireSegment(texte, { schemas: SCHEMAS, clesPubliques: cles }).evenements).to.have.length(3);
    const tronque = texte.slice(0, texte.length - 40);
    const r = C.relireSegment(tronque, { schemas: SCHEMAS, clesPubliques: cles });
    expect([r.evenements.length, r.tronque, r.corrompu]).to.deep.equal([2, true, null]);
    expect(r.longueurValide).to.equal(Buffer.byteLength(texte) - Buffer.byteLength(C.ligneSegment(ecr.evenements[2])));
    const corrompu = texte.replace('"politique:v2"', '"politique:v9"');
    const rc = C.relireSegment(corrompu, { schemas: SCHEMAS, clesPubliques: cles });
    expect([rc.corrompu.seq, rc.corrompu.raison, rc.tronque, rc.evenements.length]).to.deep.equal([2, "hash recalculé différent", false, 1]);
    const remplissage = C.relireSegment(Buffer.concat([Buffer.from(texte), Buffer.alloc(64)]), { schemas: SCHEMAS, clesPubliques: cles });
    expect([remplissage.evenements.length, remplissage.tronque, remplissage.longueurValide]).to.deep.equal([3, true, Buffer.byteLength(texte)]);
    const lignes = texte.split("\n");
    const illisible = C.relireSegment([lignes[0], lignes[1], "{pas du json", lignes[3], ""].join("\n"), { schemas: SCHEMAS, clesPubliques: cles });
    expect([illisible.tronque, illisible.corrompu.seq]).to.deep.equal([false, 2]);
    const autreCle = C.relireSegment(texte, { schemas: SCHEMAS, clesPubliques: { "rec-test-01": J.cleEd25519DepuisGraine(graine("rec-test-02")).clePublique } });
    expect([autreCle.evenements.length, autreCle.corrompu.raison]).to.deep.equal([0, "signature invalide ou clé inattendue"]);
  });

  it("réponse rendue à l'hôte : serverInfo posé, ajouté ou remplacé, resultType ajouté pour un hôte moderne, erreur recopiée (4.4 pas 14)", function () {
    const si = '"io.modelcontextprotocol/serverInfo":{"name":"noortrace-enregistreur","version":"0.1.0"}';
    expect(C.ligneHoteReponse('{"jsonrpc":"2.0","id":"e","result":{}}', { idHote: 3 })).to.equal(`{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","_meta":{${si}}}}`);
    expect(C.ligneHoteReponse('{"jsonrpc":"2.0","id":"e","result":{"content":[],"_meta":null}}', { idHote: 3, hoteModerne: false })).to.equal(`{"jsonrpc":"2.0","id":3,"result":{"content":[],"_meta":{${si}}}}`);
    expect(C.ligneHoteReponse('{"jsonrpc":"2.0","id":"e","result":{"resultType":"complete","_meta":{ "a" : 1.0 ,"io.modelcontextprotocol/serverInfo":{"name":"amont"}}}}', { idHote: "h" })).to.equal(`{"jsonrpc":"2.0","id":"h","result":{"resultType":"complete","_meta":{"a":1.0,${si}}}}`);
    // Blancs non significatifs retirés, id recopié depuis le texte de l'hôte (EX-4.43, 4.4 pas 14).
    expect(C.ligneHoteReponse('{ "jsonrpc" : "2.0" ,\r\n "id" : "e" , "result" : { "content" : [ ] , "isError" : false } }', { idHote: 12345678901234567000, idHoteTexte: "12345678901234567890" })).to.equal(`{"jsonrpc":"2.0","id":12345678901234567890,"result":{"resultType":"complete","content":[],"isError":false,"_meta":{${si}}}}`);
    expect(C.ligneHoteReponse('{"jsonrpc":"2.0","id":"e","result":["x"]}', { idHote: 1 })).to.equal('{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"noortrace: resultat amont invalide","data":{"result_type":"array"}}}');
    expect(C.ligneHoteReponse('{"jsonrpc":"2.0","id":"e","error":{"code":-32602,"message":"Unknown tool: x"}}', { idHote: 9 })).to.equal('{"jsonrpc":"2.0","id":9,"error":{"code":-32602,"message":"Unknown tool: x"}}');
    expect(C.ligneHoteErreur(9, C.erreurEnregistreur("ANNULE"))).to.equal('{"jsonrpc":"2.0","id":9,"error":{"code":-31012,"message":"noortrace: appel annule par l\'hote"}}');
    const amont = C.ligneAmontToolsCall('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"demo__x","_meta":{"progressToken":"t-hote","traceparent":"00-ab-cd-01"},"requestState":"etat","inputResponses":{"k":{"action":"accept"}}}}', { idAmont: "e-000000000001", nomOrigine: "x", protocolVersion: "2026-07-28", progressToken: "p-000000000001" });
    expect(amont.progressTokenHote).to.equal("t-hote");
    expect(amont.ligne).to.equal('{"jsonrpc":"2.0","id":"e-000000000001","method":"tools/call","params":{"name":"x","inputResponses":{"k":{"action":"accept"}},"requestState":"etat","_meta":{"progressToken":"p-000000000001","traceparent":"00-ab-cd-01","io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"noortrace-enregistreur","version":"0.1.0"}}}}');
    expect(C.pieceArguments({ name: "x" }).octets.toString()).to.equal("{}");
  });

  it("journal d'intention : intention sans levée → événement de reprise valide ; événement durable → levée implicite (EX-12.14)", function () {
    const ecr = nouvelEcrivain();
    ecr.sceller(politique("v1"), { ts_lu: "2026-11-10T10:00:00.000Z" });
    const a = C.pieceJSON({ iban: "CH9300762011623852957" }, { politique: PII, portee: "arguments" });
    const partiel = C.partielAppelOutil({ delegation: { launched_by: "agent", on_behalf_of: null, scope: "s", run_id: "r" }, code: { model: null, prompt_version: null, policy_version: "v1", recorder: "0.1.0" }, policy: { rule: null, decision: "autorise", ticket: null }, tool: "demo__pay", arguments: a.reference, status: "executee", nomRedaction: "pii-v1" });
    const id = C.idIntention(3, 1);
    const li = C.ligneIntention({ intent_id: id, upstream_id: C.idAmont(1), host: "agent", written_at: "2026-11-10T10:00:01.000Z", org_id: ORG, journal_id: JOURNAL, tool: "demo__pay", arguments: a.reference, ticket: null });
    const texte = `${li}\n${C.ligneContexteIntention(id, partiel)}\n`;
    const [rep] = C.reprise(texte, ecr.evenements, { resoudreOutil: () => ({ alias: "demo", original: "pay", classe: "ecriture" }), nomRedaction: "pii-v1" });
    expect(rep.piece.octets.toString()).to.equal(`{"intention_sha256":"${C.empreinteIntention(li)}","noortrace_reprise":"resultat inconnu : enregistreur arrete pendant le relais"}`);
    const ev = ecr.sceller(rep.partiel, { ts_lu: "2026-11-10T10:05:00.000Z" });
    expect([ev.execution.status, ev.execution.is_error, ev.execution.duration_ms, ev.policy.redaction, ev.effects[0].object]).to.deep.equal(["executee", true, 0, "pii-v1", "pay"]);
    expect(J.verifierChaine(ecr.evenements, { clesPubliques: { "rec-test-01": CLE_01.clePublique } }).valide).to.equal(true);
    expect(C.reprise(texte, ecr.evenements)).to.deep.equal([{ intent_id: id, implicite: 2 }]);
    expect(C.reprise(`${texte}${C.ligneLevee(id, 2)}\n`, [])).to.deep.equal([]);
    // Un événement désigné par une ligne levée d'une autre intention ne lève pas implicitement celle-ci (EX-12.13).
    const id2 = C.idIntention(3, 2);
    const li2 = C.ligneIntention({ intent_id: id2, upstream_id: C.idAmont(2), host: "agent", written_at: "2026-11-10T10:00:01.000Z", org_id: ORG, journal_id: JOURNAL, tool: "demo__pay", arguments: a.reference, ticket: null });
    const deux = C.reprise(`${texte}${li2}\n${C.ligneContexteIntention(id2, partiel)}\n${C.ligneLevee(id, 2)}\n`, ecr.evenements, { resoudreOutil: () => ({ alias: "demo", original: "pay", classe: "ecriture" }) });
    expect(deux.map((x) => [x.intent_id, x.implicite ?? null])).to.deep.equal([[id2, null]]);
    // Ligne illisible suivie d'autres lignes : corruption, mode dégradé « stockage » (EX-12.22).
    expect(() => C.lireJournalIntention(`${li}\n{illisible\n${li2}\n`)).to.throw(C.ErreurModeDegrade);
    expect(C.lireJournalIntention(`${li}\n{illisible`)).to.have.length(1);
    // Sans ligne contexte : reconstruction depuis la ligne intention et la chaîne, sans rien fabriquer (EX-12.13).
    const sans = C.reprise(`${li}\n`, ecr.evenements.slice(0, 1), { resoudreOutil: () => ({ alias: "demo", original: "pay", classe: "ecriture" }), resoudreHote: (h) => (h === "agent" ? { launched_by: "agent", on_behalf_of: null, scope: "s", run_id: "ignore" } : null), nomRedaction: "pii-v1" });
    expect(sans[0].sans_contexte).to.equal(true);
    expect([sans[0].partiel.delegation, sans[0].partiel.code.model, sans[0].partiel.code.policy_version, sans[0].partiel.intent, sans[0].partiel.policy.decision]).to.deep.equal([{ launched_by: "agent", on_behalf_of: null, scope: "s", run_id: null }, null, "v1", null, "autorise"]);
    expect(() => C.reprise(`${li}\n`, ecr.evenements.slice(0, 1), { resoudreHote: () => null })).to.throw(C.ErreurModeDegrade, /intention_irreconstructible/);
    const p = C.pieceAttente("att-1");
    expect(p.octets.toString()).to.equal('{"noortrace_attente":"resultat perdu pendant le mode degrade","pending_id":"att-1"}');
  });

  it("gabarits d'effets : pointeur non résolu, montant hors format, devise fixe, troncature (EX-7.6)", function () {
    const source = { arguments: { m: "12.5", n: 12.5, d: "CHF" }, result: { id: "x".repeat(600) } };
    const r = C.evaluerGabaritsEffets(
      [
        { system: "S", action: "ecriture", object: "/result/absent", amount: null, currency: null },
        { system: "S", action: "ecriture", object: "/result/id", amount: "/arguments/m", currency: "EUR" },
        { system: "S", action: "ecriture", object: "fixe", amount: "/arguments/n", currency: "/arguments/d" },
        { system: "S", action: "ecriture", object: "fixe", amount: "/arguments/m", currency: null },
        { system: "S", action: "lecture", object: "/arguments/d", extract: "^(X)", amount: null, currency: null },
      ],
      source,
    );
    expect(r.effects).to.have.length(2);
    expect(r.effects[0].object).to.have.length(512);
    expect(r.effects[1]).to.deep.equal({ system: "S", action: "ecriture", object: "fixe", amount: "12.5", currency: "CHF" });
    expect(r.notes).to.have.length(3);
    // Objet vide, extraction avec groupe capturant, conversion d'un nombre en JCS intégral (EX-7.6).
    const g = C.evaluerGabaritsEffets(
      [
        { system: "S", action: "ecriture", object: "/arguments/vide", amount: null, currency: null },
        { system: "S", action: "ecriture", object: "/result/t", extract: "ref=([A-Z]+)-", amount: null, currency: null },
        { system: "S", action: "ecriture", object: "/arguments/n", amount: null, currency: null },
        { system: "S", action: "ecriture", object: "/result/t", extract: "ref=(X)?", amount: null, currency: null },
      ],
      { arguments: { vide: "", n: 1.5e3 }, result: { t: "ok ref=ABC-12" } },
    );
    expect(g.effects.map((e) => e.object)).to.deep.equal(["ABC", "1500", "ref="]);
    expect(g.notes).to.have.length(1);
  });

  it("corrélation : nom normalisé, arguments au JCS intégral, fenêtre, consommation d'un appel (EX-5.22)", function () {
    const forme = { content: [{ type: "text", text: "Avant" }, { type: "tool_use", id: "t1", name: "demo__claims_get", input: { claim_id: "1", v: 1.0 } }] };
    const echanges = [{ seq: 2, t: 1000, run_id: "r", format: "anthropic-messages", forme, code_model: "demo/m", prompt_version: null }];
    const appel = { tool_announced: "demo__claims.get", arguments: { v: 1, claim_id: "1" }, t_recu: 2000, run_id: "r" };
    expect(C.correler(appel, echanges).appel, "sans normalisation, pas de correspondance").to.equal(null);
    const c = C.correler(appel, echanges, { sanitize: true });
    expect([c.echange.seq, c.appel.id, c.texte]).to.deep.equal([2, "t1", "Avant"]);
    const encore = C.correler(appel, echanges, { sanitize: true });
    // Aucun échange antérieur n'est repris par défaut (EX-5.22).
    expect(encore).to.deep.equal({ echange: null, appel: null, texte: null, texteClair: null });
    expect(C.correler({ ...appel, t_recu: 1000 + 600001 }, echanges, { sanitize: true }).echange).to.equal(null);
    const chat = [{ seq: 3, t: 1000, run_id: "r", format: "openai-chat", forme: { choices: [{ message: { content: "Texte", tool_calls: [{ id: "c", function: { name: "demo__claims_get", arguments: "pas du JSON" } }] } }] } }];
    expect(C.correler(appel, chat, { sanitize: true }).appel).to.equal(null);
    // Groupe d'hôte et run_id : seuls les échanges du même groupe, et du même run_id quand les deux sont déclarés, sont candidats.
    const registre = () => [
      { seq: 5, t: 1000, run_id: "autre", groupe: "g", format: "anthropic-messages", forme, forme_redigee: forme },
      { seq: 6, t: 1000, run_id: null, groupe: "h", format: "anthropic-messages", forme, forme_redigee: forme },
    ];
    expect(C.correler({ ...appel, groupe: "g", run_id: "r" }, registre(), { sanitize: true }).echange).to.equal(null);
    expect(C.correler({ ...appel, groupe: "g", run_id: null }, registre(), { sanitize: true }).echange.seq).to.equal(5);
    expect(C.correler({ ...appel, groupe: "h", run_id: "r" }, registre(), { sanitize: true }).echange.seq).to.equal(6);
    // intent vient de la réponse rédigée ; la forme en clair ne sert qu'à la comparaison.
    const redigee = { content: [{ type: "text", text: "IBAN [REDIGE:iban]" }, forme.content[1]] };
    const enClair = { content: [{ type: "text", text: "IBAN CH9300762011623852957" }, forme.content[1]] };
    const c2 = C.correler({ ...appel, groupe: "g" }, [{ seq: 7, t: 1000, run_id: null, groupe: "g", format: "anthropic-messages", forme: enClair, forme_redigee: redigee }], { sanitize: true });
    expect([c2.texte, c2.texteClair]).to.deep.equal(["IBAN [REDIGE:iban]", "IBAN CH9300762011623852957"]);
    const i2 = C.intentionRedigee(c2.texte, c2.texteClair);
    expect([i2.intent.redacted, i2.intent.media_type, i2.piece.octets.toString()]).to.deep.equal([true, "text/plain", "IBAN [REDIGE:iban]"]);
  });

  it("échange de modèle : requête non JSON stockée telle quelle, corps d'erreur HTML, intention longue en référence", function () {
    // Requête non analysable ou comprimée : refus de la passerelle, sans pièce (EX-5.7).
    const brut = C.echangeModele({ format: "anthropic-messages", provider_label: "anthropic", requete: { corps: Buffer.from("pas du json"), content_type: "Text/Plain; charset=utf-8" }, reponse: { status: 502, content_type: "text/html", corps: Buffer.from("<html>panne</html>") }, politique: PII });
    expect(brut.refus).to.deep.equal({ status: 400, raison: "corps_non_analysable", corps: { type: "error", error: { type: "invalid_request_error", message: "noortrace: corps de requete non analysable" } } });
    expect(brut.pieces).to.equal(undefined);
    const gz = C.echangeModele({ format: "openai-chat", provider_label: "openai", requete: { corps: Buffer.from("{}"), content_type: "application/json", content_encoding: "gzip" }, reponse: { status: 200, content_type: "application/json", corps: Buffer.from("{}") }, politique: PII });
    expect([gz.refus.status, gz.refus.raison, gz.refus.corps.error.code]).to.deep.equal([415, "content_encoding", "noortrace_requete_invalide"]);
    // Corps d'erreur HTML : pièce noortrace_http_error, code.model tiré de la requête rédigée.
    const html = C.echangeModele({ format: "anthropic-messages", provider_label: "anthropic", requete: { corps: Buffer.from('{"model":"m","max_tokens":1,"messages":[]}'), content_type: "application/json" }, reponse: { status: 502, content_type: "text/html", corps: Buffer.from("<html>panne : ops@exemple.ch</html>") }, politique: PII });
    expect(html.pieces.reponse.octets.toString()).to.equal('{"noortrace_http_error":{"body":"<html>panne : [REDIGE:email]</html>","content_type":"text/html","status":502}}');
    expect([html.is_error, html.code_model, html.intent]).to.deep.equal([true, "anthropic/m", null]);
    // Réponse 200 non JSON : pièce brute, rédigée quel que soit le type de média, is_error vrai (EX-8.7).
    const page = C.echangeModele({ format: "anthropic-messages", provider_label: "anthropic", requete: { corps: Buffer.from('{"model":"m","max_tokens":1,"messages":[]}'), content_type: "application/json" }, reponse: { status: 200, content_type: "Application/X-Inconnu; v=1", corps: Buffer.from("écrire à ops@exemple.ch") }, politique: PII });
    expect([page.pieces.reponse.octets.toString(), page.pieces.reponse.reference.media_type, page.pieces.reponse.reference.redacted, page.is_error]).to.deep.equal(["écrire à [REDIGE:email]", "application/x-inconnu", true, true]);
    const long = "a".repeat(4097);
    const r = C.echangeModele({ format: "openai-chat", provider_label: "openai", requete: { corps: Buffer.from('{"model":"m","messages":[]}'), content_type: "application/json" }, reponse: { status: 200, content_type: "application/json", corps: Buffer.from(JSON.stringify({ model: "m2", choices: [{ message: { content: long } }] })) }, politique: PII });
    expect([r.intent.length, r.intent.media_type, r.intent.redacted, r.code_model, r.prompt_version]).to.deep.equal([4097, "text/plain", false, "openai/m2", null]);
    const s = C.echangeSampling({ params: { messages: [], maxTokens: 10 }, resultat: { role: "assistant", content: { type: "text", text: "ok" }, model: "modele-hote" } });
    expect(s.code_model).to.equal("hote/modele-hote");
  });
});

// ---------------------------------------------------------------------------
describe("CT-2 : lecture d'une requête d'hôte, blancs, nombres, contexte (4.4 pas 1, EX-4.43 à EX-4.45)", function () {
  const ligne = (args, id = '"h"') => `{"jsonrpc":"2.0","id":${id},"method":"tools/call","params":{"name":"demo__x","arguments":${args}}}`;

  it("nombres : même valeur décimale que la forme JCS intégral, ou refus -32602 (EX-4.44)", function () {
    for (const t of ["0", "-0", "0.75", "1.0", "1e3", "1E+2", "-12.50", "9007199254740992", "0.1", "5e-324", "1.7976931348623157e308"]) expect(C.nombreExact(t), t).to.equal(true);
    for (const t of ["12345678901234567890", "9007199254740993", "0.10000000000000000001", "1e400", "3.141592653589793238"]) expect(C.nombreExact(t), t).to.equal(false);
    expect(C.textesDesNombres('{"a":[1,-2.5e3],"b":"7 8","c":{"d":0}}')).to.deep.equal(["1", "-2.5e3", "0"]);
    expect(C.lireRequeteHote(ligne('{"n":12345678901234567890}')).erreur).to.deep.equal({ code: -32602, message: "Invalid params", data: { reason: "nombre_non_representable" } });
    expect(C.lireRequeteHote(ligne('{"n":12345678901234567890}')).id).to.equal("h");
    expect(C.lireRequeteHote(ligne('{"n":1e400}'))).to.deep.equal({ erreur: { code: -32602, message: "Invalid params", data: { reason: "arguments_non_canonisables" } }, id: null });
    expect(C.lireRequeteHote(ligne('{"n":1.0,"m":1e3}')).msg.params.arguments).to.deep.equal({ n: 1, m: 1000 });
    // Un id au-delà de 2^53 n'est pas un argument : admis, recopié depuis le texte.
    expect(C.lireRequeteHote(ligne("{}", "12345678901234567890")).erreur).to.equal(undefined);
    expect(C.texteIdRequete(ligne("{}", "12345678901234567890"))).to.equal("12345678901234567890");
  });

  it("cadrage : CR refusé dans une ligne, admis dans un corps HTTP ; lot, requête mal formée, JSON invalide (EX-4.3, EX-4.43)", function () {
    expect(C.lireRequeteHote(ligne('{"a":1}\r'))).to.deep.equal({ erreur: { code: -32700, message: "Parse error", data: { reason: "cr_dans_la_ligne" } }, id: null });
    expect(C.lireRequeteHote(ligne('{"a":1}\r\n'), { cadrage: "corps" }).msg.params.arguments).to.deep.equal({ a: 1 });
    expect(C.lireRequeteHote(`[${ligne("{}")}]`).erreur).to.deep.equal({ code: -32600, message: "Invalid Request", data: { reason: "lot_non_pris_en_charge" } });
    expect(C.lireRequeteHote('{"jsonrpc":"1.0","id":1,"method":"x"}').erreur.code).to.equal(-32600);
    expect(C.lireRequeteHote("{pas du json").erreur.code).to.equal(-32700);
    expect(C.lireRequeteHote("[".repeat(200) + "]".repeat(200)).erreur.code).to.equal(-32700);
  });

  it("blancs non significatifs retirés des octets recopiés, valeurs inchangées (EX-4.43)", function () {
    const t = ' {\t"a" : [ 1.0 , "x y\\n" ] ,\r\n "b":{ } } ';
    expect(C.sansBlancs(t)).to.equal('{"a":[1.0,"x y\\n"],"b":{}}');
    expect(J.canonicaliserJCSIntegral(C.analyserJSONIntegral(C.sansBlancs(t)))).to.equal(J.canonicaliserJCSIntegral(C.analyserJSONIntegral(t)));
    const enchasse = `{"jsonrpc":"2.0","id":"h","method":"tools/call","params":{"name":"demo__x","arguments":{"q":\n{"jsonrpc":"2.0","id":"x","method":"tools/call","params":{"name":"y"}}\n}}}`;
    const amont = C.ligneAmontToolsCall(enchasse, { idAmont: "e-000000000001", nomOrigine: "x", protocolVersion: "2026-07-28" }).ligne;
    expect(amont).to.not.match(/[\r\n]/);
    expect(amont).to.include('"arguments":{"q":{"jsonrpc":"2.0","id":"x"');
  });

  it("contexte d'un appel : définition servie, définition courante si elle diffère, liste annoncée ; réglages (EX-4.45)", function () {
    const d1 = C.pieceDefinitionOutil({ name: "demo__x", description: "v1" });
    const d2 = C.pieceDefinitionOutil({ name: "demo__x", description: "v2" });
    const l = C.pieceListeAnnoncee([{ name: "demo__x", description: "v1" }]);
    expect(l.octets.toString()).to.equal('{"tools":[{"description":"v1","name":"demo__x"}]}');
    expect(C.contexteAppel({ servie: d1, courante: d1, liste: l }).map((c) => c.sha256)).to.deep.equal([d1.reference.sha256, l.reference.sha256]);
    expect(C.contexteAppel({ servie: d1, courante: d2, liste: l }).map((c) => c.sha256)).to.deep.equal([d1.reference.sha256, d2.reference.sha256, l.reference.sha256]);
    expect(C.contexteAppel({ servie: d1, courante: d2, liste: l, definitions: false }).map((c) => c.sha256)).to.deep.equal([l.reference.sha256]);
    expect(C.contexteAppel({ servie: d1, courante: d1, liste: l, listeDansContexte: false })).to.have.length(1);
    expect(C.contexteAppel({ servie: d1, liste: l }).every((c) => c.kind === "autre" && c.media_type === "application/json")).to.equal(true);
  });

  it("collision après gabarit et normalisation d'une connexion d'hôte : les deux outils sont rejetés (EX-4.11)", function () {
    const serveurs = [{ alias: "demo", tools: [{ name: "a.b" }, { name: "a_b" }, { name: "c" }] }];
    expect(C.agregerOutils(serveurs).announced).to.have.length(3);
    const r = C.agregerOutils(serveurs, { normalisations: [{ template: "{tool_announced}", sanitize: true }] });
    expect([r.announced.map((a) => a.announced), r.rejected.map((x) => [x.original, x.reason])]).to.deep.equal([["demo__c"], [["a.b", "collision"], ["a_b", "collision"]]]);
  });

  it("type de média et pièce brute : UTF-8 rédigé quel que soit le type, octets non UTF-8 en forme non rédigeable (EX-8.7)", function () {
    expect([C.typeDeMedia("Text/HTML; charset=UTF-8"), C.typeDeMedia(null), C.typeDeMedia(""), C.typeDeMedia("pas un type"), C.typeDeMedia("application/" + "x".repeat(130))]).to.deep.equal(["text/html", "application/octet-stream", "application/octet-stream", "application/octet-stream", "application/octet-stream"]);
    expect([C.estTypeJSON("application/json"), C.estTypeJSON("application/problem+json"), C.estTypeJSON("text/json")]).to.deep.equal([true, true, false]);
    const p = C.pieceBrute(Buffer.from("contact : a.b@example.ch"), { contentType: "application/x-propre", politique: PII, portee: "reponse" });
    expect([p.octets.toString(), p.reference.redacted, p.reference.media_type]).to.deep.equal(["contact : [REDIGE:email]", true, "application/x-propre"]);
    const intact = C.pieceBrute(Buffer.from("rien"), { contentType: "text/plain", politique: PII, portee: "reponse" });
    expect([intact.octets.toString(), intact.reference.redacted]).to.deep.equal(["rien", false]);
    const binaire = C.pieceBrute(Buffer.from([0xff, 0xfe, 0x00]), { contentType: "application/octet-stream", politique: PII, portee: "reponse" });
    expect([binaire.octets.toString(), binaire.reference.redacted, binaire.reference.media_type]).to.deep.equal(['{"noortrace_non_redigeable":{"content_type":"application/octet-stream","length":3,"reason":"non_utf8"}}', true, undefined]);
    const sansRegle = C.pieceBrute(Buffer.from([0xff]), { contentType: "image/png", politique: null, portee: "reponse" });
    expect([sansRegle.octets.length, sansRegle.reference.redacted, sansRegle.reference.media_type]).to.deep.equal([1, false, "image/png"]);
  });

  it("prompt laissé en place dans la requête (inline) : chaque chaîne rédigée par les règles prompt_systeme (EX-8.5)", function () {
    const corps = { model: "m", instructions: "Écrire à a@example.ch", input: [{ role: "developer", content: [{ type: "input_text", text: "IBAN CH9300762011623852957" }] }, { role: "user", content: "a@example.ch" }] };
    const r = C.redigerPromptEnPlace("openai-responses", corps, PII);
    expect([r.instructions, r.input[0].content[0].text, r.input[1].content]).to.deep.equal(["Écrire à [REDIGE:email]", "IBAN [REDIGE:iban]", "a@example.ch"]);
    expect(corps.instructions).to.equal("Écrire à a@example.ch", "l'entrée n'est pas modifiée");
    const e = C.echangeModele({ format: "openai-responses", provider_label: "openai", requete: { corps: Buffer.from(JSON.stringify(corps)), content_type: "application/json" }, reponse: { status: 200, content_type: "application/json", corps: Buffer.from('{"model":"m","output":[]}') }, politique: PII, prompt_in_request: "inline" });
    expect(e.pieces.prompt_systeme.octets.toString()).to.equal("Écrire à [REDIGE:email]\nIBAN [REDIGE:iban]");
    expect(C.analyserJSONIntegral(e.pieces.requete.octets).instructions).to.equal("Écrire à [REDIGE:email]");
  });

  it("données de flux malformées : ignorées et comptées, jamais d'exception (EX-5.27)", function () {
    const sse = (evs) => Buffer.from(evs.map((d) => `data: ${typeof d === "string" ? d : JSON.stringify(d)}\n\n`).join(""));
    const a = C.consoliderFlux("anthropic-messages", sse([{ type: "message_start", message: { id: "m", content: [] } }, { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "x" } }, { type: "content_block_start", index: 1.5, content_block: { type: "text" } }, { type: "content_block_start", index: 5, content_block: { type: "text" } }, { type: "content_block_start", index: 0, content_block: null }, { type: "content_block_stop", index: -1 }, "[1,2]", "pas du json", { type: "message_stop" }]));
    expect([a.forme.content, a.is_error, a.ignores]).to.deep.equal([[], false, 7]);
    const c = C.consoliderFlux("openai-chat", sse([{ id: "c", choices: null }, { id: "c", choices: [{ index: "0", delta: {} }, null, { index: 0, delta: { tool_calls: [{ index: -1 }, { index: 0, function: null, id: null }, { index: 0, id: "t", function: { name: "f", arguments: 7 } }] } }] }, "[DONE]"]));
    expect(c.forme.choices[0].message.tool_calls).to.deep.equal([{ index: 0, id: "t", type: "function", function: { name: "f", arguments: "" } }]);
    expect(c.is_error).to.equal(false);
    const r = C.consoliderFlux("openai-responses", sse([{ type: "response.in_progress", response: null }, { type: "response.output_item.done", output_index: "1", item: {} }, { type: "response.completed", response: { id: "r", status: "completed", output: [] } }]));
    expect([r.forme.status, r.ignores, r.is_error]).to.deep.equal(["completed", 2, false]);
  });
});

// ---------------------------------------------------------------------------
describe("CT-2 : schémas de configuration et de politique (validerSchema)", function () {
  it("la politique pii-v1 de §10.9 et l'exemple de configuration de §15.3 valident ; propertyNames et minProperties sont appliqués", function () {
    const pol = SCHEMAS[C.ID_SCHEMA_POLITIQUE_REDACTION];
    const conf = SCHEMAS[C.ID_SCHEMA_CONFIGURATION];
    expect(J.validerSchema(PII_DOC, pol, { registre: SCHEMAS })).to.deep.equal([]);
    expect(J.validerSchema(CONFIG, conf, { registre: SCHEMAS })).to.deep.equal([]);
    expect(J.validerSchema(lireJSON("redaction", "politique-pii-v1.json"), pol, { registre: SCHEMAS })).to.deep.equal([]);
    for (const f of ["politique-pseudonyme-test.json", "politique-regles-test.json"]) expect(J.validerSchema(lireJSON("redaction", f), pol, { registre: SCHEMAS }), f).to.deep.equal([]);
    // journal-demo/politique.json est figé (annexe B.6) : validé hors approval.rules, qui reste un tableau illustratif.
    const demo = lireJSON("evenements", "journal-demo", "politique.json");
    expect(Array.isArray(demo.approval.rules)).to.equal(true);
    const erreursDemo = J.validerSchema(demo, conf, { registre: SCHEMAS, fragment: "#/$defs/policy_set" });
    expect(erreursDemo.filter((e) => !(e.chemin === "/approval/rules" || e.chemin.startsWith("/approval/rules/")))).to.deep.equal([]);
    expect(erreursDemo.length, "le tableau illustratif n'est pas un document politique-approbation-v0").to.be.greaterThan(0);
    const sansServeur = C.copieJSON(CONFIG);
    sansServeur.policy.servers = {};
    expect(J.validerSchema(sansServeur, conf, { registre: SCHEMAS }).map((e) => e.message).join(" ")).to.include("moins de 1 membre");
    const aliasInvalide = C.copieJSON(CONFIG);
    aliasInvalide.policy.servers.SAP = aliasInvalide.policy.servers.sap;
    expect(J.validerSchema(aliasInvalide, conf, { registre: SCHEMAS }).some((e) => e.chemin === "/policy/servers/SAP")).to.equal(true);
    const motifInvalide = C.copieJSON(PII_DOC);
    motifInvalide.named_patterns["Nom-Invalide"] = { pattern: "x" };
    expect(J.validerSchema(motifInvalide, pol, { registre: SCHEMAS }).some((e) => e.chemin === "/named_patterns/Nom-Invalide")).to.equal(true);
    const secretClair = C.copieJSON(CONFIG);
    secretClair.signer.backend.pin = "1234";
    expect(J.validerSchema(secretClair, conf, { registre: SCHEMAS })).to.not.deep.equal([]);
    const cleInconnue = C.copieJSON(CONFIG);
    cleInconnue.tools.prefixe = true;
    expect(J.validerSchema(cleInconnue, conf, { registre: SCHEMAS }).some((e) => e.message === "membre non admis")).to.equal(true);
  });
});

// ---------------------------------------------------------------------------
describe("CT-2 révision 0.3 : codes d'erreur et résultats rendus par l'enregistreur (4.4, EX-4.24, EX-4.49)", function () {
  const MD2 = fs.readFileSync(path.join(SPEC, "CT-2-enregistreur.md"), "utf8");

  it("EX-4.24 : codes -31010 à -31017 sans -31015, hors de -32768 à -32000, messages ASCII « noortrace: » ; la table de 4.4 dit les mêmes", function () {
    expect(C.ERREURS).to.not.have.property("APPROBATION");
    const codes = Object.values(C.ERREURS).map((e) => e.code).sort((a, b) => b - a);
    expect(codes).to.deep.equal([-31010, -31011, -31012, -31013, -31014, -31016, -31017]);
    for (const [cle, e] of Object.entries(C.ERREURS)) {
      expect(e.code >= -32768 && e.code <= -32000, cle).to.equal(false);
      expect(e.message, cle).to.match(/^noortrace: [\x20-\x7e]+$/);
      // La ligne de la table de 4.4 porte ce code et ce message.
      expect(MD2, cle).to.include(`| \`${e.code}\` | \`${e.message}\` |`);
    }
    expect(MD2).to.include("| `-31015` | non attribué |");
    expect(Object.isFrozen(C.ERREURS) && Object.isFrozen(C.ERREURS.DELAI)).to.equal(true);
    // Ce que l'enregistreur peut émettre (EX-4.24) : ses codes, les codes JSON-RPC standard, -32020 à -32022.
    for (const c of [-31010, -31017, -32700, -32600, -32601, -32602, -32603, -32020, -32021, -32022]) expect(C.codeEmissible(c), String(c)).to.equal(true);
    for (const c of [-31015, -32000, -32001, -32010, -32015, -32019, -32002, -32042, -32023, -32099, 100, 408, 599, -31018, 1.5]) expect(C.codeEmissible(c), String(c)).to.equal(false);
    // Aucun littéral -3201x ne reste dans les bibliothèques.
    for (const f of ["capture.mjs", "approbation.mjs"]) expect(fs.readFileSync(path.join(PROJECT_ROOT, "scripts", "lib", f), "utf8"), f).to.not.match(/-3201[0-9]/);
  });

  it("EX-4.49 : la ligne rendue du signal d'approbation de l'annexe A (359 octets) et le refus par la politique, octet pour octet", function () {
    const signal = AP.resultatSignalApprobation("apr-1192", "en_attente");
    const ligne = C.ligneHoteResultatEnregistreur("h-77812-4", signal);
    expect(Buffer.byteLength(ligne)).to.equal(359);
    expect(MD2).to.include("```json\n" + ligne + "\n```");
    const refus = C.ligneHoteResultatEnregistreur(12345678901234567000, AP.resultatRefusPolitique(), { idHoteTexte: "12345678901234567890" });
    expect(refus).to.equal('{"jsonrpc":"2.0","id":12345678901234567890,"result":{"resultType":"complete","content":[{"type":"text","text":"noortrace: appel refuse par la politique"}],"isError":true,"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"noortrace-enregistreur","version":"0.1.0"}}}}');
    expect(C.ligneHoteResultatEnregistreur(7, AP.resultatRefusPolitique({ hoteModerne: false }))).to.equal('{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"noortrace: appel refuse par la politique"}],"isError":true,"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"noortrace-enregistreur","version":"0.1.0"}}}}');
  });
});

// ---------------------------------------------------------------------------
describe("CT-2 révision 0.3 : contrôle des motifs et budget de rédaction (EX-10.6, EX-10.23, EX-7.6)", function () {
  this.timeout(60_000);
  const politique = (motif, scopes = ["arguments", "resultat", "requete", "reponse", "prompt_systeme", "contexte"]) => C.chargerPolitique({ version: 0, name: "budget-v1", pseudonym_key: null, named_patterns: { m: { pattern: motif } }, rules: [{ id: "r-motif", scopes, tools: "*", detectors: [{ type: "regex", name: "m" }], action: { kind: "remplacer" } }] }, { schemas: SCHEMAS });
  const LONG = "1".repeat(80000) + "x";
  const duree = (fn) => {
    const t0 = process.hrtime.bigint();
    const v = fn();
    return [v, Number(process.hrtime.bigint() - t0) / 1e6];
  };

  it("EX-10.6 a) à c) : les motifs à retour arrière exponentiel connus (OWASP) sont refusés, dans l'ordre des règles ; tailles développées", function () {
    const regle = (motif) => /\(EX-10\.6 ([abc])\)/.exec(C.erreursMotifRE2(motif)[0] ?? "")?.[1] ?? null;
    for (const motif of ["^(a+)+$", "([a-zA-Z]+)*$", "(a|aa)+$", "(a|a?)+$", "(\\w|\\d)+$", "(?:[0-9]{4} ?){3}", "(a|aa){1,1000}$", "(a{1,1000}){1,1000}$", "((ab)+)?x", "(?:a|b)*?c", "(x+x+)+y"]) expect(regle(motif), motif).to.equal("a");
    for (const motif of ["(?:\\b)+x", "()+", "(?:^$)*a", "((?:\\B))?x"]) expect(regle(motif), motif).to.equal("b");
    // Ordre des règles : un motif en échec sur a) et b) donne a), sur b) et c) donne b).
    expect(regle("(?:\\b|\\B)+"), "a et b").to.equal("a");
    expect(regle("(?:\\b){1000}a"), "b et c").to.equal("b");
    for (const motif of ["[0-9]{1000}x", "(?:ab){501}", "a{1000}b{1}"]) expect(regle(motif), motif).to.equal("c");
    for (const motif of ["[0-9]+$", "a{2,1000}?", "ref=(X)?", "^(X)", "ref=([A-Z]+)-", "(?:ab)+", "((a))+", "\\b20[0-9]{2}-[0-9]{5}\\b", "(?P<a>x)|(?<b>y)|(?:z)", "(a|b)c", "[0-9]*[0-9]*[0-9]*x"]) expect(C.erreursMotifRE2(motif), motif).to.deep.equal([]);
    expect([C.tailleDeveloppeeMotif("\\b20[0-9]{2}-[0-9]{5}\\b"), C.tailleDeveloppeeMotif("a{2,1000}?"), C.tailleDeveloppeeMotif("[0-9]{1000}x"), C.tailleDeveloppeeMotif("(a|aa){1,1000}$"), C.tailleDeveloppeeMotif("(a{1,1000}){1,1000}$"), C.tailleDeveloppeeMotif("a{3,}"), C.tailleDeveloppeeMotif("a{0}"), C.tailleDeveloppeeMotif(".")]).to.deep.equal([12, 1000, 1001, 3001, 1000001, 4, 1, null]);
    // Une politique dont un motif nommé est refusé n'est pas chargée (EX-15.4 pas 3).
    expect(() => politique("^(a+)+$")).to.throw(C.ErreurConfiguration);
    expect(C.erreursPolitiqueRedaction({ version: 0, name: "x-v1", pseudonym_key: null, named_patterns: { m: { pattern: "(a|aa)+$" } }, rules: [] }).join(" ")).to.include("(EX-10.6 a)");
  });

  it("EX-10.23 : un motif admis mais polynomial ([0-9]+$) est borné par le budget ; exec, replace, split et matchAll sont interrompus sous node:vm (R10 NV-4 levé)", function () {
    const re = /[0-9]+$/gu;
    // La durée est bornée par rapport au budget (50 ms + 450 ms de marge), très en deçà d'une exécution non interrompue (plus de 4 s sur cette entrée, mesurée sous Node.js 22) : un dépassement constaté seulement en fin d'opération ne passerait pas.
    for (const [nom, fn] of [["exec", () => { re.lastIndex = 0; return re.exec(LONG); }], ["replace", () => LONG.replace(/[0-9]+$/gu, "T")], ["split", () => LONG.split(/[0-9]+$/u)], ["matchAll", () => [...LONG.matchAll(/[0-9]+$/gu)]], ["test", () => /[0-9]+$/u.test(LONG)], ["search", () => LONG.search(/[0-9]+$/u)], ["match", () => LONG.match(/[0-9]+$/u)], ["replaceAll", () => LONG.replaceAll(/[0-9]+$/gu, "T")]]) {
      const [r, ms] = duree(() => C.sousBudget(fn, 50));
      expect(r, nom).to.deep.equal({ ok: false });
      expect(ms, nom).to.be.below(50 + 450);
    }
    expect(C.sousBudget(() => 42, 50)).to.deep.equal({ ok: true, valeur: 42 });
    expect(C.sousBudget(() => 42, null)).to.deep.equal({ ok: true, valeur: 42 });
    expect(() => C.sousBudget(() => { throw new RangeError("autre"); }, 50)).to.throw(RangeError);
    expect(() => C.sousBudget(() => 1, 0)).to.throw(/budget/);
    expect(C.BUDGET_REDACTION_MS).to.equal(1000);
  });

  it("EX-10.23 opération 1 : rédaction d'une pièce au-delà du budget → pièce « non rédigeable » (budget_redaction), redacted vrai, sans media_type, note sans valeur", function () {
    const P = politique("[0-9]+$");
    const notes = [];
    const onDepassement = (n) => notes.push(n);
    const [p, ms] = duree(() => C.pieceJSON({ a: LONG }, { politique: P, portee: "arguments", budgetMs: 50, onDepassement }));
    expect(ms).to.be.below(50 + 450);
    expect(p.octets.toString()).to.equal(`{"noortrace_non_redigeable":{"content_type":null,"length":${LONG.length + 8},"reason":"budget_redaction"}}`);
    expect(p.reference).to.deep.equal({ sha256: J.sha256(p.octets), length: p.octets.length, redacted: true });
    expect(notes).to.deep.equal([{ event: "redaction_budget_exceeded", operation: "piece", scope: "arguments", rule: "r-motif" }]);
    expect(JSON.stringify(notes)).to.not.include("111");
    const t = C.pieceTexte(LONG, { politique: P, portee: "prompt_systeme", budgetMs: 50 });
    expect([t.octets.toString(), t.reference.media_type]).to.deep.equal([`{"noortrace_non_redigeable":{"content_type":null,"length":${LONG.length},"reason":"budget_redaction"}}`, undefined]);
    const b = C.pieceBrute(Buffer.from(LONG), { contentType: "text/plain; charset=utf-8", politique: P, portee: "resultat", budgetMs: 50 });
    expect([b.octets.toString(), b.reference.redacted, b.reference.media_type]).to.deep.equal([`{"noortrace_non_redigeable":{"content_type":"text/plain; charset=utf-8","length":${LONG.length},"reason":"budget_redaction"}}`, true, undefined]);
    // Pièce tirée d'un message JSON-RPC : length est la longueur du JCS intégral des arguments en clair (EX-8.7), calculé une fois avant la rédaction.
    const a = C.pieceArguments({ arguments: { a: LONG } }, { politique: P, budgetMs: 50 });
    expect(C.analyserJSONIntegral(a.octets).noortrace_non_redigeable.length).to.equal(Buffer.byteLength(J.canonicaliserJCSIntegral({ a: LONG })));
    expect(a.nonRedigeable).to.equal("budget_redaction");
    // Une requête de modèle : une seule opération pour la pièce « requête ».
    const e = C.echangeModele({ format: "anthropic-messages", provider_label: "demo", requete: { corps: Buffer.from(JSON.stringify({ model: "m", max_tokens: 1, messages: [{ role: "user", content: LONG }] })), content_type: "application/json" }, reponse: { status: 200, content_type: "application/json", corps: Buffer.from('{"id":"x","type":"message","role":"assistant","model":"m","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}') }, politique: P, budgetMs: 50 });
    expect(C.analyserJSONIntegral(e.pieces.requete.octets).noortrace_non_redigeable.reason).to.equal("budget_redaction");
    expect(e.pieces.reponse.octets.toString()).to.include('"text":"ok"');
    // Sous le budget par défaut, la même politique rédige une valeur courte comme avant.
    expect(C.pieceJSON({ a: "abc 12" }, { politique: P, portee: "arguments" }).octets.toString()).to.equal('{"a":"abc [REDIGE:m]"}');
  });

  it("EX-10.23 opérations 2 et 3 : extract d'un gabarit d'effets (effet omis), valeur en ligne (traitée comme une correspondance), effets déclarés par le SDK (omis)", function () {
    const notes = [];
    const g = C.evaluerGabaritsEffets([{ system: "S", action: "ecriture", object: "/arguments/a", extract: "[0-9]+$", amount: null, currency: null }, { system: "S", action: "ecriture", object: "fixe", amount: null, currency: null }], { arguments: { a: LONG }, budgetMs: 50, onDepassement: (n) => notes.push(n) });
    expect(g).to.deep.equal({ effects: [{ system: "S", action: "ecriture", object: "fixe", amount: null, currency: null }], notes: ["effet 0 : effect_omitted, budget_redaction"] });
    expect(notes).to.deep.equal([{ event: "redaction_budget_exceeded", operation: "extract", scope: null, rule: null }]);
    const P = politique("[0-9]+$", ["resultat"]);
    expect(C.examinerValeurEnLigne(P, LONG, { budgetMs: 50 })).to.deep.equal({ correspondance: true, depasse: true });
    expect(C.examinerValeurEnLigne(P, "run-2026-11-03-x")).to.deep.equal({ correspondance: false, depasse: false });
    // Toutes les règles, quelle que soit leur portée (EX-7.2) : la règle de portée resultat trouve le chiffre final.
    expect(C.examinerValeurEnLigne(P, "run-0142")).to.deep.equal({ correspondance: true, depasse: false });
    const Pa = politique("[0-9]+$", ["arguments"]);
    const sdk = C.effetsDeclares([{ system: "SAP", action: "ecriture", object: LONG, amount: null, currency: null }, { system: "SAP", action: "ecriture", object: "PAY-12", amount: "7400.00", currency: "CHF" }], { politique: Pa, budgetMs: 50 });
    expect(sdk.effects).to.deep.equal([{ system: "SAP", action: "ecriture", object: "PAY-[REDIGE:m]", amount: "7400.00", currency: "CHF" }]);
    expect(sdk.notes).to.deep.equal(["effet 0 : effect_omitted, budget_redaction"]);
    expect(C.effetsDeclares([{ system: "S", action: "x", object: "o", amount: "1", currency: null }]).notes).to.have.length(1);
  });

  it("EX-7.6 et EX-10.6 : extract compilé comme un motif nommé ((?P< réécrit en (?<) et contrôlé au démarrage", function () {
    const source = { arguments: { r: "ok ref=ABC-12" } };
    const avecP = C.evaluerGabaritsEffets([{ system: "S", action: "ecriture", object: "/arguments/r", extract: "ref=(?P<ref>[A-Z]+)", amount: null, currency: null }], source);
    const sansP = C.evaluerGabaritsEffets([{ system: "S", action: "ecriture", object: "/arguments/r", extract: "ref=(?<ref>[A-Z]+)", amount: null, currency: null }], source);
    expect(avecP.effects).to.deep.equal(sansP.effects);
    expect(avecP.effects[0].object).to.equal("ABC");
    expect(C.compilerExtract("ref=(?P<ref>[A-Z]+)").flags).to.equal("u");
    expect(C.erreursGabaritsEffets([{ extract: null }, { extract: "(?P<r>[A-Z]+)" }])).to.deep.equal([]);
    const e = C.erreursGabaritsEffets([{ extract: "(a+)+$" }, { extract: "." }, { extract: "x".repeat(1025) }], { ou: "/policy/servers/sap/tools/x/effects" });
    expect(e).to.have.length(3);
    expect(e[0]).to.include("/policy/servers/sap/tools/x/effects[0].extract").and.include("(EX-10.6 a)");
  });

  it("EX-10.6 : seules les ouvertures de groupe nommé (?P<nom> reconnues par l'analyse sont réécrites ; ailleurs, « (?P< » garde son sens (mêmes correspondances qu'en Go)", function () {
    const premiere = (motif, s) => C.compilerExtract(motif).exec(s)?.[0] ?? null;
    for (const motif of ["[(?P<]x", "a\\(?P<b", "\\(?P<x>", "\\\\(?P<x>a)"]) expect(C.erreursMotifRE2(motif), motif).to.deep.equal([]);
    expect(C.sourceECMAScript("[(?P<]x")).to.equal("[(?P<]x");
    expect(C.sourceECMAScript("a\\(?P<b")).to.equal("a\\(?P<b");
    expect(C.sourceECMAScript("\\\\(?P<x>a)")).to.equal("\\\\(?<x>a)");
    expect(C.sourceECMAScript("(?P<n>x)|(?P<m>[(?P<])")).to.equal("(?<n>x)|(?<m>[(?P<])");
    // Correspondances : celles du paquet regexp de Go sur le motif tel quel (redaction/motifs.json).
    expect(premiere("[(?P<]x", "Px")).to.equal("Px");
    expect([premiere("a\\(?P<b", "aP<b"), premiere("a\\(?P<b", "a<b")]).to.deep.equal(["aP<b", null]);
    expect(premiere("\\(?P<x>", "P<x>")).to.equal("P<x>");
    expect(premiere("\\\\(?P<x>a)", "\\a")).to.equal("\\a");
    expect(() => C.sourceECMAScript(".")).to.throw();
  });

  it("EX-10.6 point 5 : un quantificateur à zéro non significatif ({04}, {0,01}) est refusé ; RE2 et Go le liraient comme du texte", function () {
    for (const motif of ["a{01}", "[0-9]{04}", "a{0,01}", "a{1,01}", "a{00}", "[\\d-]{02}\\d"]) expect(C.erreursMotifRE2(motif), motif).to.deep.equal([`zéro non significatif dans un quantificateur (position ${motif.indexOf("{")})`]);
    for (const motif of ["a{0}", "a{0,0}", "a{0,}", "a{10,}", "a{1,1000}", "a{1000}"]) expect(C.erreursMotifRE2(motif), motif).to.deep.equal([]);
    expect(C.erreursMotifRE2("a{1,}x{")).to.deep.equal(["« { » qui n'ouvre pas un quantificateur (à échapper) (position 6)"]);
  });

  it("EX-10.23 quatrième opération : le contrôle des jetons de chaque motif nommé est borné ; au-delà, le motif est refusé (configuration refusée, sans blocage)", function () {
    const motif = "[^x]*".repeat(10) + "x";
    expect(C.erreursMotifRE2(motif)).to.deep.equal([]);
    const doc = { version: 0, name: "jetons-v1", pseudonym_key: null, named_patterns: { lent: { pattern: motif } }, rules: [{ id: "r", scopes: ["arguments"], tools: "*", detectors: [{ type: "regex", name: "lent" }], action: { kind: "remplacer" } }] };
    const [e, ms] = duree(() => C.erreursPolitiqueRedaction(doc, { budgetMs: 50 }));
    expect(e).to.deep.equal(["named_patterns.lent : motif trop coûteux sur les jetons (EX-10.23)"]);
    expect(ms).to.be.below(50 + 450);
    expect(() => C.chargerPolitique(doc, { budgetMs: 50 })).to.throw(C.ErreurConfiguration);
    // La même règle au démarrage d'une configuration : limits.redaction_budget_ms borne le contrôle (EX-15.4 pas 3).
    const conf = C.copieJSON(CONFIG);
    conf.limits.redaction_budget_ms = 50;
    conf.policy.redaction.named_patterns = { lent: { pattern: motif } };
    expect(AP.controlesConfiguration(conf, { schemas: SCHEMAS }).erreurs).to.deep.equal(["/policy/redaction : named_patterns.lent : motif trop coûteux sur les jetons (EX-10.23) (EX-10.6)"]);
    // Un motif rapide reste admis, et un motif qui fait correspondre un jeton est refusé comme avant.
    expect(C.erreursPolitiqueRedaction({ ...doc, named_patterns: { lent: { pattern: "[0-9]{3}-[0-9]{2}" } } }, { budgetMs: 50 })).to.deep.equal([]);
    expect(C.erreursPolitiqueRedaction({ ...doc, named_patterns: { lent: { pattern: "REDIGE" } } }, { budgetMs: 50 })[0]).to.include("fait correspondre le jeton [REDIGE:iban]");
  });

  it("EX-10.23 : la pièce « arguments » d'un appel d'écriture ou susceptible d'approbation au-delà du budget est un refus avant relais (-31010, raison redaction) ; une lecture suit son cours ; l'effet par défaut remplace un gabarit sans effet", function () {
    const P = politique("[0-9]+$");
    const a = C.pieceArguments({ arguments: { path: "/etc/cron.d/x", content: LONG } }, { politique: P, budgetMs: 50 });
    expect(a.nonRedigeable).to.equal("budget_redaction");
    const refus = { error: { code: -31010, message: "noortrace: appel bloque, enregistreur en mode degrade", data: { reason: "redaction" } } };
    const autorise = { rule: "r", decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null };
    const nouveau = { rule: "r", decision: "a_approuver", ticket: "apr-1", ticket_state: "nouveau", approval: null, approver_set: null };
    expect(C.refusArgumentsNonRedigeables(a, { classe: "ecriture", reponse: autorise })).to.deep.equal(refus);
    expect(C.refusArgumentsNonRedigeables(a, { classe: "lecture", susceptible: true, reponse: nouveau })).to.deep.equal(refus);
    expect(C.refusArgumentsNonRedigeables(a, { classe: "lecture", reponse: autorise })).to.equal(null);
    expect(C.refusArgumentsNonRedigeables(a, { classe: "ecriture", reponse: { ...autorise, decision: "refuse" } })).to.equal(null);
    expect(C.refusArgumentsNonRedigeables(a, { classe: "ecriture", reponse: { ...nouveau, ticket_state: "en_attente" } })).to.equal(null);
    expect(C.refusArgumentsNonRedigeables(C.pieceArguments({ arguments: { path: "/srv/x" } }, { politique: P }), { classe: "ecriture", reponse: autorise })).to.equal(null);
    // Effets (EX-7.6) : un gabarit qui ne résout rien parce qu'une pièce est non rédigeable donne l'effet par défaut d'un outil ecriture.
    const gabarit = [{ system: "FS", action: "ecriture", object: "/arguments/path", extract: null, amount: null, currency: null }];
    const defaut = C.effetsParDefaut({ classe: "ecriture", alias: "fichiers", original: "write_file" });
    const nr = C.evaluerGabaritsEffets(gabarit, { arguments: { path: "/srv/x" }, result: a.valeur, defaut });
    expect(nr.effects).to.deep.equal([{ system: "FS", action: "ecriture", object: "/srv/x", amount: null, currency: null }]);
    const vide = C.evaluerGabaritsEffets(gabarit, { arguments: a.valeur, result: null, defaut });
    expect(vide.effects).to.deep.equal(defaut);
    expect(vide.notes.at(-1)).to.include("effets par défaut");
    const extrait = C.evaluerGabaritsEffets([{ ...gabarit[0], extract: "[0-9]+$" }], { arguments: { path: LONG }, budgetMs: 50, defaut });
    expect(extrait.effects).to.deep.equal(defaut);
    // Sans pièce non rédigeable ni dépassement, un effet non résolu reste omis (EX-7.6).
    expect(C.evaluerGabaritsEffets(gabarit, { arguments: { autre: 1 }, defaut }).effects).to.deep.equal([]);
  });

  it("EX-4.47 : quotas par connexion d'hôte sur une minute glissante : requêtes en cours, octets reçus, octets de pièces, temps de capture ; -31013 de direction quota", function () {
    const q = new C.QuotaConnexion({ max_concurrent: 2, piece_bytes_per_minute: 1000, received_bytes_per_minute: 4096, redaction_ms_per_minute: 1500 });
    const quota = (data) => ({ code: -31013, message: "noortrace: taille maximale depassee", data: { ...data, direction: "quota" } });
    expect(q.admettre(0, 1000)).to.equal(null);
    expect(q.admettre(10, 1000)).to.equal(null);
    expect(q.admettre(20, 10)).to.deep.equal(quota({ limit_requests: 2 }));
    q.terminer();
    expect(q.admettre(30, 3000)).to.deep.equal(quota({ limit_bytes: 4096 }));
    expect(q.admettre(40, 100)).to.equal(null);
    q.terminer();
    q.terminer();
    // Une requête dont la pièce est la pièce non rédigeable écrit 96 octets mais coûte son temps de capture : le temps est compté.
    q.noter(50, { octetsPieces: 96, msCapture: 1600 });
    expect(q.admettre(60, 10)).to.deep.equal(quota({ limit_ms: 1500 }));
    q.noter(70, { octetsPieces: 2000, msCapture: 0 });
    // Une minute plus tard, la fenêtre a glissé.
    expect(q.admettre(60071, 10)).to.equal(null);
    expect(C.FENETRE_QUOTA_MS).to.equal(60000);
  });
});

// ---------------------------------------------------------------------------
describe("CT-2 révision 0.3 : configuration (15.3, EX-15.4 pas 2 à 4, EX-7.15)", function () {
  const MD2 = fs.readFileSync(path.join(SPEC, "CT-2-enregistreur.md"), "utf8");

  it("chaque bloc annoté <!-- schema: X --> ou <!-- schema: X/defs --> de CT-2 est conforme ($ref de policy.approval.rules résolu)", function () {
    const exemples = [...MD2.matchAll(/<!-- schema: ([a-z-]+)(?:\/([a-z_]+))? -->\n```json\n([\s\S]*?)\n```/g)];
    expect(exemples.length).to.be.at.least(5);
    const ids = { evenement: "evenement", "politique-redaction": "politique-redaction", "configuration-enregistreur": "configuration-enregistreur", ticket: "ticket", worm: "worm", "cout-agent": "cout-agent" };
    for (const [, nom, def, texte] of exemples) {
      const id = `https://noortrace.example/schemas/v0/${ids[nom]}.schema.json`;
      expect(SCHEMAS[id], nom).to.not.equal(undefined);
      const erreurs = J.validerSchema(JSON.parse(texte), SCHEMAS[id], def ? { registre: SCHEMAS, fragment: `#/$defs/${def}` } : { registre: SCHEMAS });
      expect(erreurs, `${nom}/${def ?? ""}`).to.deep.equal([]);
    }
    expect(exemples.some(([, nom, def]) => nom === "ticket" && def === "reponse_evaluer")).to.equal(true);
  });

  it("l'exemple de 15.3 passe les contrôles de démarrage : politique d'approbation valide en production, mode erreur, CANDIDATS ; avertissements seulement", function () {
    expect(CONFIG.policy.approval.mode).to.equal("erreur");
    expect(CONFIG.recorder.environment).to.equal("production");
    const rules = CONFIG.policy.approval.rules;
    expect(AP.erreursPolitique(rules, { schemas: SCHEMAS, environment: CONFIG.recorder.environment, expire_after_ms: CONFIG.policy.approval.expire_after_ms })).to.deep.equal([]);
    expect(AP.candidats(rules, ["fichiers__list_directory", "fichiers__read_file", "fichiers__write_file", "sap__claims.get", "sap__payments.create"])).to.deep.equal(["fichiers__write_file", "sap__payments.create"]);
    const r = AP.controlesConfiguration(CONFIG, { schemas: SCHEMAS });
    expect(r.erreurs).to.deep.equal([]);
    // Aucun avertissement : le demandeur fixe poste-cursor a son entrée dans separation.identities (CT-3 EX-4.14) ; « paiement hors CHF » (none sur egal) est une liste blanche, non signalée.
    expect(r.avertissements).to.deep.equal([]);
    expect(AP.demandeursFixes(CONFIG.mcp.hosts)).to.deep.equal(["poste-cursor"]);
    const sansIdentite = C.copieJSON(CONFIG);
    sansIdentite.policy.approval.rules.separation.identities = sansIdentite.policy.approval.rules.separation.identities.filter((e) => e.launched_by !== "poste-cursor");
    const av = AP.controlesConfiguration(sansIdentite, { schemas: SCHEMAS }).avertissements;
    expect([av.length, av[0]]).to.deep.equal([1, "/policy/approval/rules : /separation/identities : aucune entrée pour le demandeur poste-cursor ; la séparation des tâches n'est pas vérifiable pour lui (EX-10.5) (CT-3 EX-4.14)"]);
    // Pas 4 : clé du MAC de relais d'au moins 32 octets, distincte des autres clés.
    const cle = Buffer.alloc(32, 7);
    expect(AP.controlesConfiguration(CONFIG, { schemas: SCHEMAS, secrets: { relay_mac_key: cle, pseudonym_key: Buffer.alloc(32, 8) } }).erreurs).to.deep.equal([]);
    expect(AP.controlesConfiguration(CONFIG, { schemas: SCHEMAS, secrets: { relay_mac_key: Buffer.alloc(31, 7) } }).erreurs.join(" ")).to.include("/storage/relay_mac_key : au moins 32 octets");
    expect(AP.controlesConfiguration(CONFIG, { schemas: SCHEMAS, secrets: { relay_mac_key: cle, pseudonym_key: Buffer.from(cle) } }).erreurs.join(" ")).to.include("distincte de toute autre clé");
    expect(AP.controlesConfiguration(CONFIG, { schemas: SCHEMAS, secrets: { relay_mac_key: cle, autres: [Buffer.from(cle)] } }).erreurs).to.have.length(1);
    // Mode retenir : avertissement (CT-3 EX-11.1), et délai des hôtes connus (EX-11.2).
    const retenir = C.copieJSON(CONFIG);
    retenir.policy.approval.mode = "retenir";
    expect(AP.controlesConfiguration(retenir, { schemas: SCHEMAS, delaisHotesMs: [5000] }).avertissements.filter((a) => a.startsWith("/policy/approval/mode"))).to.have.length(2);
  });

  it("le schéma de configuration exige storage.relay_mac_key, désigne policy.approval.rules par $ref, exige mode (erreur dans la configuration de référence), un budget de rédaction d'au moins 1 ms et les quotas d'EX-4.47", function () {
    const conf = SCHEMAS[C.ID_SCHEMA_CONFIGURATION];
    const sansCle = C.copieJSON(CONFIG);
    delete sansCle.storage.relay_mac_key;
    expect(J.validerSchema(sansCle, conf, { registre: SCHEMAS }).length).to.be.greaterThan(0);
    expect(AP.controlesConfiguration(sansCle, { schemas: SCHEMAS }).erreurs.length).to.be.greaterThan(0);
    const tableau = C.copieJSON(CONFIG);
    tableau.policy.approval.rules = [];
    expect(J.validerSchema(tableau, conf, { registre: SCHEMAS }).length).to.be.greaterThan(0);
    // mode est requis par le schéma, sans valeur par défaut ; la configuration de référence écrit erreur (CT-3 EX-11.1).
    const sansMode = C.copieJSON(CONFIG);
    delete sansMode.policy.approval.mode;
    expect(J.validerSchema(sansMode, conf, { registre: SCHEMAS })).to.deep.equal([{ chemin: "/policy/approval", message: "membre obligatoire absent : mode" }]);
    expect(AP.controlesConfiguration(sansMode, { schemas: SCHEMAS }).erreurs).to.deep.equal(["/policy/approval : schéma : membre obligatoire absent : mode"]);
    expect(conf.$defs.policy_set.properties.approval.properties.mode).to.not.have.property("default");
    expect(JSON.stringify(conf)).to.not.include('"default"');
    expect(AP.MODE_ATTENTE_DEFAUT).to.equal("erreur");
    // limits.redaction_budget_ms : entier d'au moins 1 (EX-10.23) ; 0 est refusé au pas 2.
    const budgetNul = C.copieJSON(CONFIG);
    budgetNul.limits.redaction_budget_ms = 0;
    expect(AP.controlesConfiguration(budgetNul, { schemas: SCHEMAS }).erreurs.join(" ")).to.include("/limits/redaction_budget_ms");
    // Quotas d'EX-4.47 : octets reçus et temps de capture par minute, requis.
    const sansQuota = C.copieJSON(CONFIG);
    delete sansQuota.mcp.hosts[0].quota.redaction_ms_per_minute;
    expect(J.validerSchema(sansQuota, conf, { registre: SCHEMAS })).to.deep.equal([{ chemin: "/mcp/hosts/0/quota", message: "membre obligatoire absent : redaction_ms_per_minute" }]);
    // Pas 3 : règles sémantiques de CT-3 (contest_ms ≥ expire_after_ms) et extract hors des règles d'EX-10.6, refusés avant tout scellement.
    const contest = C.copieJSON(CONFIG);
    contest.policy.approval.rules.rules[3].contest_ms = contest.policy.approval.expire_after_ms;
    expect(AP.controlesConfiguration(contest, { schemas: SCHEMAS }).erreurs).to.deep.equal(["/policy/approval/rules/rules/3/contest_ms : contest_ms_trop_long (CT-3 EX-4.2, EX-8.2)"]);
    const statique = C.copieJSON(CONFIG);
    statique.policy.approval.rules.approver_set = { source: "statique", chain_id: null, registry: null, set: null, members: ["0x70997970c51812dc3a010c7d01b50e0d17dc79c8"], threshold: { required: 1, size: 1 } };
    expect(AP.controlesConfiguration(statique, { schemas: SCHEMAS }).erreurs).to.deep.equal(["/policy/approval/rules/approver_set/source : jeu_statique_en_production (CT-3 EX-4.2, EX-8.2)"]);
    const extract = C.copieJSON(CONFIG);
    extract.policy.servers.sap.tools["payments.create"].effects[0].extract = "(a+)+$";
    expect(AP.controlesConfiguration(extract, { schemas: SCHEMAS }).erreurs.join(" ")).to.include("/policy/servers/sap/tools/payments.create/effects[0].extract").and.include("(EX-10.6 a)");
    const motif = C.copieJSON(CONFIG);
    motif.policy.redaction.named_patterns = { ...(motif.policy.redaction.named_patterns ?? {}), lent: { pattern: "(x+x+)+y" } };
    expect(AP.controlesConfiguration(motif, { schemas: SCHEMAS }).erreurs.join(" ")).to.include("(EX-10.6 a)");
  });

  it("EX-7.15 : charger de l'exemple : approval sans service, requesters = launched_by fixes de mcp.hosts et sdk.hosts", function () {
    const outils = [
      { tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", class: "ecriture", effects: CONFIG.policy.servers.sap.tools["payments.create"].effects },
      { tool_announced: "fichiers__write_file", tool_original: "write_file", server_alias: "fichiers", class: "ecriture", effects: null },
    ];
    const m = AP.messageCharger({ org_id: CONFIG.recorder.org_id ?? "0x" + "00".repeat(32), journal_id: "0x" + "11".repeat(32), environment: CONFIG.recorder.environment, policy_version: CONFIG.policy.version, policy_sha256: C.empreinteEnsemblePolitique(CONFIG.policy).policy_sha256, approval: CONFIG.policy.approval, tools: outils, hotes: [...CONFIG.mcp.hosts, ...CONFIG.sdk.hosts] });
    expect(m.approval).to.not.have.property("service");
    expect(Object.keys(m.approval)).to.deep.equal(Object.keys(CONFIG.policy.approval).filter((k) => k !== "service"));
    expect(m.tools.map((t) => t.tool_announced)).to.deep.equal(["fichiers__write_file", "sap__payments.create"]);
    expect(m.requesters).to.deep.equal(["poste-cursor"]);
  });
});

// ---------------------------------------------------------------------------
describe("CT-2 : vecteurs spec/vecteurs/ct-2, rejoués", function () {
  this.timeout(120_000);
  const POLITIQUES = {
    "pii-v1": C.chargerPolitique(lireJSON("redaction", "politique-pii-v1.json"), { schemas: SCHEMAS }),
    "pii-pseudo-test": C.chargerPolitique(lireJSON("redaction", "politique-pseudonyme-test.json"), { schemas: SCHEMAS, clePseudonyme: CLE_PSEUDO }),
    "pii-regles-test": C.chargerPolitique(lireJSON("redaction", "politique-regles-test.json"), { schemas: SCHEMAS }),
  };
  const sansOctets = ({ bytes, ...ref }) => ref;
  const avecOctets = (p) => (p ? { ...p.reference, bytes: Buffer.from(p.octets).toString("utf8") } : null);

  it("jcs-integral/cas.json : chaque forme canonique, ou le refus", function () {
    const cas = lireJSON("jcs-integral", "cas.json");
    expect(cas.length).to.be.at.least(60);
    expect(cas.filter((c) => c.name.startsWith("rfc8785-b-") && c.name.length > 15 && /-[0-9a-f]{16}$/.test(c.name))).to.have.length(26);
    for (const c of cas) {
      let obtenu = null;
      try {
        obtenu = C.jcsIntegralDuTexte(c.input);
      } catch (err) {
        expect(err, c.name).to.be.instanceOf(J.ErreurFormat);
      }
      expect(obtenu, c.name).to.equal(c.canonical);
    }
  });

  it("redaction/ : politique pii-v1 octet pour octet, chaque pièce rédigée, ses correspondances, l'idempotence", function () {
    expect(lireTexte("redaction", "politique-pii-v1.json")).to.equal(blocs("CT-2-enregistreur.md", "politique-redaction")[0] + "\n");
    const cas = lireJSON("redaction", "cas.json");
    expect(cas.length).to.be.at.least(50);
    for (const c of cas) {
      const P = POLITIQUES[c.policy];
      const p = typeof c.input === "string" ? C.pieceTexte(c.input, { politique: P, portee: c.scope, outil: c.tool }) : C.pieceJSON(c.input, { politique: P, portee: c.scope, outil: c.tool });
      const attendu = { piece: p.octets.toString("utf8"), sha256: p.reference.sha256, length: p.reference.length, redacted: p.reference.redacted, ...(p.reference.media_type ? { media_type: p.reference.media_type } : {}), matches: p.correspondances };
      expect(attendu, c.name).to.deep.equal(c.expected);
      expect(J.verifierReference({ sha256: c.expected.sha256, length: c.expected.length, redacted: c.expected.redacted }, Buffer.from(c.expected.piece, "utf8")).ok, c.name).to.equal(true);
      const encore = typeof c.input === "string" ? C.pieceTexte(c.expected.piece, { politique: P, portee: c.scope, outil: c.tool }) : C.pieceJSON(C.analyserJSONIntegral(c.expected.piece), { politique: P, portee: c.scope, outil: c.tool });
      expect([encore.octets.toString(), encore.reference.redacted], `${c.name} : idempotence`).to.deep.equal([c.expected.piece, false]);
    }
    for (const portee of C.PORTEES) expect(cas.some((c) => c.scope === portee), portee).to.equal(true);
    // Sous-ensemble commun ECMAScript/RE2 (EX-10.6) : chaque motif admis ou refusé comme l'attendu.
    const motifs = lireJSON("redaction", "motifs.json");
    expect(motifs.length).to.be.at.least(25);
    for (const m of motifs) expect(C.erreursMotifRE2(m.pattern).length === 0, m.pattern).to.equal(m.admis);
    // Annexe B.3 (version 0.3) : les quatre motifs d'OWASP et les autres formes des règles a) à c) sont refusés, avec la règle dans la note ; [0-9]+$ est admis.
    for (const motif of ["^(a+)+$", "([a-zA-Z]+)*$", "(a|aa)+$", "(a|a?)+$", "(a|aa){1,1000}$", "(a{1,1000}){1,1000}$", "(\\w|\\d)+$", "(?:[0-9]{4} ?){3}", "(?:\\b)+x", "[0-9]{1000}x"]) {
      const m = motifs.find((x) => x.pattern === motif);
      expect(m, motif).to.not.equal(undefined);
      expect(m.admis, motif).to.equal(false);
      const regle = /^règle ([abc])\)/.exec(m.note)[1];
      expect(C.erreursMotifRE2(motif)[0], motif).to.include(`(EX-10.6 ${regle})`);
    }
    expect(motifs.find((x) => x.pattern === "[0-9]+$").admis).to.equal(true);
    expect(motifs.filter((x) => x.admis)).to.have.length(12);
    for (const m of motifs) expect(Object.keys(m)).to.deep.equal(m.matches ? ["pattern", "admis", "note", "matches"] : ["pattern", "admis", "note"]);
    // B.3 (version 0.3) : « (?P< » hors d'une ouverture de groupe nommé n'est pas réécrit ; matches donne la première correspondance de chaque texte (celle du paquet regexp de Go sur le motif tel quel).
    for (const motif of ["[(?P<]x", "a\\(?P<b", "\\(?P<x>", "\\\\(?P<x>a)"]) {
      const m = motifs.find((x) => x.pattern === motif);
      expect([m?.admis, m?.matches?.length > 0], motif).to.deep.equal([true, true]);
      for (const { input, first } of m.matches) expect(C.compilerExtract(motif).exec(input)?.[0] ?? null, `${motif} sur ${input}`).to.equal(first);
    }
    // Quantificateur à zéro non significatif : refusé.
    for (const motif of ["a{01}", "[0-9]{04}", "a{0,01}"]) expect(motifs.find((x) => x.pattern === motif)?.admis, motif).to.equal(false);
  });

  it("pieces-mcp/appels : liste servie, refus au pas 1, pièces, contexte, lignes relayées et rendues, durées, erreurs", function () {
    const lignes = (cas, f) => lireTexte("pieces-mcp", "appels", cas, f).split("\n").filter(Boolean).map((l) => JSON.parse(l));
    const appels = fs.readdirSync(path.join(VECTEURS, "pieces-mcp", "appels")).sort();
    expect(appels).to.include.members(["execute-ecriture", "resultat-is-error", "erreur-jsonrpc", "delai", "injoignable", "taille-depassee", "input-required", "hote-herite-serveur-moderne", "hote-moderne-serveur-herite", "arguments-non-entiers", "nombre-non-representable", "arguments-non-canonisables", "ligne-avec-cr", "lot-refuse", "blancs-non-significatifs", "corps-http-multiligne", "resultat-non-objet", "id-entier-long", "definition-servie-differente", "approbation-refus", "approbation-en-attente"]);
    const P = POLITIQUES["pii-v1"];
    for (const cas of appels) {
      const at = lireJSON("pieces-mcp", "appels", cas, "attendu.json");
      const hote = lignes(cas, "hote.jsonl");
      const amont = lignes(cas, "amont.jsonl");
      // L'échange tools/list qui sert la liste à la connexion d'hôte précède l'appel (EX-4.45).
      const liste = C.analyserJSONIntegral(hote[1].line).result.tools;
      expect(C.analyserJSONIntegral(hote[0].line).method, cas).to.equal("tools/list");
      const recue = hote[2];
      const lu = C.lireRequeteHote(recue.line, { cadrage: at.transports.host === "http" ? "corps" : "ligne" });
      // EX-4.24 : toute erreur rendue par l'enregistreur lui-même (refus au pas 1, message « noortrace: ») a un code qu'il peut émettre, jamais de -32000 à -32099 hors -32020 à -32022.
      if (at.error_rendered && (at.rejected || at.error_rendered.message.startsWith("noortrace:"))) expect(C.codeEmissible(at.error_rendered.code), `${cas} : code ${at.error_rendered.code}`).to.equal(true);
      // Annexe B.4 : approval et result_rendered après error_rendered, null hors des cas d'approbation.
      expect(Object.keys(at).slice(Object.keys(at).indexOf("error_rendered"), Object.keys(at).indexOf("error_rendered") + 3), cas).to.deep.equal(["error_rendered", "approval", "result_rendered"]);
      if (at.rejected) {
        expect([at.approval, at.result_rendered], cas).to.deep.equal([null, null]);
        expect(lu.erreur, `${cas} : refus`).to.deep.equal(at.error_rendered);
        expect(hote[3].line, `${cas} : erreur rendue`).to.equal(C.ligneHoteErreur(lu.id, lu.erreur, { idHoteTexte: lu.id === null ? null : C.texteIdRequete(recue.line) }));
        expect([amont, at.pieces, at.is_error, at.duration_ms], cas).to.deep.equal([[], null, null, null]);
        continue;
      }
      const requete = lu.msg;
      expect(requete.params.name, cas).to.equal(at.tool_announced);
      expect(C.resoudreNomAnnonce(at.tool_announced), cas).to.deep.equal({ alias: at.server_alias, original: at.tool_original });
      const args = C.pieceArguments(requete.params, { politique: P, outil: at.tool_announced });
      expect(avecOctets(args), `${cas} : arguments`).to.deep.equal(at.pieces.arguments);
      const servie = C.pieceDefinitionOutil(liste.find((d) => d.name === at.tool_announced));
      const pListe = C.pieceListeAnnoncee(liste);
      expect(avecOctets(servie), `${cas} : définition servie`).to.deep.equal(at.pieces.definition);
      expect(avecOctets(pListe), `${cas} : liste annoncée`).to.deep.equal(at.pieces.list);
      const courante = at.pieces.definition_current ? C.pieceDefinitionOutil(C.analyserJSONIntegral(at.pieces.definition_current.bytes)) : servie;
      expect(C.contexteAppel({ servie, courante, liste: pListe }), `${cas} : contexte`).to.deep.equal(at.context);
      if (at.approval !== null) {
        // Issue d'une politique d'approbation sans relais (4.4 pas 5 et 6, EX-4.49) : réponse d'evaluer conforme, résultat rendu par l'enregistreur.
        expect(AP.erreursSchema(at.approval.response, SCHEMAS, "reponse_evaluer"), cas).to.deep.equal([]);
        const hoteModerne = at.protocols.host === "2026-07-28";
        const action = AP.actionMandataire(at.approval.response, { hoteModerne });
        expect(action.action, cas).to.equal("resultat");
        expect(JSON.stringify(at.result_rendered), `${cas} : résultat rendu`).to.equal(JSON.stringify(action.result));
        expect(hote[3].line, `${cas} : ligne rendue`).to.equal(C.ligneHoteResultatEnregistreur(requete.id, action.result, { idHoteTexte: C.texteIdRequete(recue.line) }));
        expect(Object.hasOwn(at.result_rendered, "resultType"), cas).to.equal(hoteModerne);
        expect([at.result_rendered.isError, Object.hasOwn(at.result_rendered, "structuredContent")], cas).to.deep.equal([true, false]);
        expect([amont, at.pieces.result, at.is_error, at.duration_ms, at.error_rendered], cas).to.deep.equal([[], null, null, null, null]);
        continue;
      }
      expect(at.result_rendered, cas).to.equal(null);
      expect(at.class, cas).to.equal(C.classeOutil({ annotations: C.analyserJSONIntegral(Buffer.from(courante.octets)).annotations, configurationOutil: at.server_alias === "demo" ? { class: { "claims.get": "lecture", "claims.search": "lecture", "payments.create": "ecriture" }[at.tool_original] } : null }));
      const envoi = amont.find((l) => l.dir === "out" && C.analyserJSONIntegral(l.line).method === "tools/call");
      const idAmont = C.analyserJSONIntegral(envoi.line).id;
      const capacites = requete.params._meta?.["io.modelcontextprotocol/clientCapabilities"] ?? {};
      expect(C.ligneAmontToolsCall(recue.line, { idAmont, nomOrigine: at.tool_original, protocolVersion: at.protocols.server, clientCapabilities: capacites }).ligne, `${cas} : ligne amont`).to.equal(envoi.line);
      expect(envoi.line, `${cas} : ligne amont sans CR ni LF`).to.not.match(/[\r\n]/);
      const reponse = amont.find((l) => l.dir === "in" && l.line && C.analyserJSONIntegral(l.line).id === idAmont);
      const fin = amont.find((l) => l.dir === "in" && l.eof === true);
      const idTexte = C.texteIdRequete(recue.line);
      let resultat;
      let tReponse;
      if (at.error_rendered && at.error_rendered.code <= -31010 && at.error_rendered.code >= -31017) {
        const cle = Object.keys(C.ERREURS).find((k) => C.ERREURS[k].code === at.error_rendered.code);
        resultat = C.pieceErreurEnregistreur(cle, at.error_rendered.data, { politique: P });
        expect(hote[3].line, `${cas} : erreur rendue`).to.equal(C.ligneHoteErreur(requete.id, at.error_rendered, { idHoteTexte: idTexte }));
        // Issues sans réponse (EX-4.48) : délai, fin de fichier, borne de taille.
        if (cle === "DELAI") {
          tReponse = J.msHorodatage(envoi.t) + at.timeout_ms;
          expect(J.msHorodatage(amont.find((l) => l.line && C.analyserJSONIntegral(l.line).method === "notifications/cancelled").t)).to.equal(tReponse);
        } else if (cle === "INJOIGNABLE") tReponse = J.msHorodatage(fin.t);
        else tReponse = J.msHorodatage(reponse.t);
      } else {
        resultat = C.pieceResultatMCP(C.analyserJSONIntegral(reponse.line), { politique: P });
        expect(hote[3].line, `${cas} : réponse rendue`).to.equal(C.ligneHoteReponse(reponse.line, { idHote: requete.id, idHoteTexte: idTexte, hoteModerne: at.protocols.host === "2026-07-28" }));
        tReponse = J.msHorodatage(reponse.t);
      }
      expect(tReponse - J.msHorodatage(envoi.t), `${cas} : durée`).to.equal(at.duration_ms);
      expect([avecOctets(resultat), resultat.is_error], `${cas} : résultat`).to.deep.equal([at.pieces.result, at.is_error]);
      expect(J.msHorodatage(hote[3].t)).to.be.greaterThan(J.msHorodatage(envoi.t));
    }
  });

  it("pieces-mcp/agregation : noms annoncés, rejets, classes, empreintes des définitions, pages ; préfixe désactivé", function () {
    const at = lireJSON("pieces-mcp", "agregation", "attendu.json");
    const r = C.agregerOutils(lireJSON("pieces-mcp", "agregation", "serveurs.json"), { prefix: at.prefix, page_size: at.page_size });
    expect(r.announced.map(({ server_alias, original, announced, class: classe, definition }) => ({ server_alias, original, announced, class: classe, definition_sha256: C.pieceDefinitionOutil(definition).reference.sha256 }))).to.deep.equal(at.announced);
    expect(r.rejected).to.deep.equal(at.rejected);
    expect(r.pages).to.deep.equal(at.pages);
    expect(new Set(at.rejected.map((x) => x.reason))).to.deep.equal(new Set(["nom_reserve", "nom_invalide", "collision"]));
    const refus = lireJSON("pieces-mcp", "agregation", "sans-prefixe", "attendu.json");
    expect(refus.configuration_refusee).to.equal(true);
    expect(() => C.agregerOutils(lireJSON("pieces-mcp", "agregation", "sans-prefixe", "serveurs.json"), { prefix: false })).to.throw(C.ErreurConfiguration);
    const un = lireJSON("pieces-mcp", "agregation", "sans-prefixe-un-serveur", "attendu.json");
    const r1 = C.agregerOutils(lireJSON("pieces-mcp", "agregation", "sans-prefixe-un-serveur", "serveurs.json"), { prefix: false, page_size: un.page_size });
    expect([r1.announced.map((a) => a.announced), r1.rejected]).to.deep.equal([un.announced.map((a) => a.announced), un.rejected]);
    const n = lireJSON("pieces-mcp", "agregation", "normalisation", "attendu.json");
    const rn = C.agregerOutils(lireJSON("pieces-mcp", "agregation", "normalisation", "serveurs.json"), { prefix: n.prefix, page_size: n.page_size, normalisations: n.normalisations });
    expect([rn.announced.map((a) => a.announced), rn.rejected, rn.pages]).to.deep.equal([n.announced.map((a) => a.announced), n.rejected, n.pages]);
  });

  it("pieces-modele : formes consolidées, pièces, code.model, prompt_version, intention, appels d'outils, refus", function () {
    // Les cas gemini-* (révision 0.5) sont rejoués par test/enregistreur-r05.test.js (échange de la passerelle, EX-5.28 à EX-5.36).
    const cas = fs.readdirSync(path.join(VECTEURS, "pieces-modele")).filter((n) => !n.startsWith("gemini-")).sort();
    expect(cas).to.have.length(15);
    for (const nom of cas) {
      const at = lireJSON("pieces-modele", nom, "attendu.json");
      const brut = fs.existsSync(path.join(VECTEURS, "pieces-modele", nom, "requete.brut"));
      const corpsRequete = fs.readFileSync(path.join(VECTEURS, "pieces-modele", nom, brut ? "requete.brut" : "requete.json"));
      if (at.refused) {
        const r = C.echangeModele({ format: at.format, provider_label: at.provider_label, requete: { corps: corpsRequete, content_type: "application/json" }, reponse: null, politique: POLITIQUES["pii-v1"], prompt_in_request: at.options.prompt_in_request });
        expect({ status: r.refus.status, reason: r.refus.raison, body: r.refus.corps }, nom).to.deep.equal(at.refused);
        expect([at.pieces, fs.existsSync(path.join(VECTEURS, "pieces-modele", nom, "reponse-entetes.json"))], nom).to.deep.equal([null, false]);
        continue;
      }
      const entetes = lireJSON("pieces-modele", nom, "reponse-entetes.json");
      const flux = fs.existsSync(path.join(VECTEURS, "pieces-modele", nom, "reponse.sse"));
      const r = C.echangeModele({
        format: at.format,
        provider_label: at.provider_label,
        requete: { corps: corpsRequete, content_type: "application/json" },
        reponse: { status: entetes.status, content_type: entetes["content-type"], corps: fs.readFileSync(path.join(VECTEURS, "pieces-modele", nom, flux ? "reponse.sse" : "reponse.json")) },
        politique: POLITIQUES["pii-v1"],
        prompt_in_request: at.options.prompt_in_request,
      });
      expect(J.canonicaliserJCSIntegral(r.consolidated), `${nom} : forme consolidée`).to.equal(J.canonicaliserJCSIntegral(at.consolidated));
      expect({ request: avecOctets(r.pieces.requete), response: avecOctets(r.pieces.reponse), system_prompt: avecOctets(r.pieces.prompt_systeme), intent: avecOctets(r.pieces.intention) }, `${nom} : pièces`).to.deep.equal(at.pieces);
      expect([r.code_model, r.prompt_version, r.intent, r.is_error, r.incomplete], nom).to.deep.equal([at.code_model, at.prompt_version, at.intent, at.is_error, at.incomplete]);
      expect(J.canonicaliserJCSIntegral(r.tool_calls), `${nom} : appels`).to.equal(J.canonicaliserJCSIntegral(at.tool_calls));
      if (at.pieces.system_prompt) expect(at.prompt_version).to.equal(at.pieces.system_prompt.sha256);
      if (flux) expect(lireTexte("pieces-modele", nom, "reponse.sse")).to.not.include("\r");
    }
  });

  it("evenements/journal-demo : chaîne, attendus, pièces, politique, intention, segment ; arguments de seq 7 = pieces-mcp", function () {
    const R = ["evenements", "journal-demo"];
    const evs = lireJSON(...R, "evenements.json");
    const at = lireJSON(...R, "attendu.json");
    const cles = lireJSON(...R, "cles.json");
    expect(J.verifierChaine(evs, { clesPubliques: cles })).to.deep.equal({ valide: true, diagnostics: [] });
    expect(evs.map((e) => ({ seq: e.seq, tool: e.execution.tool, prev_hash: e.prev_hash, hash: e.hash, sig: e.sig, canonical_length: J.octetsJCS(J.corpsEvenement(e)).length }))).to.deep.equal(at.events);
    expect(evs.map((e) => e.execution.tool)).to.deep.equal(["noortrace.journal.politique", "noortrace.modele.echange", "demo__claims.get", "noortrace.modele.echange", "demo__payments.create", "noortrace.approbation.decision", "demo__payments.create", "noortrace.modele.echange"]);
    for (const ev of evs) expect(Object.entries(J.controlesEvenement(ev, { schemas: SCHEMAS, cles })).filter(([, x]) => x.ok === false), `seq ${ev.seq}`).to.deep.equal([]);
    expect(J.condenseApprobation(at.A)).to.equal(at.D_A);
    expect(at.A.request_hash).to.equal(evs[4].hash);
    const pieces = new Map(lireJSON(...R, "pieces.json").map((p) => [p.sha256, p]));
    for (const ev of evs) {
      for (const { chemin, ref } of J.referencesEvenement(ev)) {
        if (ref.value !== undefined) continue;
        const p = pieces.get(ref.sha256);
        expect(p, `seq ${ev.seq} ${chemin}`).to.not.equal(undefined);
        expect(J.verifierReference(ref, Buffer.from(p.bytes, "utf8")).ok, `seq ${ev.seq} ${chemin}`).to.equal(true);
        expect(p.media_type ?? undefined).to.equal(ref.media_type);
      }
      if (ev.code.prompt_version) expect(J.sha256(Buffer.from(pieces.get(ev.code.prompt_version).bytes, "utf8"))).to.equal(ev.code.prompt_version);
    }
    const politique = C.empreinteEnsemblePolitique(lireJSON(...R, "politique.json"));
    expect([politique.policy_sha256, politique.policy_version, politique.octets.length]).to.deep.equal([at.policy_sha256, at.policy_version, at.policy_length]);
    expect(evs[0].execution.arguments.value).to.deep.equal({ policy_version: at.policy_version, policy_sha256: at.policy_sha256 });
    expect(evs.every((e) => e.code.policy_version === at.policy_version)).to.equal(true);
    expect(pieces.get(at.policy_sha256).bytes).to.equal(politique.octets.toString("utf8"));
    const intentions = lireTexte(...R, "intentions.ndjson").split("\n");
    expect(C.empreinteIntention(intentions[0])).to.equal(at.intention_sha256);
    const ligneIntention = JSON.parse(intentions[0]);
    expect([Object.keys(ligneIntention).length, ligneIntention.intent_id, ligneIntention.upstream_id, ligneIntention.host, ligneIntention.ticket]).to.deep.equal([9, at.intent_id, "e-000000000004", "agent-demo", "apr-demo-0001"]);
    expect(ligneIntention.arguments).to.deep.equal(evs[6].execution.arguments);
    expect(C.lireJournalIntention(intentions.join("\n"))).to.have.length(1);
    expect(C.reprise(intentions.join("\n"), evs)).to.deep.equal([]);
    const segment = lireTexte(...R, "segment.ndjson");
    const entete = C.analyserJSONIntegral(segment.split("\n")[0]);
    expect(segment).to.equal(C.segment(entete, evs));
    expect([entete.epoch, entete.first_seq, J.sha256(Buffer.from(segment, "utf8"))]).to.deep.equal([1, 1, at.segment_sha256]);
    // Signal d'approbation rendu pour seq 5 en mode erreur (EX-4.49) : hôte moderne, ticket de la retenue, en_attente ; plus d'erreur -32015 (version 0.2).
    expect(Object.hasOwn(at, "error_rendered_seq_5")).to.equal(false);
    expect(JSON.stringify(at.result_rendered_seq_5)).to.equal(JSON.stringify(AP.resultatSignalApprobation(evs[4].policy.ticket, "en_attente", { hoteModerne: true, recorder: evs[4].code.recorder })));
    expect(at.result_rendered_seq_5.content[0].text).to.equal(`noortrace: appel soumis a approbation ; ticket=${evs[4].policy.ticket} ; state=en_attente`);
    expect(evs[4].execution.result).to.equal(null);
    const mcp = lireJSON("pieces-mcp", "appels", "execute-ecriture", "attendu.json");
    expect(sansOctets(mcp.pieces.arguments)).to.deep.equal(evs[6].execution.arguments);
    expect(sansOctets(mcp.pieces.result)).to.deep.equal(evs[6].execution.result);
    expect(mcp.context).to.deep.equal(evs[6].context);
    const ligneAppel = JSON.parse(lireTexte("pieces-mcp", "appels", "execute-ecriture", "hote.jsonl").split("\n")[2]).line;
    expect(C.pieceArguments({ arguments: C.analyserJSONIntegral(ligneAppel).params.arguments }, { politique: POLITIQUES["pii-v1"], outil: "demo__payments.create" }).octets.toString()).to.equal(mcp.pieces.arguments.bytes);
    // Corrélation recalculée depuis les entrées brutes (EX-5.22) ; seq 7 reprend de seq 5 intent, code et policy (EX-7.12).
    const entrees = lireJSON(...R, "entrees.json");
    const registre = [];
    for (const e of entrees.exchanges) {
      const r = C.echangeModele({ format: e.format, provider_label: e.provider_label, requete: { corps: Buffer.from(J.texteJSON(e.request), "utf8"), content_type: "application/json" }, reponse: { status: 200, content_type: e.response_content_type, corps: Buffer.from(e.response_body, "utf8") }, politique: POLITIQUES["pii-v1"] });
      const ev = evs[e.seq - 1];
      expect([ev.execution.arguments, ev.execution.result, ev.intent, ev.code.model, ev.code.prompt_version], `seq ${e.seq}`).to.deep.equal([r.pieces.requete.reference, r.pieces.reponse.reference, r.intent, r.code_model, r.prompt_version]);
      registre.push({ seq: e.seq, t: J.msHorodatage(e.t_complet), run_id: e.run_id, groupe: e.host_group, format: e.format, forme: r.forme, forme_redigee: r.forme_redigee });
    }
    const options = { fenetre_ms: at.correlation.window_ms, template: at.correlation.tool_name_template, sanitize: at.correlation.tool_name_sanitize };
    for (const a of entrees.calls) {
      const ev = evs[a.seq - 1];
      const attendu = at.correlation.calls.find((c) => c.seq === a.seq);
      if (a.inherits_from_seq !== null) {
        const source = evs[a.inherits_from_seq - 1];
        expect([ev.intent, ev.code, ev.policy.rule, ev.policy.decision, ev.policy.ticket], `seq ${a.seq} hérite`).to.deep.equal([source.intent, source.code, source.policy.rule, source.policy.decision, source.policy.ticket]);
        continue;
      }
      const msg = C.lireRequeteHote(a.host_line).msg;
      const c = C.correler({ tool_announced: msg.params.name, arguments: msg.params.arguments, t_recu: J.msHorodatage(a.t_recu), run_id: a.run_id, groupe: a.host_group }, registre, options);
      expect([c.echange?.seq ?? null, c.appel?.id ?? null], `seq ${a.seq} corrélé`).to.deep.equal([attendu.exchange_seq, attendu.tool_call_id]);
      expect(C.intentionRedigee(c.texte, c.texteClair).intent, `seq ${a.seq} intent`).to.deep.equal(ev.intent);
    }
    // Effets évalués sur les valeurs rédigées des pièces (EX-7.6).
    const pol = lireJSON(...R, "politique.json");
    const valeur = (ref) => C.analyserJSONIntegral(pieces.get(ref.sha256).bytes);
    expect(C.evaluerGabaritsEffets(pol.servers.demo.tools["payments.create"].effects, { arguments: valeur(evs[6].execution.arguments), result: valeur(evs[6].execution.result) }).effects).to.deep.equal(evs[6].effects);
  });

  it("evenements/journal-demo/dossier-seq-7 : dossier CT-1 valide par verifierDossier et par scripts/verify/dossier.mjs (code 0)", function () {
    const repertoire = path.join(VECTEURS, "evenements", "journal-demo", "dossier-seq-7");
    const fichiers = Object.fromEntries(fs.readdirSync(repertoire).filter((f) => f !== "attendu.json").map((f) => [f, fs.readFileSync(path.join(repertoire, f))]));
    const rapport = J.verifierDossier(fichiers, { schemas: SCHEMAS });
    expect([rapport.valide, J.controlesEnEchec(rapport), rapport.nonExecutesBloquants]).to.deep.equal([true, [], []]);
    expect(rapport.evenement.seq).to.equal(7);
    const r = lancer(["verify", "dossier.mjs"], [repertoire]);
    expect(r.code, r.stderr + r.stdout).to.equal(0);
    expect(r.stdout).to.include("VALIDE");
  });

  it("rejouer scripts/vecteurs/generer-ct2.mjs produit exactement les mêmes fichiers que spec/vecteurs/ct-2", function () {
    const sortie = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-vecteurs-ct2-"));
    const r = lancer(["vecteurs", "generer-ct2.mjs"], ["--sortie", sortie]);
    expect(r.code, r.stderr).to.equal(0);
    const lister = (racine) => {
      const out = [];
      const marcher = (d) => {
        for (const e of fs.readdirSync(d, { withFileTypes: true })) {
          const p = path.join(d, e.name);
          if (e.isDirectory()) marcher(p);
          else out.push(path.relative(racine, p));
        }
      };
      marcher(racine);
      return out.sort();
    };
    // Seules les entrées que le générateur possède sont comparées : le vérificateur Go vit à côté.
    const produits = lister(sortie);
    const possedees = new Set(produits.map((f) => f.split(path.sep)[0]));
    const attendus = lister(VECTEURS).filter((f) => possedees.has(f.split(path.sep)[0]));
    expect(produits).to.deep.equal(attendus);
    expect(produits.length).to.be.at.least(100);
    expect(possedees.has("verificateur-independant")).to.equal(false);
    for (const f of produits) expect(J.sha256(fs.readFileSync(path.join(sortie, f))), f).to.equal(J.sha256(fs.readFileSync(path.join(VECTEURS, f))));
    fs.rmSync(sortie, { recursive: true, force: true });
    const index = lireTexte("INDEX.md");
    for (const d of fs.readdirSync(path.join(VECTEURS, "pieces-modele"))) expect(index, d).to.include(`\`${d}/\``);
    for (const d of fs.readdirSync(path.join(VECTEURS, "pieces-mcp", "appels"))) expect(index, d).to.include(`\`${d}/\``);
  });
});
