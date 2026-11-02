// Tests unitaires de l'API publique de @noortrace/noyau et de ses refus :
// entrées mal formées, types, bornes, et tout ce que les vecteurs de CT-1
// n'exercent pas (exemple de référence de la spécification, équation de
// vérification Ed25519 sans cofacteur, refus des encodages non canoniques,
// dates inexistantes, validateur de schémas, parties absentes ou en trop d'un
// dossier, lecture d'un répertoire, pureté du paquet).
//
// L'exemple de référence (journal-principal, annexe A de CT-1) est lu dans le
// texte même de la spécification : ses blocs annotés <!-- schema: … --> sont
// extraits, validés contre leur schéma et recalculés.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import * as N from "@noortrace/noyau";
import { lireRepertoireDossier, verifierRepertoireDossier } from "@noortrace/noyau/dossier-fichiers";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SPEC = fs.readFileSync(path.join(RACINE, "spec", "CT-1-evenements-et-formats.md"), "utf8");
const PAQUET = path.join(RACINE, "paquets", "noyau");

// Blocs JSON annotés de CT-1, dans l'ordre du texte.
const BLOCS = [...SPEC.matchAll(/<!-- schema: (\S+) -->\n```json\n([\s\S]*?)\n```/g)].map((m) => ({ schema: m[1], valeur: N.analyserJson(m[2]) }));
const blocs = (nom) => BLOCS.filter((b) => b.schema === nom).map((b) => b.valeur);

const graine = (id) => N.sha256(N.utf8(`noortrace/vecteurs/v0/cle-enregistreur/${id}`));
const G1 = graine("rec-test-01");
const G2 = graine("rec-test-02");
const COMPTES = [
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
  "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
].map((h) => N.hexVersOctets(h, 32));

// Les cinq événements de l'exemple de référence (annexe A et §5.5), par seq.
const EXEMPLE = new Map(blocs("evenement").map((e) => [e.seq, e]));
const ev = (s) => structuredClone(EXEMPLE.get(s));
const D5 = [1, 2, 3, 4, 5].map((s) => EXEMPLE.get(s).hash);
const [MANIFESTE_1, MANIFESTE_2] = blocs("manifeste");
const CLES_EXEMPLE = blocs("cles")[0];
const enFichier = (objet) => N.utf8(JSON.stringify(objet, null, 2) + "\n");

/** Dossier de référence de CT-1 §11.1 et §11.2, assemblé depuis les exemples du texte. */
function dossierDeReference({ points = false, attestation = false } = {}) {
  const fichiers = new Map([
    ["evenement.json", enFichier(ev(4))],
    ["voisins.json", enFichier({ version: 0, previous: ev(3), next: ev(5) })],
    ["chemin.json", enFichier(blocs("chemin")[0])],
    ["manifeste.json", enFichier(MANIFESTE_1)],
    ["manifeste.sig", enFichier(blocs("manifeste_sig")[0])],
    ["cles.json", enFichier(CLES_EXEMPLE)],
    ["approbations.json", enFichier(blocs("approbations")[0])],
  ]);
  if (points) fichiers.set("points-de-controle.json", enFichier(blocs("points_de_controle")[0]));
  if (attestation) fichiers.set("attestation-perimetre.json", enFichier(blocs("attestation_perimetre")[0]));
  const index = N.indexerDossier({
    event: { seq: 4, hash: EXEMPLE.get(4).hash },
    org_id: EXEMPLE.get(4).org_id,
    journal_id: EXEMPLE.get(4).journal_id,
    generated_at: "2026-11-04T09:15:00.000Z",
    fichiers,
    points: points || attestation,
    attestation,
  });
  fichiers.set("dossier.json", enFichier(index));
  return fichiers;
}

/** Réindexe un dossier après modification d'une partie. */
function reindexer(fichiers) {
  const index = N.analyserJson(fichiers.get("dossier.json"));
  const nouveau = N.indexerDossier({
    event: index.event,
    org_id: index.org_id,
    journal_id: index.journal_id,
    generated_at: index.generated_at,
    fichiers,
    points: index.parts.length >= 13,
    attestation: index.parts.length === 14,
    raisons: Object.fromEntries(index.parts.filter((p) => !p.present).map((p) => [p.name, p.reason_if_absent])),
  });
  fichiers.set("dossier.json", enFichier(nouveau));
  return fichiers;
}

const statut = (r, id) => r.controles.find((c) => c.id === id);

// ---------------------------------------------------------------------------
// Arithmétique minimale d'Edwards25519 (forme affine), pour fabriquer une clé
// d'ordre mixte et montrer que la vérification est sans cofacteur.
const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const mod = (a) => ((a % P) + P) % P;
const puissance = (b, e) => {
  let r = 1n;
  b = mod(b);
  while (e > 0n) {
    if (e & 1n) r = mod(r * b);
    b = mod(b * b);
    e >>= 1n;
  }
  return r;
};
const inverse = (a) => puissance(a, P - 2n);
const D_ED = mod(-121665n * inverse(121666n));
const RACINE_M1 = puissance(2n, (P - 1n) / 4n);
const ajouter = ([x1, y1], [x2, y2]) => {
  const t = mod(D_ED * x1 * x2 * y1 * y2);
  return [mod((x1 * y2 + y1 * x2) * inverse(1n + t)), mod((y1 * y2 + x1 * x2) * inverse(1n - t))];
};
const multiplier = (k, Q) => {
  let R = [0n, 1n];
  let A = Q;
  while (k > 0n) {
    if (k & 1n) R = ajouter(R, A);
    A = ajouter(A, A);
    k >>= 1n;
  }
  return R;
};
const lePetit = (o) => o.reduceRight((acc, x) => (acc << 8n) | BigInt(x), 0n);
const versLe = (x, n = 32) => Uint8Array.from({ length: n }, (_, i) => Number((x >> BigInt(8 * i)) & 0xffn));
const decoderPoint = (o) => {
  const y = lePetit(o) & ((1n << 255n) - 1n);
  const signe = o[31] >> 7;
  const x2 = mod((y * y - 1n) * inverse(D_ED * y * y + 1n));
  let x = puissance(x2, (P + 3n) / 8n);
  if (mod(x * x - x2) !== 0n) x = mod(x * RACINE_M1);
  if (Number(x & 1n) !== signe) x = mod(-x);
  return [x, y];
};
const encoderPoint = ([x, y]) => {
  const o = versLe(y);
  o[31] |= Number(x & 1n) << 7;
  return o;
};
const BASE = decoderPoint(versLe(mod(4n * inverse(5n))));

describe("Noyau : API publique et refus", function () {
  describe("paquet", function () {
    it("package.json : nom, version, privé, ESM, Apache-2.0, Node ≥ 22, exports explicites, deux dépendances à version exacte", function () {
      const p = JSON.parse(fs.readFileSync(path.join(PAQUET, "package.json"), "utf8"));
      expect(p.name).to.equal("@noortrace/noyau");
      expect(p.version).to.equal("0.1.0");
      expect(p.private).to.equal(true);
      expect(p.type).to.equal("module");
      expect(p.license).to.equal("Apache-2.0");
      expect(p.engines).to.deep.equal({ node: ">=22" });
      expect(p.exports["."]).to.equal("./src/index.mjs");
      expect(p.exports["./dossier-fichiers"]).to.equal("./src/dossier-fichiers.mjs");
      expect(p.dependencies).to.deep.equal({ "@noble/curves": "2.4.0", "@noble/hashes": "2.4.0" });
      const racine = JSON.parse(fs.readFileSync(path.join(RACINE, "package.json"), "utf8"));
      expect(racine.workspaces).to.deep.equal(["paquets/*"]);
      expect(racine.devDependencies["fast-check"]).to.equal("4.10.2");
    });

    it("pureté : seul dossier-fichiers.mjs lit des fichiers ; aucune horloge ni aléa implicite dans src/", function () {
      const src = path.join(PAQUET, "src");
      for (const f of fs.readdirSync(src)) {
        const t = fs.readFileSync(path.join(src, f), "utf8");
        const lit = /from "node:fs"|from "fs"|require\(|readFileSync|readdirSync/.test(t);
        expect(lit, f).to.equal(f === "dossier-fichiers.mjs");
        expect(/Date\.now|new Date\(\)|performance\.now|Math\.random|randomBytes/.test(t), f).to.equal(false);
      }
    });

    it("LISEZMOI.md nomme chaque export, une ligne par export", function () {
      const lisezmoi = fs.readFileSync(path.join(PAQUET, "LISEZMOI.md"), "utf8");
      const lignes = new Set([...lisezmoi.matchAll(/^- `([A-Za-z0-9_]+)[(`]/gm)].map((m) => m[1]));
      const exports = [...Object.keys(N), "lireRepertoireDossier", "verifierRepertoireDossier"];
      expect(exports.filter((x) => !lignes.has(x)), "exports absents du LISEZMOI").to.deep.equal([]);
      expect([...lignes].filter((x) => !exports.includes(x)), "lignes sans export").to.deep.equal([]);
    });

    it("le point d'entrée n'exporte pas la lecture de répertoire", function () {
      expect(N).not.to.have.property("lireRepertoireDossier");
      expect(lireRepertoireDossier).to.be.a("function");
    });
  });

  describe("schémas", function () {
    it("les cinq schémas embarqués sont identiques, membre pour membre, à ceux de spec/schemas", function () {
      const paires = [
        [N.SCHEMA_EVENEMENT, "evenement-v0.schema.json"],
        [N.SCHEMA_MANIFESTE, "manifeste-v0.schema.json"],
        [N.SCHEMA_POINT_DE_CONTROLE, "point-de-controle-v0.schema.json"],
        [N.SCHEMA_ATTESTATION_PERIMETRE, "attestation-perimetre-v0.schema.json"],
        [N.SCHEMA_DOSSIER, "dossier-v0.schema.json"],
      ];
      for (const [copie, fichier] of paires) {
        const original = JSON.parse(fs.readFileSync(path.join(RACINE, "spec", "schemas", fichier), "utf8"));
        expect(N.egaliteJson(copie, original), fichier).to.equal(true);
      }
    });

    it("chaque bloc annoté de CT-1 valide contre son schéma", function () {
      const nom = { evenement: "evenement", manifeste: "manifeste", "point-de-controle": "point-de-controle" };
      expect(BLOCS).to.have.length(16);
      for (const b of BLOCS) {
        const r = N.validerSchema(nom[b.schema] ?? b.schema, b.valeur);
        expect(r.erreurs, b.schema).to.deep.equal([]);
      }
    });

    const schema = (corps) => ({ $schema: "https://json-schema.org/draft/2020-12/schema", $id: "https://essai.example/s.json", ...corps });

    it("refuse tout mot-clé inconnu, à toute profondeur, et un autre draft", function () {
      for (const inconnu of ["format", "patternProperties", "dependentRequired", "unevaluatedProperties", "$anchor", "contains", "exclusiveMinimum"]) {
        expect(() => new N.RegistreSchemas([schema({ properties: { a: { [inconnu]: 1 } } })]), inconnu).to.throw(N.ErreurSchema, /inconnu/);
      }
      expect(() => new N.RegistreSchemas([{ ...schema({}), $schema: "http://json-schema.org/draft-07/schema#" }])).to.throw(N.ErreurSchema);
      expect(() => new N.RegistreSchemas([schema({ $ref: "#/$defs/absent" })])).to.throw(N.ErreurSchema, /introuvable/);
      expect(() => new N.RegistreSchemas([schema({ pattern: "(" })])).to.throw(N.ErreurSchema);
      expect(N.MOTS_CLES).to.include("prefixItems").and.not.to.include("format");
    });

    it("sémantique 2020-12 des mots-clés employés", function () {
      const reg = new N.RegistreSchemas([
        schema({
          type: "object",
          additionalProperties: false,
          required: ["s", "n", "t"],
          properties: {
            s: { type: "string", minLength: 2, maxLength: 2, pattern: "^[a-z😀]+$" },
            n: { type: "integer", minimum: 0, maximum: 7200, multipleOf: 3600 },
            t: { type: "array", prefixItems: [{ const: 0 }], items: false, uniqueItems: true },
            o: { oneOf: [{ type: "null" }, { type: "string" }] },
            c: { if: { const: 1 }, then: { type: "integer" }, else: { not: { type: "integer" } } },
          },
        }),
      ]);
      const v = (x) => reg.valider("https://essai.example/s.json", x).valide;
      expect(v({ s: "a😀", n: 3600, t: [0] })).to.equal(true); // deux points de code
      expect(v({ s: "a", n: 3600, t: [0] })).to.equal(false);
      expect(v({ s: "ab", n: 1800, t: [0] })).to.equal(false);
      expect(v({ s: "ab", n: 3600.5, t: [0] })).to.equal(false);
      expect(v({ s: "ab", n: 3600, t: [0, 1] })).to.equal(false); // items: false
      expect(v({ s: "ab", n: 3600, t: [0], x: 1 })).to.equal(false);
      expect(v({ s: "ab", n: 3600, t: [0], o: 5 })).to.equal(false);
      expect(v({ s: "ab", n: 3600, t: [0], c: 2 })).to.equal(false);
      expect(v({ s: "ab", n: 3600, t: [0], c: "x" })).to.equal(true);
      expect(v({ s: "AB", n: 3600, t: [0] })).to.equal(false);
      expect(() => N.validerSchema("inexistant", {})).to.throw(RangeError);
    });

    it("refus du schéma d'événement : media_type null, value rédigée, clé en trop, majuscules, nom réservé inconnu", function () {
      const e = ev(4);
      expect(N.validerSchema("evenement", e).valide).to.equal(true);
      const avec = (f) => {
        const x = structuredClone(e);
        f(x);
        return N.validerSchema("evenement", x).valide;
      };
      expect(avec((x) => (x.execution.result.media_type = null))).to.equal(false);
      expect(avec((x) => (x.execution.arguments.value = {}))).to.equal(false);
      expect(avec((x) => (x.extra = 1))).to.equal(false);
      expect(avec((x) => (x.prev_hash = x.prev_hash.toUpperCase().replace("0X", "0x")))).to.equal(false);
      expect(avec((x) => (x.execution.tool = "noortrace.inconnu"))).to.equal(false);
      expect(avec((x) => (x.seq = 0))).to.equal(false);
    });
  });

  describe("conventions (CT-1 §3)", function () {
    it("hexadécimal minuscule préfixé, longueur exacte", function () {
      expect(N.estHex("0xab", 1)).to.equal(true);
      for (const x of ["0xAB", "ab", "0xa", "0x", 12, null]) expect(N.estHex(x, 1)).to.equal(false);
      expect(() => N.hexVersOctets("0xABCD")).to.throw(TypeError);
      expect(N.octetsVersHex(N.hexVersOctets("0x00ff"))).to.equal("0x00ff");
    });

    it("horodatages : décodage strict, dates inexistantes refusées, jamais renormalisées", function () {
      expect(N.decoderHorodatage("2026-11-03T13:52:41.090Z")).to.equal(Date.parse("2026-11-03T13:52:41.090Z"));
      expect(N.decoderHorodatage("2024-02-29T00:00:00.000Z")).to.equal(Date.parse("2024-02-29T00:00:00.000Z"));
      expect(N.decoderHorodatage("2000-02-29T23:59:59.999Z")).to.equal(Date.parse("2000-02-29T23:59:59.999Z"));
      for (const x of [
        "2026-02-30T00:00:00.000Z",
        "2026-04-31T00:00:00.000Z",
        "2026-02-29T00:00:00.000Z",
        "1900-02-29T00:00:00.000Z",
        "2026-11-03T13:52:60.000Z",
        "2026-11-03T24:00:00.000Z",
        "2026-11-03T13:52:41Z",
        "2026-11-03T13:52:41.09Z",
        "2026-11-03T13:52:41.090+01:00",
        "2026-11-03t13:52:41.090z",
        "2026-13-01T00:00:00.000Z",
        "2026-00-10T00:00:00.000Z",
      ]) {
        expect(N.decoderHorodatage(x), x).to.equal(null);
      }
      expect(Date.parse("2026-02-30T00:00:00.000Z")).to.not.be.NaN; // ce que le noyau refuse de faire
      expect(N.ecrireHorodatage(N.decoderHorodatage("2026-11-03T13:52:41.090Z"))).to.equal("2026-11-03T13:52:41.090Z");
      expect(N.decoderHorodatage("0000-01-01T00:00:00.000Z")).to.equal(-62167219200000);
    });

    it("base64 canonique : remplissage exact, bits de bourrage nuls, limite de taille", function () {
      expect(N.decoderBase64Canonique("QQ==")).to.deep.equal(Uint8Array.of(0x41));
      for (const x of ["QR==", "QQ", "QQ=", "Q Q==", "QQ==\n", "-_8=", "QQ==QQ=="]) expect(N.decoderBase64Canonique(x), JSON.stringify(x)).to.equal(null);
      expect(N.decoderBase64Canonique("QUJD", 2)).to.equal(null);
      expect(N.encoderBase64(N.utf8("ABC"))).to.equal("QUJD");
    });

    it("entiers sûrs seulement", function () {
      expect(N.estEntierSur(2 ** 53 - 1)).to.equal(true);
      expect(N.estEntierSur(2 ** 53)).to.equal(false);
      expect(N.estEntierSur(1.5)).to.equal(false);
      expect(N.estEntierSur("1")).to.equal(false);
    });
  });

  describe("JSON strict et JCS v0 (CT-1 §4)", function () {
    it("refus de lecture : clé en double, substitut isolé, nombres non entiers ou hors intervalle, syntaxe", function () {
      const code = (t, o) => {
        try {
          N.analyserJson(t, o);
          return "ok";
        } catch (e) {
          expect(e).to.be.instanceOf(N.ErreurJson);
          return e.code;
        }
      };
      expect(code('{"a":1,"a":2}')).to.equal("cle_en_double");
      expect(code('{"a":{"b":1,"\\u0062":2}}')).to.equal("cle_en_double");
      expect(code('"\\udc00"')).to.equal("substitut_isole");
      expect(code('"\\ud800x"')).to.equal("substitut_isole");
      expect(code('"\\ud83d\\ude00"')).to.equal("ok");
      expect(code("1.0")).to.equal("nombre_non_entier");
      expect(code("1E3")).to.equal("nombre_non_entier");
      expect(code("-0.0")).to.equal("nombre_non_entier");
      expect(code("9007199254740992")).to.equal("nombre_hors_intervalle");
      expect(code("-9007199254740992")).to.equal("nombre_hors_intervalle");
      expect(code("-9007199254740991")).to.equal("ok");
      expect(code("01")).to.equal("syntaxe");
      expect(code("[1,]")).to.equal("syntaxe");
      expect(code('{"a":1} x')).to.equal("syntaxe");
      expect(code('"a\u0001"')).to.equal("syntaxe");
      expect(code("NaN")).to.equal("syntaxe");
      expect(code("[".repeat(300) + "]".repeat(300))).to.equal("ok"); // CT-1 §4 ne fixe aucune profondeur
      expect(code("[".repeat(300) + "]".repeat(300), { profondeurMax: N.PROFONDEUR_CT6 })).to.equal("profondeur");
      expect(code(Uint8Array.of(0xef, 0xbb, 0xbf, 0x31))).to.equal("utf8");
      expect(code(Uint8Array.of(0x22, 0xff, 0x22))).to.equal("utf8");
      // Substitut encodé en UTF-8 (CESU-8) : substitut isolé de §4 (E-2), sauf
      // si le texte a aussi un autre défaut d'UTF-8.
      expect(code(Uint8Array.of(0x22, 0xed, 0xa0, 0x80, 0x22))).to.equal("substitut_isole");
      expect(code(Uint8Array.of(0x22, 0xed, 0xbf, 0xbf, 0x22))).to.equal("substitut_isole");
      expect(code(Uint8Array.of(0x22, 0xed, 0xa0, 0x80, 0xff, 0x22))).to.equal("utf8");
      expect(code(Uint8Array.of(0x22, 0xed, 0x9f, 0xbf, 0x22))).to.equal("ok"); // U+D7FF, dernier caractère avant les substituts
      expect(code("1.5", { nombres: "libres" })).to.equal("ok");
      expect(code('"\\ud800"', { substituts: "admis" })).to.equal("ok");
      expect(N.analyserJson("-0")).to.equal(0);
      expect(Object.is(N.analyserJson("-0"), 0)).to.equal(true);
    });

    it("refus d'écriture : NaN, infini, fraction, hors intervalle, substitut isolé, types non JSON", function () {
      for (const x of [NaN, Infinity, 1.5, 2 ** 53, "\ud800", { a: "\udfff" }, 1n, undefined, () => 1, new Date(0), new Map(), [1, , 3], { a: undefined }]) {
        expect(() => N.jcs(x)).to.throw(N.ErreurJson);
      }
      expect(N.jcs(-0)).to.equal("0");
      expect(N.jcs({ "": 1, "😀": 2 })).to.equal('{"😀":2,"":1}'); // unités UTF-16, pas points de code
      expect(N.jcs({ a: " \u007f/\u001f" })).to.equal('{"a":" \u007f/\\u001f"}');
      const proto = N.analyserJson('{"__proto__":{"x":1},"b":2}');
      expect(Object.getPrototypeOf(proto)).to.equal(Object.prototype);
      expect(N.jcs(proto)).to.equal('{"__proto__":{"x":1},"b":2}');
    });

    it("canoniserTexte et égalité JSON", function () {
      expect(N.canoniserTexte('{"b":[1,{"d":true,"c":null}],"a":"é"}')).to.equal('{"a":"é","b":[1,{"c":null,"d":true}]}');
      expect(N.canoniserTexte("{")).to.equal(null);
      expect(N.egaliteJson({ a: [1, { b: 2 }] }, { a: [1, { b: 2 }] })).to.equal(true);
      expect(N.egaliteJson({ a: [1, 2] }, { a: [2, 1] })).to.equal(false);
      expect(N.egaliteJson({ a: 1 }, { a: 1, b: undefined })).to.equal(false);
    });
  });

  describe("hachage et signatures (CT-1 §6, annexe B)", function () {
    it("préfixes de domaine octet pour octet (annexe B, §10.6, CT-7 §7.2)", function () {
      const attendus = {
        P_H: "6e6f6f7274726163652f6576656e656d656e742f76300a",
        P_S: "6e6f6f7274726163652f7369676e61747572652d6576656e656d656e742f76300a",
        P_M: "6e6f6f7274726163652f6d616e6966657374652f76300a",
        P_SM: "6e6f6f7274726163652f7369676e61747572652d6d616e6966657374652f76300a",
        P_A: "6e6f6f7274726163652f617070726f626174696f6e2f76300a",
        P_R: "6e6f6f7274726163652f7369676e61747572652d726f746174696f6e2f76300a",
        P_K: "6e6f6f7274726163652f706f696e742d64652d636f6e74726f6c652f76300a",
        P_SK: "6e6f6f7274726163652f7369676e61747572652d706f696e742d64652d636f6e74726f6c652f76300a",
        P_P: "6e6f6f7274726163652f6174746573746174696f6e2d706572696d657472652f76300a",
      };
      for (const [k, v] of Object.entries(attendus)) expect(N.octetsVersHex(N.PREFIXES[k]), k).to.equal("0x" + v);
      expect(Object.keys(N.PREFIXES).sort()).to.deep.equal(Object.keys(attendus).sort());
    });

    it("SHA-256 et Keccak-256 (et non SHA3-256)", function () {
      expect(N.sha256Hex(new Uint8Array(0))).to.equal("0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
      expect(N.octetsVersHex(N.keccak256(new Uint8Array(0)))).to.equal("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    });

    it("clés publiques Ed25519 de rec-test-01 et rec-test-02 (CT-1 §13)", function () {
      expect(N.octetsVersHex(G1)).to.equal("0x6215c33a2801ef7f21a894e98924eba8d72e3514f5fe7929ce0b595f5d39fa79");
      expect(N.octetsVersHex(N.clePubliqueEd25519(G1))).to.equal("0xe2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045");
      expect(N.octetsVersHex(N.clePubliqueEd25519(G2))).to.equal("0xfd08757fa4798c3c8757bbf5a0db49580cbcb80075ddb30f13f881b0f47aacb3");
      expect(() => N.clePubliqueEd25519(new Uint8Array(31))).to.throw(TypeError);
    });

    it("Ed25519 : refus de S non réduit, de R et A non canoniques, des huit points de petit ordre, des longueurs fausses", function () {
      const pub = N.clePubliqueEd25519(G1);
      const msg = N.utf8("message");
      const sig = N.signerEd25519(G1, msg);
      expect(N.verifierEd25519(pub, msg, sig)).to.equal(true);
      const S = lePetit(sig.subarray(32));
      const nonReduit = N.concatener(sig.subarray(0, 32), versLe(S + L));
      expect(N.verifierEd25519(pub, msg, nonReduit)).to.equal(false);
      for (const h of N.POINTS_PETIT_ORDRE) {
        expect(N.clePubliqueEd25519Admise(N.hexVersOctets("0x" + h)), h).to.equal(false);
      }
      // Encodages de y ≥ p (non canoniques), refusés pour A comme pour R.
      for (let k = 0n; k < 19n; k++) {
        const o = versLe(P + k);
        expect(N.encodageEd25519Canonique(o)).to.equal(false);
        expect(N.clePubliqueEd25519Admise(o)).to.equal(false);
        expect(N.verifierEd25519(pub, msg, N.concatener(o, sig.subarray(32)))).to.equal(false);
      }
      expect(N.verifierEd25519(pub, msg, sig.subarray(0, 63))).to.equal(false);
      expect(N.verifierEd25519(pub.subarray(0, 31), msg, sig)).to.equal(false);
      expect(N.verifierEd25519(pub, N.utf8("autre"), sig)).to.equal(false);
    });

    it("Ed25519 : équation sans cofacteur, [S]B = R + [k]A, sur une clé d'ordre mixte A + T", function () {
      const a = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcden % L;
      const T = decoderPoint(N.hexVersOctets("0x" + N.POINTS_PETIT_ORDRE[4])); // ordre 8
      const Amixte = encoderPoint(ajouter(multiplier(a, BASE), T));
      expect(N.clePubliqueEd25519Admise(Amixte)).to.equal(true);
      const signer = (message, r) => {
        const R = encoderPoint(multiplier(r, BASE));
        const k = lePetit(Uint8Array.from(createHash("sha512").update(N.concatener(R, Amixte, message)).digest())) % L;
        return { k, sig: N.concatener(R, versLe((r + k * a) % L)) };
      };
      let refusees = 0;
      let acceptees = 0;
      for (let i = 1n; i < 64n && (refusees === 0 || acceptees === 0); i++) {
        const message = N.utf8(`ordre mixte ${i}`);
        const { k, sig } = signer(message, 1000n + i);
        // Avec cofacteur, les deux cas vérifieraient ; sans, seul k ≡ 0 (mod 8).
        const attendu = k % 8n === 0n;
        expect(N.verifierEd25519(Amixte, message, sig), `k mod 8 = ${k % 8n}`).to.equal(attendu);
        if (attendu) acceptees++;
        else refusees++;
      }
      expect(refusees).to.be.greaterThan(0);
      expect(acceptees).to.be.greaterThan(0);
    });

    it("EIP-191 : signature déterministe de D_A (CT-1 §6.4) et refus des formes non canoniques", function () {
      const DA = N.hexVersOctets("0x59b49949b9e97d7e3fd9d46a3992476dd2cc27c48e25ef77b467816d144f37a7");
      const sig = N.signerEip191(COMPTES[0], DA);
      expect(N.octetsVersHex(sig)).to.equal(
        "0x9b56cadb515c1fc18cc37f5b85bc78be8c916daef1ef9017fb3067f19dbcc8585ae2b338117e554f3ec7faa77bc615c82a17a695a4f76295383d9c931d2648a01b",
      );
      expect(N.recouvrerAdresseEip191(DA, sig)).to.deep.equal({ adresse: "0x70997970c51812dc3a010c7d01b50e0d17dc79c8", canonique: true, raison: null });
      const haute = N.formeHauteEip191(sig);
      expect(N.recouvrerAdresseEip191(DA, haute).canonique).to.equal(false);
      for (const v of [0, 1, 29]) {
        const s = Uint8Array.from(sig);
        s[64] = v;
        expect(N.recouvrerAdresseEip191(DA, s).adresse).to.equal(null);
      }
      const zero = Uint8Array.from(sig);
      zero.fill(0, 0, 32);
      expect(N.recouvrerAdresseEip191(DA, zero).adresse).to.equal(null);
      expect(N.recouvrerAdresseEip191(DA, sig.subarray(0, 64)).adresse).to.equal(null);
      expect(N.verifierEip191(DA, N.octetsVersHex(sig), "0x70997970c51812dc3a010c7d01b50e0d17dc79c8")).to.equal(true);
      expect(N.verifierEip191(DA, N.octetsVersHex(sig), "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc")).to.equal(false);
      expect(() => N.messageEip191(new Uint8Array(31))).to.throw(TypeError);
    });
  });

  describe("exemple de référence de CT-1 (journal-principal)", function () {
    it("événement seq 4 : forme canonique de 2188 octets, hash et sig de §6.4", function () {
      const e = ev(4);
      expect(N.utf8(N.formeCanoniqueEvenement(e)).length).to.equal(2188);
      expect(N.hacherEvenement(e)).to.equal("0x471dab56146ae2e4c678120af7faf5eed7b1f8e5db3657226de97614bde4dc00");
      expect(N.scellerEvenement(e, G1).sig).to.equal(e.sig);
      expect(N.verifierSignatureEvenement(e, N.clePubliqueEd25519(G1))).to.equal(true);
      expect(N.verifierSignatureEvenement(e, N.clePubliqueEd25519(G2))).to.equal(false);
    });

    it("les cinq événements de l'annexe A forment une chaîne valide", function () {
      const r = N.verifierJournal([1, 2, 3, 4, 5].map(ev), CLES_EXEMPLE);
      expect(r).to.deep.equal({ valide: true, controles_en_echec: [], diagnostics: [] });
      for (const s of [1, 2, 3, 4, 5]) expect(N.hacherEvenement(ev(s))).to.equal(EXEMPLE.get(s).hash);
    });

    it("pièces de seq 4 et références (§5.5)", function () {
      const pieces = [
        ['{"claim_id":"2026-77812","amount":"7400.00","currency":"CHF","beneficiary_iban":"[REDIGE:iban]"}', ev(4).execution.arguments],
        ['{"content":[{"type":"text","text":"Paiement PAY-2026-55120 créé"}],"isError":false}', ev(4).execution.result],
        ["piece 1 (contenu fictif) : constat du 2026-10-28", ev(4).context[0]],
        ["piece 2 (contenu fictif) : facture du garage", ev(4).context[1]],
      ];
      for (const [t, ref] of pieces) {
        expect(N.verifierPiece(ref, N.utf8(t))).to.equal(true);
        const { kind, ...reference } = ref; // kind : propre aux éléments de context
        expect(N.creerReference(N.utf8(t), { redacted: ref.redacted })).to.deep.equal(reference);
      }
      expect(N.sha256Hex(N.utf8("prompt systeme fictif v3"))).to.equal(ev(4).code.prompt_version);
      expect(N.referencesEvenement(ev(4)).map((x) => x.chemin)).to.deep.equal(["execution.arguments", "execution.result", "context[0]", "context[1]"]);
    });

    it("décision seq 3 : A, D_A, signatures des comptes 1 et 2, référence en ligne", function () {
      const e = ev(3);
      const A = N.objetApprobation(e);
      expect(N.jcs(A)).to.equal(
        '{"decision":"approuve","journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","request_hash":"0xdd3b7036baeca6426596377870f5982e00ac1e4de7fb344cd1b2c5fa4bbefce0","ticket":"apr-1192"}',
      );
      expect(N.octetsVersHex(N.condenseApprobation(A))).to.equal("0x59b49949b9e97d7e3fd9d46a3992476dd2cc27c48e25ef77b467816d144f37a7");
      expect([N.signerApprobation(COMPTES[0], A), N.signerApprobation(COMPTES[1], A)]).to.deep.equal(e.approval.signatures);
      expect(N.creerReferenceEnLigne(A)).to.deep.equal(e.execution.arguments);
      expect(N.verifierReferenceEnLigne(e.execution.arguments)).to.equal(true);
      expect(N.verifierReferenceEnLigne({ ...e.execution.arguments, length: 288 })).to.equal(false);
      expect(() => N.objetApprobation(ev(4 - 2))).to.throw(TypeError);
    });

    it("rotation seq 5 : JCS(R) et contresignature de §8 reproduites ; E-10 refuse les annonces fausses", function () {
      const e = ev(5);
      const annonce = e.execution.arguments.value;
      expect(N.jcs(N.corpsRotation(annonce))).to.equal(
        '{"journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","new_key_id":"rec-test-02","new_public_key":"0xfd08757fa4798c3c8757bbf5a0db49580cbcb80075ddb30f13f881b0f47aacb3","old_key_id":"rec-test-01","org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","valid_from":"2026-11-03T13:59:59.999Z"}',
      );
      const refaite = N.annoncerRotation({ ...N.corpsRotation(annonce) }, G2);
      expect(refaite).to.deep.equal(annonce);
      expect(N.champsEvenementRotation(annonce)).to.deep.equal({ execution: e.execution, effects: e.effects });
      const idx = N.indexerCles(CLES_EXEMPLE, {});
      expect(N.ecartsRotation(e, idx)).to.deep.equal([]);
      const varier = (f) => {
        const x = ev(5);
        f(x.execution.arguments.value);
        return N.ecartsRotation(x, idx);
      };
      expect(varier((v) => (v.counter_sig = N.annoncerRotation(N.corpsRotation(v), G1).counter_sig))).to.have.length.greaterThan(0);
      expect(varier((v) => (v.new_key_id = "rec-test-01"))).to.have.length.greaterThan(0);
      expect(varier((v) => (v.valid_from = "2026-11-03T13:59:59.998Z"))).to.have.length.greaterThan(0);
      expect(varier((v) => (v.old_key_id = "rec-test-09"))).to.have.length.greaterThan(0);
      expect(varier((v) => delete v.counter_sig)).to.deep.equal(["annonce de rotation absente ou mal formée (sept clés de CT-1 §8 attendues)"]);
      expect(N.ecartsRotation(e, N.indexerCles({ ...CLES_EXEMPLE, keys: [CLES_EXEMPLE.keys[0]] }, {}))).to.include("cles.json ne porte pas la clé rec-test-02");
    });

    it("arbre de §9.4 : feuilles, nœuds, racine, chemin de seq 4 et son déroulé", function () {
      expect(N.feuille(D5[0])).to.equal("0xd5e2098df5be8721f7343aab8ad414a5bea5b55bb0fb0e72eb8fb9bb6c3f5a8b");
      expect(N.noeud(N.feuille(D5[0]), N.feuille(D5[1]))).to.equal("0xa5b5b030de6510a06da18b109b73e7b85c4afe3e6d0fb89b4bd9b53b3d42f79e");
      expect(N.racineMerkle(D5.slice(0, 4))).to.equal("0x22264c23c7f8fea323dd1998376576e0fa4d14c67dc577dc7a01e5ae9c2e4cf6");
      expect(N.racineMerkle(D5)).to.equal("0x6782bad9bd4717caf61b261a0a7f86fa9263f4b5b76c1d80d4c3bfbe0512ed06");
      expect(N.racineMerkle(D5.slice(0, 3))).to.equal("0x3f18df046e3c8dbff1ec006b9533cb0be82d756c347c8838a25f03bfda5cd399");
      expect(N.preuveInclusion(3, D5)).to.deep.equal(blocs("chemin")[0]);
      expect(N.verifierInclusion(blocs("chemin")[0])).to.equal(true);
      expect([N.puissanceInferieure(2), N.puissanceInferieure(5), N.puissanceInferieure(8), N.puissanceInferieure(9)]).to.deep.equal([1, 4, 4, 8]);
      expect(() => N.preuveInclusion(5, D5)).to.throw(RangeError);
      expect(() => N.preuveInclusion(0, [])).to.throw(RangeError);
      expect(N.verifierInclusion({ ...blocs("chemin")[0], tree_size: 0 })).to.equal(false);
      expect(N.verifierInclusion(null)).to.equal(false);
    });

    it("preuves de cohérence de §10.8 : PROOF(1..4, D[5]) et refus hors définition", function () {
      const attendues = {
        1: ["0x3ef9fdf53c5fd27d37c20efdce9d0d8bfcfd459d491e5cb66dd3f384540d270c", "0x2fb61705d23c09d71bebc1a297940ce119c3bda5b3357d39d76043cb554cfea8", "0xa93b6b900d821b68a351fb3e8e986f8298a21254f1c348f108843f7ede2f1ec0"],
        2: ["0x2fb61705d23c09d71bebc1a297940ce119c3bda5b3357d39d76043cb554cfea8", "0xa93b6b900d821b68a351fb3e8e986f8298a21254f1c348f108843f7ede2f1ec0"],
        3: ["0x8380b74438d71a5fb81aa3b62f1c7e0b06cb0e9c73f5d5a42f44372e203fbf3e", "0x3617a8c28e38e476cc671a109baf783cd70e1f24eca0278280a215b28f1c55db", "0xa5b5b030de6510a06da18b109b73e7b85c4afe3e6d0fb89b4bd9b53b3d42f79e", "0xa93b6b900d821b68a351fb3e8e986f8298a21254f1c348f108843f7ede2f1ec0"],
        4: ["0xa93b6b900d821b68a351fb3e8e986f8298a21254f1c348f108843f7ede2f1ec0"],
      };
      for (const [m, path_] of Object.entries(attendues)) {
        expect(N.preuveCoherence(Number(m), D5)).to.deep.equal(path_);
        const preuve = { first_size: Number(m), second_size: 5, first_root: N.racineMerkle(D5.slice(0, Number(m))), second_root: N.racineMerkle(D5), path: path_ };
        expect(N.verifierCoherence(preuve).valide).to.equal(true);
        expect(N.verifierCoherence({ ...preuve, path: [...path_].reverse() }).valide).to.equal(path_.length === 1);
      }
      expect(N.preuveCoherence(5, D5)).to.deep.equal([]);
      expect(() => N.preuveCoherence(0, D5)).to.throw(RangeError);
      expect(() => N.preuveCoherence(6, D5)).to.throw(RangeError);
      const r = N.racineMerkle(D5);
      expect(N.verifierCoherence({ first_size: 0, second_size: 0, first_root: N.ZERO32, second_root: N.ZERO32, path: [] })).to.deep.equal({ valide: false, raison: "m = 0" });
      expect(N.verifierCoherence({ first_size: 5, second_size: 5, first_root: r, second_root: N.ZERO32, path: [] }).valide).to.equal(false);
      expect(N.verifierCoherence({ first_size: 1.5, second_size: 5, first_root: r, second_root: r, path: [] }).valide).to.equal(false);
    });

    it("manifestes de §10.1 à §10.4 : construction, periodHash, signatures, continuité, PeriodMeta, empreinte d'ancre", function () {
      const construit = N.construireManifeste({
        org_id: MANIFESTE_1.org_id,
        journal_id: MANIFESTE_1.journal_id,
        period_start: 1793710800,
        first_seq: 1,
        hashes: D5,
        prev_period_hash: N.ZERO32,
        recorder_key_id: "rec-test-02",
        nonce: N.sha256Hex(N.utf8("noortrace/vecteurs/v0/nonce/periode-1")),
        generated_at: "2026-11-03T14:00:00.250Z",
      });
      expect(construit).to.deep.equal(MANIFESTE_1);
      expect(N.hacherManifeste(MANIFESTE_1)).to.equal("0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1");
      expect(N.signerManifeste(MANIFESTE_1, G2)).to.deep.equal(blocs("manifeste_sig")[0]);
      expect(N.hacherManifeste(MANIFESTE_2)).to.equal("0x3ed80e52f0d52f184986da64ba009947998cfd41624899ad5137594c58f9be4b");
      expect(N.signerManifeste(MANIFESTE_2, G2).sig).to.equal(
        "0x054847990ed1662c10a2b5cde8d7389a17af5a074d6e068c0a3ed855b79d2368c4cd95e425d0b28a3534b108864018c6f6b9bfc994ab0bdc639adf5f0b9fbb03",
      );
      expect(N.verifierContinuite(MANIFESTE_1, MANIFESTE_2)).to.deep.equal({ valide: true, erreurs: [] });
      expect(N.verifierContinuite(MANIFESTE_2, MANIFESTE_1).erreurs).to.have.length(3);
      expect(N.empreinteAncre(MANIFESTE_1.org_id, MANIFESTE_1.journal_id, N.hacherManifeste(MANIFESTE_1))).to.equal(
        "0x3200e496c555b46459191c852a7f79b1e0b4156802cac2f2df7b80b0aa9d823b",
      );
      expect(N.periodMeta(MANIFESTE_2)).to.include({ firstSeq: 6, lastSeq: 5, root: N.ZERO32, version: 0 });
      expect(N.ecartsManifeste(MANIFESTE_1)).to.deep.equal([]);
      expect(N.ecartsManifeste({ ...MANIFESTE_1, period_end: MANIFESTE_1.period_start + 7200 })).to.have.length(1);
      expect(N.ecartsManifeste({ ...MANIFESTE_1, count: 4 })).to.have.length(1);
      expect(N.ecartsManifeste({ ...MANIFESTE_1, root: N.ZERO32 }).length).to.be.greaterThan(0);
      expect(N.ecartsManifeste({ ...MANIFESTE_1, generated_at: "2026-02-30T00:00:00.000Z" })).to.deep.equal(["generated_at : horodatage qui ne se décode pas"]);
      expect(N.ecartsManifeste(null).length).to.be.greaterThan(0);
    });

    it("points de contrôle K1 à K6 de §10.8 : checkpointHash, signatures et série valide contre les manifestes", function () {
      const table = [
        [2, 2, "2026-11-03T13:42:00.000Z", "rec-test-01", "0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4", "0x96c006c0f2be56f834413b6ee08961badd810c893bbdd9d40bb5d48bd498f7d66b89cb29979e0907e48b4ec33250e7f0b89f89447f0d4f57d78b11cf6675c409"],
        [4, 4, "2026-11-03T13:53:00.000Z", "rec-test-01", "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff", "0x29f6f3f6463ecba15185a160d923033e48d4c15f97f747105894b0dd49a3e021b489a9b6591416fcc71f68e174a251d9cf790fcbac39b6fdc74fd6a61f49870f"],
        [4, 4, "2026-11-03T13:54:00.000Z", "rec-test-01", "0x3feb86ac4d6d8c054bef224f131f0276d2f1c9c9db2a6ce06adec173378d8867", "0x8e37a2cf042ceacaab8d81df08591802228330d76e398a2fe1813ec10b6d2bb9c68282f3e6a481a4723ec76fd48179f76568cfec12e7c1ba32d2120cbf2a4c0a"],
        [5, 5, "2026-11-03T14:00:00.250Z", "rec-test-02", "0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107", "0xe2dd1ae0b182e6da7d34a6ebb611dc8a628297a09b03e987e921f8c71659c572fcf70b428f678380fb4c05d73bf6118a41d5e25ffb7d10eb8e689a426c63e80e"],
        [0, 5, "2026-11-03T14:01:00.000Z", "rec-test-02", "0x3c4bd86148138e52a1ef6912c7ab4fa98ffdaf90879900887833e726b5a9e153", "0x7bd3835f0f686cdd5141f0d0d590b293a09724cd1bce9b6ffd3e337f3dfa189f77945264ca4a0743d6e5e35c164dc7f81f64b877974b497a567094b6a130730f"],
        [0, 5, "2026-11-03T15:00:00.112Z", "rec-test-02", "0xd6e22871885b68962dadee69f9fa2ff3a76949d23550d1682d3564bcc705474d", "0x4993daaf14482da9001d4eb6123dab4720cfa62f8da39e8ecc9a7cdd547d67c520acaaddddfa6684e6a1a368ae0f4e982c019c254ecf2e64f8aff26a591c0d02"],
      ];
      const points = [];
      let precedent = N.ZERO32;
      table.forEach(([n, last, ts, cle, hash, sig], i) => {
        if (i === 4) precedent = N.ZERO32; // nouvelle période, nouvelle chaîne
        const p = N.signerPoint(
          {
            version: 0,
            org_id: MANIFESTE_1.org_id,
            journal_id: MANIFESTE_1.journal_id,
            period_start: i < 4 ? 1793710800 : 1793714400,
            tree_size: n,
            root: N.racineMerkle(D5.slice(0, n)),
            last_seq: last,
            last_hash: D5[last - 1],
            checkpoint_ts: ts,
            prev_checkpoint_hash: precedent,
            key_id: cle,
          },
          cle === "rec-test-01" ? G1 : G2,
        );
        expect(N.hacherPoint(p), `K${i + 1}`).to.equal(hash);
        expect(p.sig, `K${i + 1}`).to.equal(sig);
        precedent = hash;
        points.push(p);
      });
      expect(points[1]).to.deep.equal(blocs("point-de-controle")[0]);
      expect(points[4]).to.deep.equal(blocs("point-de-controle")[1]);
      const evs = [1, 2, 3, 4, 5].map(ev);
      expect(N.verifierSeriePointsDeControle(points.slice(0, 4), MANIFESTE_1, evs, CLES_EXEMPLE)).to.deep.equal({ valide: true, rules_failed: [], errors: [] });
      expect(N.verifierSeriePointsDeControle(points.slice(4), MANIFESTE_2, evs, CLES_EXEMPLE)).to.deep.equal({ valide: true, rules_failed: [], errors: [] });
      expect(N.coherencePoint(4, D5).path).to.deep.equal(["0xa93b6b900d821b68a351fb3e8e986f8298a21254f1c348f108843f7ede2f1ec0"]);
      expect(N.coherencePoint(0, D5)).to.equal(null);
      // Règles de série non exercées par les vecteurs : period_start, root, last_seq.
      const r = N.verifierSeriePointsDeControle(
        [{ ...points[0], period_start: 1793714400 }, N.signerPoint({ ...points[1], root: points[0].root, last_seq: 3 }, G1), ...points.slice(2, 4)],
        MANIFESTE_1,
        evs,
        CLES_EXEMPLE,
      );
      expect(r.rules_failed).to.include.members(["period_start", "root", "last_seq", "chainage", "signature"]);
      expect(N.verifierSeriePointsDeControle([], MANIFESTE_1, evs, CLES_EXEMPLE).rules_failed).to.deep.equal(["dernier_point"]);
      expect(() => N.verifierSeriePointsDeControle(points, { ...MANIFESTE_1, last_seq: 2 ** 53 - 1 }, evs, CLES_EXEMPLE)).to.throw(TypeError, /manifeste non conforme/);
      expect(N.verifierSeriePointsDeControle(points.slice(0, 4), MANIFESTE_1, evs.slice(0, 3), CLES_EXEMPLE).rules_failed).to.include.members(["root", "last_hash"]);
      expect(N.cleEnVigueur(new Map(evs.map((e) => [e.seq, e])), 5)).to.equal("rec-test-02");
      // Sans l'événement last_seq : règle de §10.1 sur cles.json, à l'instant du point.
      expect(N.cleEnVigueur(new Map(evs.map((e) => [e.seq, e])), 0)).to.equal(null);
      const indexCles = N.indexerCles(CLES_EXEMPLE);
      const a = (t) => N.cleEnVigueur(new Map(), 0, { indexCles, instant: N.decoderHorodatage(t) });
      expect(a("2026-11-03T13:00:00.000Z")).to.equal("rec-test-01");
      expect(a("2026-11-03T13:59:59.999Z")).to.equal("rec-test-02"); // valid_from de rec-test-02, borne incluse
      expect(a("2026-10-31T23:59:59.999Z")).to.equal(null);
    });
  });

  describe("contrôles d'un événement (E-1 à E-11)", function () {
    const idx = N.indexerCles(CLES_EXEMPLE, {});
    const controler = (e) => N.controlerEvenement(e, { indexCles: idx }).controles;
    const enEchec = (e) => Object.entries(controler(e)).filter(([, r]) => r.statut === "echoue").map(([id]) => id);
    const rescelle = (s, f) => {
      const e = ev(s);
      f(e);
      return N.scellerEvenement(e, e.recorder_key_id === "rec-test-01" ? G1 : G2);
    };

    it("les cinq événements de l'exemple passent les onze contrôles", function () {
      for (const s of [1, 2, 3, 4, 5]) expect(enEchec(ev(s)), `seq ${s}`).to.deep.equal([]);
    });

    it("E-1 : date inexistante, identifiant nul, non-objet", function () {
      expect(enEchec(rescelle(4, (e) => (e.ts = "2026-02-30T13:52:41.090Z")))).to.include("E-1");
      expect(enEchec(rescelle(4, (e) => (e.approval.at = "2026-02-29T13:52:40.511Z")))).to.include("E-1");
      expect(enEchec(rescelle(4, (e) => (e.org_id = N.ZERO32)))).to.include("E-1");
      expect(N.controlerEvenement([], {}).controles["E-1"].statut).to.equal("echoue");
    });

    it("E-2 : une valeur sans forme canonique dans un objet construit en mémoire", function () {
      const e = ev(4);
      e.execution.duration_ms = 412.5;
      const r = controler(e);
      expect(r["E-2"].statut).to.equal("echoue");
      expect(r["E-7"].statut).to.equal("non_execute");
    });

    it("E-3 : cohérence de la sorte", function () {
      expect(enEchec(rescelle(4, (e) => (e.policy.decision = "autorise")))).to.include("E-3");
      expect(enEchec(rescelle(2, (e) => (e.execution.status = "executee")))).to.include("E-3");
      expect(enEchec(rescelle(3, (e) => (e.intent = "texte")))).to.include("E-3");
      expect(enEchec(rescelle(3, (e) => (e.execution.arguments = N.creerReferenceEnLigne({ autre: 1 }))))).to.include("E-3");
      expect(enEchec(rescelle(5, (e) => (e.effects = [])))).to.include("E-3");
      expect(enEchec(rescelle(1, (e) => (e.approval = ev(3).approval)))).to.include("E-3");
      expect(N.ecartsSorte({ execution: { tool: "noortrace.autre" } })).to.have.length(1);
      expect(N.ecartsSorte({})).to.deep.equal(["execution.tool illisible"]);
    });

    it("E-4, E-5, E-6, E-7, E-8, E-9, E-11", function () {
      expect(enEchec(rescelle(4, (e) => (e.policy.redaction = null)))).to.deep.equal(["E-4"]);
      expect(enEchec(rescelle(4, (e) => e.approval.signatures.pop()))).to.deep.equal(["E-5"]);
      expect(enEchec(rescelle(4, (e) => (e.policy.ticket = "apr-1193")))).to.include("E-5");
      expect(enEchec(rescelle(3, (e) => (e.execution.arguments.length += 1)))).to.deep.equal(["E-6"]);
      expect(enEchec({ ...ev(4), hash: N.ZERO32 })).to.deep.equal(["E-7"]);
      expect(enEchec({ ...ev(4), recorder_key_id: "rec-test-02" })).to.include("E-8");
      expect(enEchec({ ...ev(4), recorder_key_id: "rec-test-09" })).to.include("E-8");
      expect(enEchec(rescelle(4, (e) => e.approval.signatures.reverse()))).to.deep.equal(["E-9"]);
      expect(enEchec(rescelle(4, (e) => (e.approval.signatures[0] = N.octetsVersHex(N.formeHauteEip191(N.hexVersOctets(e.approval.signatures[0]))))))).to.deep.equal(["E-9"]);
      expect(enEchec(rescelle(4, (e) => (e.ts = "2026-11-03T14:00:00.000Z")))).to.deep.equal(["E-11"]);
      const sansCles = N.controlerEvenement(ev(4), {}).controles;
      expect(sansCles["E-8"].statut).to.equal("non_execute");
      expect(sansCles["E-11"].statut).to.equal("non_execute");
    });

    it("une clé publique de petit ordre dans cles.json fait échouer E-8", function () {
      const cles = structuredClone(CLES_EXEMPLE);
      cles.keys[0].public_key = "0x" + N.POINTS_PETIT_ORDRE[6];
      const r = N.controlerEvenement(ev(4), { indexCles: N.indexerCles(cles, {}) }).controles;
      expect(r["E-8"].statut).to.equal("echoue");
    });

    it("cles.json inexploitable : schéma, autre journal, key_id ou clé publique en double, validités inversées, date inexistante", function () {
      const attendus = { org_id: CLES_EXEMPLE.org_id, journal_id: CLES_EXEMPLE.journal_id };
      expect(N.indexerCles(CLES_EXEMPLE, attendus).exploitable).to.equal(true);
      const casser = (f) => {
        const c = structuredClone(CLES_EXEMPLE);
        f(c);
        return N.indexerCles(c, attendus).exploitable;
      };
      expect(casser((c) => (c.version = 1))).to.equal(false);
      expect(casser((c) => (c.journal_id = "0x" + "11".repeat(32)))).to.equal(false);
      expect(casser((c) => (c.keys[1].key_id = "rec-test-01"))).to.equal(false);
      expect(casser((c) => (c.keys[1].public_key = c.keys[0].public_key))).to.equal(false);
      expect(casser((c) => (c.keys[0].valid_to = "2026-10-01T00:00:00.000Z"))).to.equal(false);
      expect(casser((c) => (c.keys[0].valid_from = "2026-02-30T00:00:00.000Z"))).to.equal(false);
      expect(N.indexerCles(null).exploitable).to.equal(false);
    });
  });

  describe("chaînage (CT-1 §7)", function () {
    const journal = () => [1, 2, 3, 4, 5].map(ev);

    it("tableau attendu, symptômes d'identité, de clé et d'origine", function () {
      expect(() => N.verifierJournal(null, CLES_EXEMPLE)).to.throw(TypeError);
      const j = journal();
      const r1 = N.verifierJournal([j[0], { ...j[1], journal_id: MANIFESTE_1.org_id }], CLES_EXEMPLE);
      expect(r1.diagnostics.map((d) => d.type)).to.include("identite");
      const premier = N.scellerEvenement({ ...j[0], prev_hash: j[1].hash }, G1);
      expect(N.verifierJournal([premier], CLES_EXEMPLE).diagnostics.map((d) => d.type)).to.deep.equal(["origine"]);
      const sixieme = N.scellerEvenement({ ...j[3], seq: 6, ts: "2026-11-03T13:59:59.999Z", prev_hash: j[4].hash }, G1);
      const r2 = N.verifierJournal([...j, sixieme], CLES_EXEMPLE);
      expect(r2.controles_en_echec).to.deep.equal(["C-3"]);
      const r3 = N.verifierJournal(j, { ...CLES_EXEMPLE, version: 1 });
      expect(r3.controles_en_echec).to.deep.equal(["E-8"]);
      expect(r3.diagnostics.map((d) => d.type)).to.deep.equal(["cles"]);
    });

    it("trierControles suit l'ordre de CT-1 §11.4", function () {
      expect(N.trierControles(["K-1", "A-1", "E-10", "E-2", "D-2", "E-2"])).to.deep.equal(["D-2", "E-2", "E-10", "A-1", "K-1"]);
      expect(N.ORDRE_CONTROLES).to.have.length(37);
    });
  });

  describe("dossier de référence de CT-1 §11 (assemblé depuis le texte)", function () {
    it("les SHA-256 des parties sont ceux de l'index de §11.1", function () {
      const index = blocs("dossier")[0];
      const fichiers = dossierDeReference();
      for (const p of index.parts.filter((x) => x.present)) {
        expect(N.sha256Hex(fichiers.get(p.file)), p.file).to.equal(p.sha256);
      }
      expect(N.analyserJson(fichiers.get("dossier.json"))).to.deep.equal(index);
      expect(N.sha256Hex(enFichier(blocs("points_de_controle")[0]))).to.equal("0xe9340e56c7c7ad6d7b1e168ad1e5d8616f3aa6dfc31e46a49860c89f38460a05");
      const sansAncre = structuredClone(blocs("points_de_controle")[0]);
      sansAncre.anchors.rfc3161 = null;
      expect(N.sha256Hex(enFichier(sansAncre))).to.equal("0x1c10718bce466f0f8bd31501209f7dcabd675d9c83b0eb0c81e20a1b5b86aa65");
      const attestation = enFichier(blocs("attestation_perimetre")[0]);
      expect(attestation.length).to.equal(5443);
      expect(N.sha256Hex(attestation)).to.equal("0x08c7b70e7b757bebc9137210446eabb60032c38f8d7bc2434da2df97cb423072");
    });

    it("douze parties : valide, A-4 non exécuté (demande hors du dossier), borne énoncée", function () {
      const r = N.verifierDossier(dossierDeReference());
      expect(r.verdict, JSON.stringify(r.controles.filter((c) => c.statut !== "reussi"))).to.equal("valide");
      expect(r.evenement).to.deep.equal({ seq: 4, hash: EXEMPLE.get(4).hash });
      expect(statut(r, "A-4")).to.include({ statut: "non_execute", raison: "piece_hors_dossier", admise: true });
      expect(r.controles.map((c) => c.id)).to.deep.equal(N.ORDRE_CONTROLES.filter((id) => !id.startsWith("K-")));
      expect(r.borne).to.equal(N.BORNE);
      expect(r.parties_absentes.map((p) => p.name)).to.deep.equal(N.PARTIES_RESERVEES);
      expect(r.perimetre).to.equal(null);
    });

    it("treize parties : jeton RFC 3161 non vérifié par la bibliothèque (K-7 bloquant), vérifié par délégation", function () {
      const fichiers = dossierDeReference({ points: true });
      const r = N.verifierDossier(fichiers);
      expect(r.verdict).to.equal("invalide");
      expect(r.controles_en_echec).to.deep.equal([]);
      expect(r.non_executes_bloquants).to.deep.equal(["K-7"]);
      for (const id of ["K-1", "K-2", "K-3", "K-4", "K-5", "K-6"]) expect(statut(r, id).statut, id).to.equal("reussi");
      expect(statut(r, "K-8")).to.include({ statut: "non_execute", raison: "partie_absente" });
      const appels = [];
      const delegue = N.verifierDossier(fichiers, {
        verificateursAncres: {
          rfc3161: (ancre, ctx) => {
            appels.push(ctx.checkpoint_hash);
            return { statut: "reussi", details: ["jeton vérifié par CT-6"] };
          },
        },
      });
      expect(delegue.verdict).to.equal("valide");
      expect(appels).to.deep.equal(["0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff"]);
      const sansAncre = structuredClone(blocs("points_de_controle")[0]);
      sansAncre.anchors.rfc3161 = null;
      fichiers.set("points-de-controle.json", enFichier(sansAncre));
      expect(N.verifierDossier(reindexer(fichiers)).verdict).to.equal("valide");
    });

    it("ancre au registre : empreinte et doc_type recalculés (K-8), le reste relève de CT-6", function () {
      const fichiers = dossierDeReference({ points: true });
      const partie = structuredClone(blocs("points_de_controle")[0]);
      partie.anchors.rfc3161 = null;
      partie.anchors.registry = {
        chain_id: 2124,
        contract: "0x0000000000000000000000000000000000000000",
        fingerprint: "0x7f721a4526c614882ff41ac33792c6d05fa7fb6dd98bc1c369d0e277029f4e44",
        doc_type: "0x72c486c933f8fb8fef2c726539023e8fd80113cc0ca89e3fdf1314d553932178",
        block_number: 0,
        block_hash: N.ZERO32,
        transaction_hash: N.ZERO32,
        log_index: 0,
      };
      expect(N.DOC_TYPE_POINT).to.equal(partie.anchors.registry.doc_type);
      fichiers.set("points-de-controle.json", enFichier(partie));
      const r = N.verifierDossier(reindexer(fichiers));
      expect(statut(r, "K-8")).to.include({ statut: "non_execute", raison: "verification_ct6_requise" });
      partie.anchors.registry.fingerprint = N.ZERO32;
      fichiers.set("points-de-controle.json", enFichier(partie));
      expect(N.verifierDossier(reindexer(fichiers)).controles_en_echec).to.deep.equal(["K-8"]);
    });

    it("quatorze parties : AT-1 à AT-5 réussies, AT-6 et AT-7 non exécutées (partie absente), attestation retenue", function () {
      const fichiers = dossierDeReference({ attestation: true });
      const partie = structuredClone(blocs("points_de_controle")[0]);
      partie.anchors.rfc3161 = null;
      fichiers.set("points-de-controle.json", enFichier(partie));
      const r = N.verifierDossier(reindexer(fichiers));
      expect(r.verdict).to.equal("valide");
      expect(r.perimetre.verifications.map((v) => [v.id, v.status, v.reason])).to.deep.equal([
        ["AT-1", "reussi", null],
        ["AT-2", "reussi", null],
        ["AT-3", "reussi", null],
        ["AT-4", "reussi", null],
        ["AT-5", "reussi", null],
        ["AT-6", "non_execute", "partie_absente"],
        ["AT-7", "non_execute", "partie_absente"],
      ]);
      expect(r.perimetre.retenue).to.equal(true);
      expect(r.perimetre.avertissements).to.deep.equal([]);
      expect(r.perimetre.digest).to.equal("0x4481a2e47712539c4ca50f2eea3d6062ec11a70d497c153c1a6f707606657cfd");
    });

    it("index refusé (D-1) : quinze parties, treizième mal nommée, generated_at inexistant", function () {
      const fichiers = dossierDeReference();
      const index = N.analyserJson(fichiers.get("dossier.json"));
      const essayer = (f) => {
        const x = structuredClone(index);
        f(x);
        const copie = new Map(fichiers);
        copie.set("dossier.json", enFichier(x));
        return N.verifierDossier(copie);
      };
      const absente = (name, file) => ({ name, file, sha256: null, present: false, reason_if_absent: "aucune" });
      const r1 = essayer((x) => x.parts.push(absente("points_de_controle", "points-de-controle.json"), absente("attestation_perimetre", "attestation-perimetre.json"), absente("points_de_controle", "points-de-controle.json")));
      expect(r1.controles_en_echec).to.deep.equal(["D-1"]);
      expect(r1.controles.filter((c) => c.id !== "D-1").every((c) => c.statut === "non_execute")).to.equal(true);
      expect(essayer((x) => x.parts.push(absente("attestation_perimetre", "attestation-perimetre.json"))).controles_en_echec).to.deep.equal(["D-1"]);
      expect(essayer((x) => (x.generated_at = "2026-02-29T09:15:00.000Z")).controles_en_echec).to.deep.equal(["D-1"]);
    });

    it("D-2 : partie déclarée absente mais présente, partie déclarée présente mais manquante", function () {
      const f1 = dossierDeReference();
      f1.set("jeton-rfc3161.der", Uint8Array.of(1, 2, 3));
      expect(N.verifierDossier(f1).controles_en_echec).to.deep.equal(["D-2"]);
      const f2 = dossierDeReference();
      f2.delete("chemin.json");
      const r = N.verifierDossier(f2);
      expect(r.controles_en_echec).to.deep.equal(["D-2"]);
      expect(statut(r, "M-2").statut).to.equal("non_execute");
      expect(r.verdict).to.equal("invalide");
    });

    it("entrée inutilisable : dossier.json absent ou qui n'est pas du JSON (aucun verdict)", function () {
      const f = dossierDeReference();
      f.delete("dossier.json");
      expect(N.verifierDossier(f)).to.include({ utilisable: false, verdict: null });
      f.set("dossier.json", N.utf8("{"));
      expect(N.verifierDossier(f).verdict).to.equal(null);
      f.set("dossier.json", N.utf8('{"version":0,"version":0}'));
      const r = N.verifierDossier(f);
      expect(r.utilisable).to.equal(true);
      expect(r.controles_en_echec).to.deep.equal(["E-2"]);
    });

    it("parties inexploitables : non-JSON, tableau, forme non canonique ; rien n'est repris de l'index", function () {
      const remplacer = (fichier, octets) => {
        const f = dossierDeReference();
        f.set(fichier, octets);
        return N.verifierDossier(reindexer(f));
      };
      expect(remplacer("voisins.json", N.utf8("pas du JSON")).controles_en_echec).to.deep.equal(["C-1"]);
      expect(remplacer("chemin.json", N.utf8("[]")).controles_en_echec).to.deep.equal(["M-2"]);
      expect(remplacer("manifeste.json", N.utf8("42")).controles_en_echec).to.deep.equal(["P-1"]);
      expect(remplacer("manifeste.sig", N.utf8("null")).controles_en_echec).to.deep.equal(["P-5"]);
      expect(remplacer("cles.json", N.utf8("true")).controles_en_echec).to.deep.equal(["E-8"]);
      expect(remplacer("approbations.json", N.utf8('"x"')).controles_en_echec).to.deep.equal(["A-1"]);
      const canon = remplacer("evenement.json", N.utf8('{"seq":4,"seq":4}'));
      expect(canon.controles_en_echec).to.deep.equal(["E-2"]);
      expect(canon.evenement).to.equal(null);
    });

    it("pièces fournies à part (E-6) et second manifeste (continuité, P-5)", function () {
      const fichiers = dossierDeReference();
      const bonne = N.utf8("piece 1 (contenu fictif) : constat du 2026-10-28");
      expect(N.verifierDossier(fichiers, { pieces: [bonne] }).verdict).to.equal("valide");
      expect(N.verifierDossier(fichiers, { pieces: [N.utf8("pièce inconnue")] }).controles_en_echec).to.deep.equal(["E-6"]);
      expect(N.verifierDossier(fichiers, { manifesteSuivant: MANIFESTE_2 }).verdict).to.equal("valide");
      expect(N.verifierDossier(fichiers, { manifestePrecedent: MANIFESTE_2 }).controles_en_echec).to.deep.equal(["P-5"]);
    });

    it("partie réservée déclarée présente : sa vérification relève de CT-6, le verdict de la bibliothèque est invalide", function () {
      const fichiers = dossierDeReference();
      fichiers.set("validateurs.json", N.utf8("{}\n"));
      const r = N.verifierDossier(reindexer(fichiers));
      expect(r.controles_en_echec).to.deep.equal([]);
      expect(r.non_executes_bloquants).to.deep.equal(["partie validateurs (vérification CT-6)"]);
      expect(r.verdict).to.equal("invalide");
    });

    it("voisin à date inexistante : E-1 seul ; voisin suivant d'une autre clé : C-3", function () {
      const fichiers = dossierDeReference();
      const voisins = { version: 0, previous: ev(3), next: N.scellerEvenement({ ...ev(5), ts: "2026-02-30T13:59:59.999Z" }, G1) };
      fichiers.set("voisins.json", enFichier(voisins));
      const r = N.verifierDossier(reindexer(fichiers));
      expect(r.controles_en_echec).to.include("E-1");
      const f2 = dossierDeReference();
      f2.set("voisins.json", enFichier({ version: 0, previous: ev(3), next: N.scellerEvenement({ ...ev(5), recorder_key_id: "rec-test-02" }, G2) }));
      expect(N.verifierDossier(reindexer(f2)).controles_en_echec).to.include("C-3");
    });
  });

  describe("attestation de périmètre hors dossier (CT-7 §7)", function () {
    const partie = () => structuredClone(blocs("attestation_perimetre")[0]);

    it("condensé D_P et signatures des comptes 1 et 2 reproduits", function () {
      const { signed, approver_set } = partie();
      expect(N.utf8(N.jcs(signed.attestation)).length).to.equal(3201);
      expect(N.octetsVersHex(N.condenseAttestation(signed.attestation))).to.equal(signed.digest);
      expect(signed.signatures.map((s, i) => N.signerAttestation(COMPTES[i], signed.attestation))).to.deep.equal(signed.signatures.map((s) => s.signature));
      const r = N.verifierAttestationSignee(signed, approver_set);
      expect(r.retained).to.equal(true);
      expect(r.recovered).to.deep.equal(signed.signatures.map((s) => s.address));
    });

    it("AT-1 refuse une validité de plus de 366 jours, des journaux en double, un agent hors journaux, des signataires en double", function () {
      const essai = (f) => {
        const { signed, approver_set } = partie();
        f(signed.attestation);
        return N.verifierAttestationSignee(signed, approver_set).checks[0].status;
      };
      expect(essai(() => {})).to.equal("reussi");
      expect(essai((P) => (P.validity.until = "2027-11-02T00:00:00.001Z"))).to.equal("echoue");
      expect(essai((P) => (P.validity.until = "2027-11-02T00:00:00.000Z"))).to.equal("reussi"); // 366 jours exactement
      expect(essai((P) => (P.validity.from = "2027-02-01T00:00:00.000Z"))).to.equal("echoue");
      expect(essai((P) => P.journals.push(structuredClone(P.journals[0])))).to.equal("echoue");
      expect(essai((P) => (P.agents[0].journal_id = N.ZERO32))).to.equal("echoue");
      expect(essai((P) => (P.agents[1].agent_id = P.agents[0].agent_id))).to.equal("echoue");
      expect(essai((P) => (P.signatories[1].address = P.signatories[0].address))).to.equal("echoue");
      expect(essai((P) => (P.issued_at = "2026-02-29T16:00:00.000Z"))).to.equal("echoue");
    });

    it("AT-2, AT-3, AT-4 : condensé faux, signature haute, seuil non atteint", function () {
      const { signed, approver_set } = partie();
      expect(N.verifierAttestationSignee({ ...signed, digest: N.ZERO32 }, approver_set).checks.map((c) => c.status)).to.deep.equal(["reussi", "echoue", "reussi", "reussi"]);
      const haute = structuredClone(signed);
      haute.signatures[0].signature = N.octetsVersHex(N.formeHauteEip191(N.hexVersOctets(haute.signatures[0].signature)));
      expect(N.verifierAttestationSignee(haute, approver_set).checks.map((c) => c.status)).to.deep.equal(["reussi", "reussi", "echoue", "non_execute"]);
      const seul = { ...signed, signatures: [signed.signatures[0]] };
      expect(N.verifierAttestationSignee(seul, approver_set).checks[3].status).to.equal("echoue");
      expect(N.verifierAttestationSignee(signed, { ...approver_set, threshold: { required: 4, size: 3 } }).retained).to.equal(false);
    });
  });

  // -------------------------------------------------------------------------
  // Non-régression des constats de la relecture de l'étape 1. Chaque cas est
  // reconstruit ici depuis l'exemple de référence de CT-1 ou les vecteurs de
  // spec/vecteurs/ct-1 ; aucune donnée n'est lue hors du dépôt.
  describe("corrections de la relecture (non-régression)", function () {
    /**
     * Dossier de référence dont l'événement prouvé seq 4 est remplacé : seq 4
     * et seq 5 rescellés (rec-test-01), racine, chemin, manifeste et sa
     * signature (rec-test-02) recalculés. `ecrire` donne les octets d'une
     * partie (JSON indenté par défaut).
     */
    function dossierSeq4(modifier, ecrire = enFichier) {
      const e4 = N.scellerEvenement(modifier(ev(4)), G1);
      const e5 = N.scellerEvenement({ ...ev(5), prev_hash: e4.hash }, G1);
      const hashes = [D5[0], D5[1], D5[2], e4.hash, e5.hash];
      const manifeste = { ...MANIFESTE_1, root: N.racineMerkle(hashes) };
      const fichiers = dossierDeReference();
      fichiers.set("evenement.json", ecrire(e4));
      fichiers.set("voisins.json", enFichier({ version: 0, previous: ev(3), next: e5 }));
      fichiers.set("chemin.json", enFichier(N.preuveInclusion(3, hashes)));
      fichiers.set("manifeste.json", enFichier(manifeste));
      fichiers.set("manifeste.sig", enFichier(N.signerManifeste(manifeste, G2)));
      const index = N.analyserJson(fichiers.get("dossier.json"));
      fichiers.set("dossier.json", enFichier({ ...index, event: { seq: 4, hash: e4.hash } }));
      return reindexer(fichiers);
    }
    // Arguments de seq 4 remplacés par une référence en ligne de valeur v.
    const argumentsEnLigne = (v) => (e) => {
      const octets = N.jcsOctets(v);
      return { ...e, execution: { ...e.execution, arguments: { sha256: N.sha256Hex(octets), length: octets.length, redacted: false, value: v } } };
    };
    const imbrique = (n) => N.analyserJson("[".repeat(n) + "]".repeat(n));

    it("constat 1 : série de points d'une période sans événement, journal encore vide (last_seq = 0) : valide", function () {
      // Première période d'un journal, aucun événement : count = 0, deux points
      // tree_size = 0, last_hash nul, signés par rec-test-01, seule clé dont
      // valid_from précède les points (CT-1 §10.5 règles 2 et 5, §10.1).
      const ORG = EXEMPLE.get(4).org_id;
      const JOURNAL = "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164";
      const manifeste = {
        version: 0, org_id: ORG, journal_id: JOURNAL, period_start: 1793865600, period_end: 1793869200,
        first_seq: 1, last_seq: 0, count: 0, root: N.ZERO32, prev_period_hash: N.ZERO32, recorder_key_id: "rec-test-01",
        nonce: "0x" + "42".repeat(32), generated_at: "2026-11-05T09:00:00.100Z",
      };
      const cles = {
        version: 0, org_id: ORG, journal_id: JOURNAL,
        keys: [
          { ...CLES_EXEMPLE.keys[0], valid_to: "2026-11-05T09:59:58.000Z" },
          { ...CLES_EXEMPLE.keys[1], valid_from: "2026-11-05T09:59:58.000Z" },
        ],
      };
      const serie = (cle, graineCle) => {
        const points = [];
        for (const ts of ["2026-11-05T08:00:00.000Z", "2026-11-05T09:00:00.100Z"]) {
          const prev = points.length ? N.hacherPoint(points[points.length - 1]) : N.ZERO32;
          points.push(N.signerPoint({
            version: 0, org_id: ORG, journal_id: JOURNAL, period_start: 1793865600, tree_size: 0, root: N.ZERO32,
            last_seq: 0, last_hash: N.ZERO32, checkpoint_ts: ts, prev_checkpoint_hash: prev, key_id: cle,
          }, graineCle));
        }
        return points;
      };
      expect(N.ecartsManifeste(manifeste)).to.deep.equal([]);
      expect(N.verifierSeriePointsDeControle(serie("rec-test-01", G1), manifeste, [], cles)).to.deep.equal({ valide: true, rules_failed: [], errors: [] });
      // Une autre clé que celle en vigueur reste refusée.
      expect(N.verifierSeriePointsDeControle(serie("rec-test-02", G2), manifeste, [], cles).rules_failed).to.deep.equal(["cle_en_vigueur", "validite_cle"]);
    });

    it("constat 2 : fichier creux de 3 Gio déclaré absent : D-2 en échec, jamais lu ni d'exception ; bornes de CT-6 EX-4.13", function () {
      expect(N.TAILLES_MAX["jeton-rfc3161.der"]).to.equal(65536);
      expect(N.TAILLES_MAX["dossier.json"]).to.equal(1048576);
      expect(N.TAILLES_MAX["evenement.json"]).to.equal(16 * 1048576);
      expect(N.TAILLES_MAX["points-de-controle.json"]).to.equal(1048576);
      expect(N.TAILLES_MAX["attestation-perimetre.json"]).to.equal(4 * 1048576);
      expect(N.PLAFOND_LECTURE).to.equal(64 * 1048576);
      expect(Object.keys(N.TAILLES_MAX).sort()).to.deep.equal([...N.FICHIERS_DOSSIER].sort());
      const rep = fs.mkdtempSync(path.join(os.tmpdir(), "noyau-enorme-"));
      try {
        for (const [nom, o] of dossierDeReference()) fs.writeFileSync(path.join(rep, nom), o);
        const enorme = path.join(rep, "jeton-rfc3161.der");
        fs.writeFileSync(enorme, "");
        fs.truncateSync(enorme, 3 * 1024 ** 3);
        const lus = lireRepertoireDossier(rep);
        expect(lus.get("jeton-rfc3161.der")).to.deep.equal({ taille: 3 * 1024 ** 3, sha256: null });
        const r = verifierRepertoireDossier(rep);
        expect(r.verdict).to.equal("invalide");
        expect(r.controles_en_echec).to.deep.equal(["D-2"]);
        expect(statut(r, "D-2").details[0]).to.match(/jeton-rfc3161\.der déclaré absent, présent/);
      } finally {
        fs.rmSync(rep, { recursive: true, force: true });
      }
    });

    it("constat 2 : partie déclarée présente au-delà de sa limite : échec du contrôle porteur, SHA-256 non lu", function () {
      const f = dossierDeReference();
      f.set("evenement.json", new Uint8Array(N.TAILLES_MAX["evenement.json"] + 1));
      const r = N.verifierDossier(f);
      expect(r.controles_en_echec).to.deep.equal(["E-1"]);
      expect(statut(r, "E-1").details[0]).to.match(/au-delà de sa limite/);
      expect(statut(r, "D-2").statut).to.equal("reussi");
      expect(statut(r, "D-2").details[0]).to.match(/SHA-256 non calculé/);
      // Même lecture pour un fichier non lu rendu par lireRepertoireDossier.
      const g = dossierDeReference();
      g.set("chemin.json", { taille: 17 * 1048576, sha256: null });
      expect(N.verifierDossier(g).controles_en_echec).to.deep.equal(["M-2"]);
      const h = dossierDeReference();
      h.set("dossier.json", new Uint8Array(1048577));
      expect(N.verifierDossier(h)).to.include({ utilisable: true, verdict: "invalide" });
      expect(N.verifierDossier(h).controles_en_echec).to.deep.equal(["D-1"]);
    });

    it("constat 2 : attestation-perimetre.json creuse au-delà de 4 Mio (SHA-256 en flux, AT-1) et au-delà de 64 Mio (inutilisable)", function () {
      const rep = fs.mkdtempSync(path.join(os.tmpdir(), "noyau-attestation-"));
      try {
        const fichiers = dossierDeReference({ attestation: true });
        const partie = structuredClone(blocs("points_de_controle")[0]);
        partie.anchors.rfc3161 = null;
        fichiers.set("points-de-controle.json", enFichier(partie));
        for (const [nom, o] of reindexer(fichiers)) fs.writeFileSync(path.join(rep, nom), o);
        expect(verifierRepertoireDossier(rep).verdict).to.equal("valide");
        const chemin = path.join(rep, "attestation-perimetre.json");
        fs.truncateSync(chemin, 5 * 1048576); // 5 Mio : octets d'origine puis zéros
        const lu = lireRepertoireDossier(rep).get("attestation-perimetre.json");
        const attendu = createHash("sha256");
        attendu.update(fs.readFileSync(chemin));
        expect(lu).to.deep.equal({ taille: 5 * 1048576, sha256: "0x" + attendu.digest("hex") });
        const r = verifierRepertoireDossier(rep);
        expect(r.controles_en_echec).to.deep.equal(["D-2"]);
        expect(r.perimetre.verifications[0].status).to.equal("echoue");
        fs.truncateSync(chemin, 64 * 1048576 + 1);
        const r2 = verifierRepertoireDossier(rep);
        expect(r2).to.include({ utilisable: false, verdict: null });
        expect(r2.erreur).to.match(/^taille_depassee/);
      } finally {
        fs.rmSync(rep, { recursive: true, force: true });
      }
    });

    it("constat 3 : aucune profondeur maximale par défaut ; option profondeurMax ; 100 000 niveaux sans débordement de pile", function () {
      // 128 niveaux admis et 129 refusés avec la borne de CT-6 ; 260 admis sans borne.
      expect(() => N.analyserJson("[".repeat(128) + "]".repeat(128), { profondeurMax: N.PROFONDEUR_CT6 })).not.to.throw();
      expect(() => N.analyserJson("[".repeat(129) + "]".repeat(129), { profondeurMax: N.PROFONDEUR_CT6 })).to.throw(N.ErreurJson, /imbrication/);
      expect(N.jcs(imbrique(260))).to.equal("[".repeat(260) + "]".repeat(260));
      expect(() => N.jcs(imbrique(129), { profondeurMax: 128 })).to.throw(N.ErreurJson);
      expect(() => N.analyserJson("[]", { profondeurMax: -1 })).to.throw(TypeError);
      const cycle = { a: 1 };
      cycle.b = cycle;
      expect(() => N.jcs(cycle)).to.throw(N.ErreurJson, /cyclique/);
      // 100 000 niveaux : lecture, forme canonique et égalité itératives.
      const texte = '{"a":'.repeat(50000) + "[".repeat(50000) + "]".repeat(50000) + "}".repeat(50000);
      const profond = N.analyserJson(texte);
      expect(N.jcs(profond)).to.equal(texte);
      expect(N.canoniserTexte(texte)).to.equal(texte);
      expect(N.egaliteJson(profond, N.analyserJson(texte))).to.equal(true);
      expect(N.egaliteJson(profond, imbrique(100000))).to.equal(false);
      expect(N.canoniserTexte(texte, { profondeurMax: N.PROFONDEUR_CT6 })).to.equal(null);
    });

    it("constat 3 : événement conforme dont une valeur est imbriquée sur 260 niveaux, puis sur 100 000 : valide ; refusé (E-1) sous la borne de CT-6", function () {
      const f260 = dossierSeq4(argumentsEnLigne(imbrique(260)));
      const r = N.verifierDossier(f260);
      expect(r.verdict, JSON.stringify(r.controles_en_echec)).to.equal("valide");
      expect(N.verifierDossier(f260, { profondeurMax: N.PROFONDEUR_CT6 }).controles_en_echec).to.deep.equal(["E-1"]);
      // JSON.stringify ne sait pas écrire 100 000 niveaux : la partie est écrite par jcs.
      const f100k = dossierSeq4(argumentsEnLigne(imbrique(100000)), (o) => N.utf8(N.jcs(o)));
      let r100k;
      expect(() => (r100k = N.verifierDossier(f100k))).not.to.throw();
      expect(r100k.verdict, JSON.stringify(r100k.controles_en_echec)).to.equal("valide");
    });

    it("constat 3 : document de politique imbriqué sur 300 niveaux (valide-seq-13-at7-autre-version) : AT-6 réussie ; refusée sous la borne de CT-6", function () {
      const rep = path.join(RACINE, "spec", "vecteurs", "ct-1", "dossiers", "valide-seq-13-at7-autre-version");
      const fichiers = new Map(fs.readdirSync(rep).filter((n) => n !== "attendu.json").map((n) => [n, Uint8Array.from(fs.readFileSync(path.join(rep, n)))]));
      const partie = N.analyserJson(fichiers.get("attestation-perimetre.json"));
      const ancien = N.analyserJson(Buffer.from(partie.inscription.policy_document, "base64").toString("utf8"));
      const document = N.utf8(`{"perimeter":${N.jcs(ancien.perimeter)},"profond":${"[".repeat(300)}${"]".repeat(300)},"version":${JSON.stringify(ancien.version)}}`);
      const ins = structuredClone(partie.inscription.event);
      const valeur = { ...ins.execution.arguments.value, policy_sha256: N.sha256Hex(document) };
      const octets = N.jcsOctets(valeur);
      ins.execution.arguments = { sha256: N.sha256Hex(octets), length: octets.length, redacted: false, value: valeur };
      expect(ins.recorder_key_id).to.equal("rec-test-02");
      partie.inscription = { event: N.scellerEvenement(ins, G2), policy_document: N.encoderBase64(document) };
      fichiers.set("attestation-perimetre.json", enFichier(partie));
      const r = N.verifierDossier(reindexer(fichiers));
      expect(r.verdict).to.equal("valide");
      expect(r.perimetre.verifications.find((v) => v.id === "AT-6").status).to.equal("reussi");
      const borne = N.verifierDossier(fichiers, { profondeurMax: N.PROFONDEUR_CT6 });
      expect(borne.verdict).to.equal("valide");
      expect(borne.perimetre.verifications.find((v) => v.id === "AT-6").status).to.equal("echoue");
    });

    it("constat 4 : K-1 contrôle le schéma de la partie même quand P-1 échoue", function () {
      const essai = (modifierPoint) => {
        const fichiers = dossierDeReference({ points: true });
        const partie = structuredClone(blocs("points_de_controle")[0]);
        modifierPoint(partie);
        fichiers.set("points-de-controle.json", enFichier(partie));
        fichiers.set("manifeste.json", N.utf8("42"));
        return N.verifierDossier(reindexer(fichiers));
      };
      const defaut = essai((p) => (p.checkpoint.tree_size = "4"));
      expect(defaut.controles_en_echec).to.deep.equal(["P-1", "K-1"]);
      expect(defaut.non_executes_bloquants.filter((id) => id.startsWith("K-"))).to.deep.equal(["K-2", "K-3", "K-4", "K-5", "K-6", "K-7", "K-8", "K-9"]);
      const temoin = essai(() => {});
      expect(temoin.controles_en_echec).to.deep.equal(["P-1"]);
      expect(statut(temoin, "K-1")).to.include({ statut: "non_execute", raison: "prerequis_en_echec" });
    });

    it("constat 5 : un premier événement altéré ne fait pas disparaître les E-8 des autres événements", function () {
      const j = [1, 2, 3, 4, 5].map(ev);
      j[0] = { ...j[0], org_id: "0x" + "ab".repeat(32) };
      j[2] = N.scellerEvenement(j[2], G2); // seq 3 signée par une autre clé que rec-test-01
      const r = N.verifierJournal(j, CLES_EXEMPLE);
      const vus = r.diagnostics.map((d) => `${d.controle}:${d.seq}`);
      expect(vus).to.include.members(["E-7:1", "E-8:1", "E-8:3", "C-1:2", "C-2:2"]);
      expect(vus.filter((v) => v.startsWith("E-8"))).to.deep.equal(["E-8:1", "E-8:3"]);
      expect(r.diagnostics.find((d) => d.controle === "E-8" && d.seq === 1).message).to.match(/cles\.json : org_id .* différent de celui de l'événement/);
      expect(r.controles_en_echec).to.deep.equal(["E-7", "E-8", "C-1", "C-2"]);
    });

    it("constat 6 : treizième partie sans forme canonique (E-2) ou déclarée présente mais manquante (D-2 seul)", function () {
      const fichiers = dossierDeReference({ points: true });
      const texte = new TextDecoder().decode(fichiers.get("points-de-controle.json")).replace('"version": 0,', '"version": 0,\n  "version": 0,');
      fichiers.set("points-de-controle.json", N.utf8(texte));
      const r = N.verifierDossier(reindexer(fichiers));
      expect(r.controles_en_echec).to.deep.equal(["E-2"]);
      expect(statut(r, "E-2").details[0]).to.match(/points-de-controle\.json sans forme canonique/);
      expect(r.non_executes_bloquants).to.deep.equal(["K-1", "K-2", "K-3", "K-4", "K-5", "K-6", "K-7", "K-8", "K-9"]);
      // La même règle pour toute partie : chemin.json sans forme canonique → E-2.
      const g = dossierDeReference();
      g.set("chemin.json", N.utf8('{"version":0,"version":0}'));
      expect(N.verifierDossier(reindexer(g)).controles_en_echec).to.deep.equal(["E-2"]);
      // Partie déclarée présente, fichier absent : D-2 seul, comme evenement.json manquant.
      const manquant = (nom, options) => {
        const f = dossierDeReference(options);
        f.delete(nom);
        return N.verifierDossier(f);
      };
      const k = manquant("points-de-controle.json", { points: true });
      expect(k.controles_en_echec).to.deep.equal(["D-2"]);
      expect(statut(k, "K-1")).to.include({ statut: "non_execute", raison: "partie_manquante" });
      expect(k.non_executes_bloquants.filter((id) => id.startsWith("K-"))).to.have.length(9);
      expect(manquant("evenement.json").controles_en_echec).to.deep.equal(["D-2"]);
      const c = manquant("cles.json");
      expect(c.controles_en_echec).to.deep.equal(["D-2"]);
      expect(statut(c, "E-8")).to.include({ statut: "non_execute", raison: "partie_manquante" });
      const a = manquant("approbations.json");
      expect(a.controles_en_echec).to.deep.equal(["D-2"]);
      expect(statut(a, "A-1")).to.include({ statut: "non_execute", raison: "partie_manquante" });
    });

    it("constat 7 : ecartsManifeste refuse un org_id ou un journal_id nul", function () {
      expect(N.ecartsManifeste({ ...MANIFESTE_1, journal_id: N.ZERO32 })).to.deep.equal(["journal_id nul"]);
      expect(N.ecartsManifeste({ ...MANIFESTE_1, org_id: N.ZERO32 })).to.deep.equal(["org_id nul"]);
    });

    it("lectures alignées sur le texte : substitut CESU-8 → E-2 (BOM, octet invalide → E-1) ; signature sans approbateur → E-5 et E-9", function () {
      const avecOctets = (avant, octets) => {
        const f = dossierDeReference();
        const texte = new TextDecoder().decode(f.get("evenement.json")).replace('"service-sinistres"', '"service-sinistres@@"');
        const [a, b] = texte.split("@@");
        f.set("evenement.json", N.concatener(avant, N.utf8(a), octets, N.utf8(b)));
        return N.verifierDossier(reindexer(f));
      };
      expect(avecOctets(new Uint8Array(0), Uint8Array.of(0xed, 0xa0, 0x80)).controles_en_echec).to.deep.equal(["E-2"]);
      expect(avecOctets(new Uint8Array(0), Uint8Array.of(0xff)).controles_en_echec).to.deep.equal(["E-1"]);
      expect(avecOctets(Uint8Array.of(0xef, 0xbb, 0xbf), new Uint8Array(0)).controles_en_echec).to.deep.equal(["E-1"]);
      // Pour chaque i de signatures : une signature de trop échoue aussi à E-9.
      const e = ev(4);
      e.approval.signatures.push(e.approval.signatures[0]);
      const r = N.controlerEvenement(e, {}).controles;
      expect(r["E-5"].statut).to.equal("echoue");
      expect(r["E-9"].statut).to.equal("echoue");
      expect(r["E-9"].details).to.deep.equal([`signatures[2] recouvre ${e.approval.approvers[0]}, sans approvers[2]`]);
      // Un approbateur sans signature relève de E-5 seul.
      const f = ev(4);
      f.approval.signatures.pop();
      const r2 = N.controlerEvenement(f, {}).controles;
      expect([r2["E-5"].statut, r2["E-9"].statut]).to.deep.equal(["echoue", "reussi"]);
    });
  });

  describe("lecture d'un répertoire de dossier", function () {
    it("ne lit que dossier.json et les fichiers d'un index ; ignore les autres fichiers, les répertoires et les liens", function () {
      const rep = fs.mkdtempSync(path.join(os.tmpdir(), "noyau-dossier-"));
      try {
        for (const [nom, o] of dossierDeReference()) fs.writeFileSync(path.join(rep, nom), o);
        fs.writeFileSync(path.join(rep, "attendu.json"), "{}");
        fs.mkdirSync(path.join(rep, "preuve.ots"));
        fs.symlinkSync(path.join(rep, "cles.json"), path.join(rep, "registre.json"));
        const lus = lireRepertoireDossier(rep);
        expect([...lus.keys()].sort()).to.deep.equal(
          ["approbations.json", "chemin.json", "cles.json", "dossier.json", "evenement.json", "manifeste.json", "manifeste.sig", "voisins.json"],
        );
        expect(verifierRepertoireDossier(rep).verdict).to.equal("valide");
      } finally {
        fs.rmSync(rep, { recursive: true, force: true });
      }
    });
  });
});
