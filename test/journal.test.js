import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { Wallet, keccak256, toUtf8Bytes } from "ethers";
import { PROJECT_ROOT, anchorFingerprint, periodMetaDuManifeste } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";

// L'IMPLÉMENTATION DE RÉFÉRENCE DE CT-1 (scripts/lib/journal.mjs) : forme
// canonique JCS v0 (RFC 8785 restreinte aux entiers), Ed25519 (RFC 8032),
// hachage, signature et chaînage des événements, arbre de Merkle RFC 6962,
// manifeste de période, références, dossier de preuve et ses contrôles. Les
// valeurs attendues viennent des RFC (vecteurs publiés), des vecteurs de
// référence de Certificate Transparency, de l'exemple numérique de la
// spécification (lu dans spec/CT-1-evenements-et-formats.md) et des vecteurs
// de spec/vecteurs/ct-1, rejoués un par un. La ligne de commande
// scripts/verify/dossier.mjs et la génération déterministe des vecteurs sont
// testées en bout de chaîne.

const SPEC = path.join(PROJECT_ROOT, "spec");
const VECTEURS = path.join(SPEC, "vecteurs", "ct-1");
const SCHEMAS = J.registreSchemas(["evenement", "manifeste", "dossier"].map((n) => JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", `${n}-v0.schema.json`), "utf8"))));
const lireJSON = (fichier) => J.analyserJSONStrict(fs.readFileSync(fichier));
const lireDossier = (repertoire) => Object.fromEntries(fs.readdirSync(repertoire).filter((f) => f !== "attendu.json").map((f) => [f, fs.readFileSync(path.join(repertoire, f))]));
const graine = (id) => J.sha256(Buffer.from(`noortrace/vecteurs/v0/cle-enregistreur/${id}`, "utf8"));
const CLE_01 = J.cleEd25519DepuisGraine(graine("rec-test-01"));
const CLE_02 = J.cleEd25519DepuisGraine(graine("rec-test-02"));
const PUBS = { "rec-test-01": CLE_01.clePublique, "rec-test-02": CLE_02.clePublique };
const HARDHAT = {
  1: new Wallet("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"),
  2: new Wallet("0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"),
  3: new Wallet("0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"),
};

/** Les blocs JSON annotés `<!-- schema: … -->` de la spécification. */
function blocsSpec(marque) {
  const md = fs.readFileSync(path.join(SPEC, "CT-1-evenements-et-formats.md"), "utf8");
  const re = new RegExp(`<!-- schema: ${marque} -->\\n\`\`\`json\\n([\\s\\S]*?)\\n\`\`\``, "g");
  const out = [];
  let m;
  while ((m = re.exec(md))) out.push(J.analyserJSONStrict(m[1]));
  return out;
}
const EXEMPLE = {
  evenements: blocsSpec("evenement").sort((a, b) => a.seq - b.seq),
  manifestes: blocsSpec("manifeste"),
  manifesteSig: blocsSpec("manifeste_sig")[0],
  chemin: blocsSpec("chemin")[0],
  dossier: blocsSpec("dossier")[0],
  cles: blocsSpec("cles")[0],
  approbations: blocsSpec("approbations")[0],
};

function lancer(script, args) {
  const r = spawnSync(process.execPath, [path.join(PROJECT_ROOT, "scripts", ...script), ...args], { encoding: "utf8", cwd: PROJECT_ROOT });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

// ---------------------------------------------------------------------------
describe("CT-1 : forme canonique JCS v0 (RFC 8785 restreinte aux entiers)", function () {
  it("les cas limites de la section 4 donnent exactement la forme attendue", function () {
    const cas = [
      [{ b: 1, a: 2 }, '{"a":2,"b":1}'],
      [{ é: 1, z: 2, Z: 3 }, '{"Z":3,"z":2,"é":1}'],
      [{ é: 1 }, '{"é":1}'],
      [{ "a😀": 1 }, '{"a😀":1}'],
      [{ a: "x\u0001y" }, '{"a":"x\\u0001y"}'],
      [{ a: "\u007f" }, '{"a":"\u007f"}'],
      [{ a: "/" }, '{"a":"/"}'],
      [{ a: -0 }, '{"a":0}'],
      [{ a: [] }, '{"a":[]}'],
      [{ a: {} }, '{"a":{}}'],
      [{ a: "  é" }, '{"a":"  é"}'],
      [{ a: "\b\t\n\f\r\"\\" }, '{"a":"\\b\\t\\n\\f\\r\\"\\\\"}'],
      [{ a: "\u001f" }, '{"a":"\\u001f"}'],
      [[true, false, null, 9007199254740991, -9007199254740991], "[true,false,null,9007199254740991,-9007199254740991]"],
    ];
    for (const [entree, attendu] of cas) expect(J.canonicaliserJCS(entree), JSON.stringify(entree)).to.equal(attendu);
    expect(Buffer.from(J.canonicaliserJCS({ "a😀": 1 }), "utf8").length).to.equal(11, "la paire de substituts est écrite en UTF-8 sur 4 octets");
  });

  it("refuse les nombres non entiers ou hors intervalle, les substituts isolés, les valeurs non JSON", function () {
    for (const v of [{ a: 1.5 }, { a: 1e300 }, { a: 2 ** 53 }, { a: -(2 ** 53) }, { a: NaN }, { a: Infinity }]) expect(() => J.canonicaliserJCS(v), JSON.stringify(v)).to.throw(J.ErreurFormat);
    expect(() => J.canonicaliserJCS({ a: "\ud800" })).to.throw(J.ErreurFormat, /substitut/);
    expect(() => J.canonicaliserJCS({ a: "\udc00x" })).to.throw(J.ErreurFormat, /substitut/);
    expect(() => J.canonicaliserJCS({ "\ud800": 1 })).to.throw(J.ErreurFormat, /substitut/);
    expect(() => J.canonicaliserJCS({ a: 1n })).to.throw(J.ErreurFormat);
    expect(() => J.canonicaliserJCS(undefined)).to.throw(J.ErreurFormat);
    expect(J.canonicaliserJCS({ a: undefined, b: 1 })).to.equal('{"b":1}', "un membre undefined n'existe pas en JSON");
  });

  it("reproduit les exemples de la RFC 8785 (structure §3.2.3, tri Unicode par unités UTF-16)", function () {
    const structure = { 1: { f: { f: "hi", F: 5 }, "\n": 56 }, 10: {}, "": "empty", a: {}, 111: [{ e: "yes", E: "no" }], A: {} };
    expect(J.canonicaliserJCS(structure)).to.equal('{"":"empty","1":{"\\n":56,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}');
    const unicode = {
      "€": "Euro Sign",
      "\r": "Carriage Return",
      "\u000a": "Newline",
      1: "One",
      "\u0080": "Control\u007f",
      "😂": "Smiley",
      "ö": "Latin Small Letter O With Diaeresis",
      "דּ": "Hebrew Letter Dalet With Dagesh",
      "</script>": "Browser Challenge",
    };
    // Sortie attendue de la RFC : U+0080 et U+007F en clair, ö (U+00F6), € (U+20AC), 😂 (U+1F602) puis דּ (U+FB33, précomposé).
    expect(J.canonicaliserJCS(unicode)).to.equal(
      '{"\\n":"Newline","\\r":"Carriage Return","1":"One","</script>":"Browser Challenge","\u0080":"Control\u007f","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😂":"Smiley","דּ":"Hebrew Letter Dalet With Dagesh"}',
    );
  });

  it("équivaut à JSON.stringify après tri récursif des clés sur les événements des vecteurs", function () {
    const trier = (v) => (Array.isArray(v) ? v.map(trier) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, trier(v[k])])) : v);
    for (const ev of lireJSON(path.join(VECTEURS, "journal-valide", "evenements.json"))) expect(J.canonicaliserJCS(ev)).to.equal(JSON.stringify(trier(ev)));
  });

  it("l'analyseur strict refuse ce que JSON.parse accepte en silence : 412.0, 1e3, entier hors intervalle, clé en double, substitut isolé, BOM", function () {
    expect(J.analyserJSONStrict('{"a":412,"b":[1,-0,"x\\u00e9"],"c":null}')).to.deep.equal({ a: 412, b: [1, 0, "xé"], c: null });
    expect(J.analyserJSONStrict(Buffer.from('{"é":"😀"}', "utf8"))).to.deep.equal({ é: "😀" });
    const invalides = {
      '{"a":412.0}': /non entier/,
      '{"a":1e3}': /non entier/,
      '{"a":9007199254740993}': /intervalle sûr/,
      '{"a":-9007199254740992}': /intervalle sûr/,
      '{"a":1,"a":2}': /clé en double/,
      '{"a":{"b":1,"b":1}}': /clé en double/,
      '{"a":"\\ud800"}': /substitut/,
      '{"a":"\\udc00"}': /substitut/,
      '{"a":"\\ud800x"}': /substitut/,
      '{"a":"x\u0001"}': /contrôle/,
      '{"a":1} x': /après la valeur/,
      '{"a":01}': /,|attendu/,
      "": /fin de texte/,
      '{"a":tru}': /littéral/,
    };
    for (const [texte, motif] of Object.entries(invalides)) expect(() => J.analyserJSONStrict(texte), JSON.stringify(texte)).to.throw(J.ErreurJSON, motif);
    expect(() => J.analyserJSONStrict(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("{}")]))).to.throw(J.ErreurJSON, /ordre d'octets/);
    expect(() => J.analyserJSONStrict(Buffer.from([0x22, 0xff, 0x22]))).to.throw(J.ErreurJSON, /UTF-8/);
    const proto = J.analyserJSONStrict('{"__proto__":{"x":1},"a":1}');
    expect(Object.hasOwn(proto, "__proto__")).to.equal(true, "la clé __proto__ est un membre ordinaire");
    expect({}.x).to.equal(undefined, "aucune pollution du prototype");
  });

  it("rejoue jcs/cas-limites.json : forme canonique attendue, ou refus", function () {
    const v = lireJSON(path.join(VECTEURS, "jcs", "cas-limites.json"));
    expect(v.cas.length).to.be.at.least(14);
    expect(v.cas.filter((c) => c.canonical === null).length).to.equal(6);
    for (const c of v.cas) {
      if (c.canonical === null) expect(() => J.canonicaliserJCS(J.analyserJSONStrict(c.input)), c.name).to.throw(J.ErreurFormat);
      else expect(J.canonicaliserJCS(J.analyserJSONStrict(c.input)), c.name).to.equal(c.canonical);
    }
  });

  it("horodatages : la date doit exister dans le calendrier (section 3) ; Date.parse renormalise, estHorodatage refuse", function () {
    for (const faux of ["2026-02-30T10:00:00.000Z", "2026-04-31T00:00:00.000Z", "2026-02-29T00:00:00.000Z", "2026-11-31T09:40:00.000Z", "2026-11-05T09:59:58Z", "2026-11-05T09:59:58.000+00:00", "2026-11-05T09:59:60.000Z"]) {
      expect(J.estHorodatage(faux), faux).to.equal(false);
      expect(Number.isNaN(J.msHorodatage(faux)), faux).to.equal(true);
    }
    expect(new Date(Date.parse("2026-02-30T10:00:00.000Z")).toISOString()).to.equal("2026-03-02T10:00:00.000Z", "ce que Date.parse ferait seul");
    for (const vrai of ["2024-02-29T00:00:00.000Z", "2026-11-05T09:59:58.000Z", "2026-12-31T23:59:59.999Z", "2000-02-29T12:00:00.000Z"]) expect(J.estHorodatage(vrai), vrai).to.equal(true);
    const e4 = EXEMPLE.evenements[3];
    const resceller = (ev) => J.scellerEvenement(J.corpsEvenement(ev), CLE_01.clePrivee);
    const r = J.controlesEvenement(resceller({ ...e4, ts: "2026-02-30T13:52:41.090Z" }), { schemas: SCHEMAS, cles: EXEMPLE.cles });
    expect(r["E-1"].ok).to.equal(false, "un 30 février respecte le motif du schéma mais ne se décode pas : E-1");
    expect(r["E-1"].detail).to.match(/hors du calendrier/);
    expect(J.controlesEvenement(resceller({ ...e4, approval: { ...e4.approval, at: "2026-11-31T13:52:40.511Z" } }), { schemas: SCHEMAS, cles: EXEMPLE.cles })["E-1"].ok).to.equal(false, "approval.at : 31 novembre");
    expect(J.verifierCles({ ...EXEMPLE.cles, keys: [{ ...EXEMPLE.cles.keys[0], valid_to: "2026-02-30T00:00:00.000Z" }] }).join(" ")).to.match(/hors du calendrier/);
    expect(J.horodatagesHorsCalendrier([["/x", "2026-11-05T09:59:58.000Z"], ["/y", null], ["/z", "pas une date"]])).to.deep.equal([], "seuls les horodatages qui respectent le motif sans se décoder sont signalés ; les autres relèvent du schéma");
  });

  it("egalJSON compare structurellement", function () {
    expect(J.egalJSON({ a: [1, { b: null }] }, { a: [1, { b: null }] })).to.equal(true);
    expect(J.egalJSON({ a: 1 }, { a: 1, b: 2 })).to.equal(false);
    expect(J.egalJSON([1, 2], [2, 1])).to.equal(false);
    expect(J.egalJSON(null, {})).to.equal(false);
  });
});

// ---------------------------------------------------------------------------
describe("CT-1 : Ed25519 (RFC 8032)", function () {
  const VECTEURS_RFC8032 = [
    {
      nom: "TEST 1",
      graine: "0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      pub: "0xd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      message: "0x",
      sig: "0xe5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    {
      nom: "TEST 2",
      graine: "0x4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      pub: "0x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      message: "0x72",
      sig: "0x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    {
      nom: "TEST 3",
      graine: "0xc5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
      pub: "0xfc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
      message: "0xaf82",
      sig: "0x6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
  ];

  it("reproduit les vecteurs TEST 1, 2 et 3 de la RFC 8032 §7.1 (clé publique, signature, vérification)", function () {
    for (const v of VECTEURS_RFC8032) {
      const cle = J.cleEd25519DepuisGraine(v.graine);
      expect(cle.clePublique, v.nom).to.equal(v.pub);
      expect(J.signerEd25519(cle.clePrivee, v.message), v.nom).to.equal(v.sig);
      expect(J.signerEd25519(v.graine, v.message), `${v.nom} depuis la graine`).to.equal(v.sig);
      expect(J.verifierEd25519(v.pub, v.message, v.sig), v.nom).to.equal(true);
    }
  });

  it("refuse une signature altérée, un S non réduit, une clé de petit ordre ou non canonique, des longueurs incorrectes", function () {
    const { pub, message, sig } = VECTEURS_RFC8032[1];
    const alteree = sig.slice(0, 20) + (sig[20] === "0" ? "1" : "0") + sig.slice(21);
    expect(J.verifierEd25519(pub, message, alteree)).to.equal(false);
    expect(J.verifierEd25519(pub, "0x73", sig)).to.equal(false);
    // S + L : même point, S non réduit modulo l'ordre du groupe (RFC 8032 §5.1.7).
    const L = (1n << 252n) + 27742317777372353535851937790883648493n;
    const s = BigInt("0x" + Buffer.from(sig.slice(66), "hex").reverse().toString("hex"));
    const sPlusL = Buffer.from((s + L).toString(16).padStart(64, "0"), "hex").reverse().toString("hex");
    expect(J.verifierEd25519(pub, message, sig.slice(0, 66) + sPlusL)).to.equal(false);
    expect(J.verifierEd25519("0x" + "00".repeat(31) + "01", message, sig)).to.equal(false, "point neutre");
    expect(J.verifierEd25519("0x" + "ec" + "ff".repeat(30) + "7f", message, sig)).to.equal(false, "point d'ordre 2");
    expect(J.verifierEd25519("0x" + "ed" + "ff".repeat(30) + "7f", message, sig)).to.equal(false, "y = p, encodage non canonique");
    expect(J.verifierEd25519(pub, message, sig.slice(0, 128))).to.equal(false);
    expect(J.verifierEd25519(pub.slice(0, 60), message, sig)).to.equal(false);
    expect(J.verifierEd25519(pub.toUpperCase(), message, sig)).to.equal(false, "hexadécimal majuscule refusé");
  });

  it("dérive les clés de test de la section 13 depuis les graines documentées", function () {
    expect(graine("rec-test-01")).to.equal("0x6215c33a2801ef7f21a894e98924eba8d72e3514f5fe7929ce0b595f5d39fa79");
    expect(graine("rec-test-02")).to.equal("0x4aa9b030b0d9dbc1eb4e2619929bb7ace43b6479678c6162ea467c84a6bda5db");
    expect(CLE_01.clePublique).to.equal("0xe2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045");
    expect(CLE_02.clePublique).to.equal("0xfd08757fa4798c3c8757bbf5a0db49580cbcb80075ddb30f13f881b0f47aacb3");
    expect(J.clePubliqueEd25519(graine("rec-test-01"))).to.equal(CLE_01.clePublique);
    expect(HARDHAT[1].address.toLowerCase()).to.equal("0x70997970c51812dc3a010c7d01b50e0d17dc79c8");
    expect(HARDHAT[2].address.toLowerCase()).to.equal("0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc");
    expect(HARDHAT[3].address.toLowerCase()).to.equal("0x90f79bf6eb2c4f870365e785982e1f101e93b906");
  });
});

// ---------------------------------------------------------------------------
describe("CT-1 : événements, hachage, signature, approbation, rotation", function () {
  it("l'exemple de référence de la spécification (annexe A) est reproduit valeur par valeur", function () {
    expect(EXEMPLE.evenements.map((e) => e.seq)).to.deep.equal([1, 2, 3, 4, 5]);
    for (const e of EXEMPLE.evenements) {
      expect(J.hachageEvenement(e), `hash seq ${e.seq}`).to.equal(e.hash);
      expect(J.verifierSignatureEvenement(e, PUBS[e.recorder_key_id]), `sig seq ${e.seq}`).to.equal(true);
      expect(J.signerEvenement(e, CLE_01.clePrivee), `sig seq ${e.seq} reproduite`).to.equal(e.sig);
      const controles = J.controlesEvenement(e, { schemas: SCHEMAS, cles: EXEMPLE.cles });
      expect(Object.values(controles).filter((c) => c.ok === false), `contrôles seq ${e.seq}`).to.deep.equal([]);
    }
    const e4 = EXEMPLE.evenements[3];
    const C = J.canonicaliserJCS(J.corpsEvenement(e4));
    expect(Buffer.byteLength(C, "utf8")).to.equal(2188);
    expect(C.startsWith('{"approval":{"approvers":["0x70997970c51812dc3a010c7d01b50e0d17dc79c8"')).to.equal(true);
    expect(C.endsWith('"seq":4,"ts":"2026-11-03T13:52:41.090Z","version":0}')).to.equal(true);
    expect(e4.hash).to.equal("0x471dab56146ae2e4c678120af7faf5eed7b1f8e5db3657226de97614bde4dc00");
    expect(J.verifierChaine(EXEMPLE.evenements, { clesPubliques: PUBS })).to.deep.equal({ valide: true, diagnostics: [] });
    expect(Buffer.from(J.PREFIXE_EVENEMENT, "utf8").toString("hex")).to.equal("6e6f6f7274726163652f6576656e656d656e742f76300a");
    expect(Buffer.from(J.PREFIXE_SIGNATURE_EVENEMENT, "utf8").toString("hex")).to.equal("6e6f6f7274726163652f7369676e61747572652d6576656e656d656e742f76300a");
    expect(Buffer.from(J.PREFIXE_APPROBATION, "utf8").toString("hex")).to.equal("6e6f6f7274726163652f617070726f626174696f6e2f76300a");
    expect(Buffer.from(J.PREFIXE_ROTATION, "utf8").toString("hex")).to.equal("6e6f6f7274726163652f7369676e61747572652d726f746174696f6e2f76300a");
  });

  it("la décision d'approbation : JCS(A), D_A, signatures EIP-191 des comptes Hardhat 1 et 2, recouvrement", function () {
    const e3 = EXEMPLE.evenements[2];
    const A = J.objetApprobation(e3);
    expect(J.canonicaliserJCS(A)).to.equal(
      '{"decision":"approuve","journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","request_hash":"0xdd3b7036baeca6426596377870f5982e00ac1e4de7fb344cd1b2c5fa4bbefce0","ticket":"apr-1192"}',
    );
    expect(J.condenseApprobation(A)).to.equal("0x59b49949b9e97d7e3fd9d46a3992476dd2cc27c48e25ef77b467816d144f37a7");
    expect(J.signerApprobation(HARDHAT[1], A)).to.equal(e3.approval.signatures[0]);
    expect(J.signerApprobation(HARDHAT[2], A)).to.equal(e3.approval.signatures[1]);
    expect(J.verifierSignatureApprobation(A, e3.approval.signatures[1], e3.approval.approvers[1])).to.deep.equal({ ok: true, adresse: e3.approval.approvers[1], raison: null });
    // Compte 3 à la place du 2, s haut, v hors de {27, 28}, forme incorrecte.
    expect(J.verifierSignatureApprobation(A, J.signerApprobation(HARDHAT[3], A), e3.approval.approvers[1]).raison).to.match(/adresse recouvrée/);
    const sig = e3.approval.signatures[0];
    const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
    const s = BigInt("0x" + sig.slice(66, 130));
    const sHaut = (N - s).toString(16).padStart(64, "0");
    const vFlip = sig.slice(130) === "1b" ? "1c" : "1b";
    expect(J.verifierSignatureApprobation(A, sig.slice(0, 66) + sHaut + vFlip, e3.approval.approvers[0]).raison).to.match(/moitié haute/);
    expect(J.verifierSignatureApprobation(A, sig.slice(0, 130) + "00", e3.approval.approvers[0]).raison).to.match(/v = 0/);
    expect(J.verifierSignatureApprobation(A, sig.slice(0, 130), e3.approval.approvers[0]).raison).to.match(/65 octets/);
    expect(J.verifierReference(e3.execution.arguments)).to.deep.equal({ ok: true, raison: null });
  });

  it("la rotation de clé : JCS(R), contresignature par la nouvelle clé, cohérence E-10", function () {
    const e5 = EXEMPLE.evenements[4];
    const value = e5.execution.arguments.value;
    expect(J.canonicaliserJCS(J.objetRotation(value))).to.equal(
      '{"journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","new_key_id":"rec-test-02","new_public_key":"0xfd08757fa4798c3c8757bbf5a0db49580cbcb80075ddb30f13f881b0f47aacb3","old_key_id":"rec-test-01","org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","valid_from":"2026-11-03T13:59:59.999Z"}',
    );
    expect(J.contresignerRotation(value, CLE_02.clePrivee)).to.equal(value.counter_sig);
    expect(J.verifierContresignatureRotation(value)).to.equal(true);
    expect(J.verifierContresignatureRotation({ ...value, counter_sig: J.contresignerRotation(value, CLE_01.clePrivee) })).to.equal(false);
    expect(J.cleSuivanteAttendue(e5)).to.equal("rec-test-02");
    expect(J.cleSuivanteAttendue(EXEMPLE.evenements[0])).to.equal("rec-test-01");
    const annonce = J.annonceRotation({ org_id: e5.org_id, journal_id: e5.journal_id, old_key_id: "rec-test-01", new_key_id: "rec-test-02", new_public_key: CLE_02.clePublique, valid_from: e5.ts, cleNouvelle: CLE_02.clePrivee });
    expect(annonce).to.deep.equal(value);
    const sansContresignature = { ...e5, execution: { ...e5.execution, arguments: J.referenceEnLigne({ ...value, counter_sig: "0x" + "11".repeat(64) }) } };
    expect(J.controlesEvenement(sansContresignature, { cles: EXEMPLE.cles })["E-10"].ok).to.equal(false);
  });

  it("E-10 : cles.json annonce valid_from(nouvelle) = valid_to(ancienne) = ts de la rotation (section 8, règle 3) ; new_key_id différent de old_key_id", function () {
    const e5 = EXEMPLE.evenements[4];
    const cles = EXEMPLE.cles;
    const e10 = (ev, c) => J.controlesEvenement(ev, { schemas: SCHEMAS, cles: c })["E-10"];
    expect(e10(e5, cles).ok).to.equal(true);
    const modif = (id, champ, val) => ({ ...cles, keys: cles.keys.map((k) => (k.key_id === id ? { ...k, [champ]: val } : k)) });
    expect(e10(e5, modif("rec-test-02", "valid_from", "2026-11-03T13:00:00.000Z")).detail).to.match(/valid_from de rec-test-02/);
    expect(e10(e5, modif("rec-test-01", "valid_to", null)).detail).to.match(/valid_to de rec-test-01/);
    expect(e10(e5, modif("rec-test-01", "valid_to", "2026-11-03T14:30:00.000Z")).detail).to.match(/valid_to de rec-test-01/);
    expect(e10(e5, { "rec-test-01": CLE_01.clePublique, "rec-test-02": CLE_02.clePublique }).ok).to.equal(true, "sans validité annoncée (source sans dates), seule la clé publique est confrontée");
    const annonce = J.annonceRotation({ org_id: e5.org_id, journal_id: e5.journal_id, old_key_id: "rec-test-01", new_key_id: "rec-test-01", new_public_key: CLE_01.clePublique, valid_from: e5.ts, cleNouvelle: CLE_01.clePrivee });
    const memeCle = J.scellerEvenement(J.corpsEvenement({ ...e5, execution: { ...e5.execution, arguments: J.referenceEnLigne(annonce) }, effects: [{ ...e5.effects[0], object: "cle:rec-test-01" }] }), CLE_01.clePrivee);
    const r = e10(memeCle, cles);
    expect(r.ok).to.equal(false);
    expect(r.detail).to.match(/égal à old_key_id/);
  });

  it("les pièces de l'exemple donnent les références imprimées (SHA-256 des octets stockés, après rédaction)", function () {
    expect(J.reference('{"claim_id":"2026-77812","amount":"7400.00","currency":"CHF","beneficiary_iban":"[REDIGE:iban]"}', { redacted: true })).to.deep.equal({
      sha256: "0x0fb2fc1e0625e460687315e9861347a2f0ac8680068c84582080b3f46c8faaf9",
      length: 96,
      redacted: true,
    });
    expect(J.reference("piece 1 (contenu fictif) : constat du 2026-10-28").sha256).to.equal("0x2aca5294d591501378fe8629f9713fdf75af93a641fb1ab58c8e231edec823a4");
    expect(J.reference("prompt systeme fictif v3", { media_type: "text/plain" })).to.deep.equal({ sha256: "0xb71552443a0b6e9793dd337ab10d057b354013fba35c2c82fdbdfb6df99d6b58", length: 24, redacted: false, media_type: "text/plain" });
    const enLigne = J.referenceEnLigne({ b: 1, a: "é" });
    expect(enLigne).to.deep.equal({ sha256: J.sha256(Buffer.from('{"a":"é","b":1}', "utf8")), length: 16, redacted: false, value: { b: 1, a: "é" } });
    expect(J.verifierReference({ ...enLigne, length: 15 }).raison).to.match(/length/);
    expect(J.verifierReference({ ...enLigne, sha256: J.HASH_NUL }).raison).to.match(/sha256/);
    expect(J.verifierReference({ ...enLigne, redacted: true }).raison).to.match(/value interdite/);
    expect(J.verifierReference({ sha256: enLigne.sha256, length: 16, redacted: false }, Buffer.from('{"a":"é","b":1}', "utf8")).ok).to.equal(true);
    expect(J.verifierReference({ sha256: enLigne.sha256, length: 16, redacted: false }, Buffer.from("autre", "utf8")).ok).to.equal(false);
  });

  it("scellerEvenement produit un événement vérifiable ; toute modification est détectée", function () {
    const corps = J.corpsEvenement(EXEMPLE.evenements[1]);
    const ev = J.scellerEvenement(corps, CLE_01.clePrivee);
    expect(Object.keys(ev)).to.deep.equal(J.CLES_EVENEMENT);
    expect(ev.hash).to.equal(EXEMPLE.evenements[1].hash);
    expect(ev.sig).to.equal(EXEMPLE.evenements[1].sig);
    const modifie = { ...ev, intent: "autre intention" };
    expect(J.verifierHachageEvenement(modifie)).to.equal(false);
    expect(J.verifierSignatureEvenement(modifie, CLE_01.clePublique)).to.equal(false);
    expect(J.verifierSignatureEvenement({ ...modifie, hash: J.hachageEvenement(modifie) }, CLE_01.clePublique)).to.equal(false, "la signature ne dépend pas du champ hash : la réécrire ne la répare pas");
  });

  it("controlesEvenement nomme le contrôle en échec : E-3, E-4, E-5, E-6, E-7, E-8, E-11", function () {
    const e4 = EXEMPLE.evenements[3];
    const cles = EXEMPLE.cles;
    const echecs = (ev, opts = { schemas: SCHEMAS, cles }) => Object.entries(J.controlesEvenement(ev, opts)).filter(([, c]) => c.ok === false).map(([id]) => id);
    expect(echecs(e4)).to.deep.equal([]);
    const resceller = (ev) => J.scellerEvenement(J.corpsEvenement(ev), CLE_01.clePrivee);
    expect(echecs(resceller({ ...e4, execution: { ...e4.execution, tool: "noortrace.inconnu" } }))).to.include.members(["E-1", "E-3"]);
    expect(echecs(resceller({ ...e4, policy: { ...e4.policy, redaction: null } }))).to.deep.equal(["E-4"]);
    expect(echecs(resceller({ ...e4, approval: { ...e4.approval, signatures: e4.approval.signatures.slice(0, 1) } }))).to.deep.equal(["E-5"]);
    const e3 = EXEMPLE.evenements[2];
    expect(echecs(resceller({ ...e3, execution: { ...e3.execution, arguments: { ...e3.execution.arguments, length: 1 } } }))).to.deep.equal(["E-6"]);
    expect(echecs({ ...e4, hash: J.HASH_NUL })).to.deep.equal(["E-7"]);
    expect(echecs({ ...e4, sig: EXEMPLE.evenements[0].sig })).to.deep.equal(["E-8"]);
    expect(echecs({ ...e4, recorder_key_id: "rec-test-03" })).to.deep.equal(["E-7", "E-8"], "identifiant bien formé mais absent de cles.json : hash modifié, clé inconnue pour E-8 ; E-11 non exécuté");
    expect(J.controlesEvenement({ ...e4, recorder_key_id: "rec-test-03" }, { schemas: SCHEMAS, cles })["E-11"].execute).to.equal(false, "clé absente : E-11 non exécuté, l'échec est porté par E-8");
    expect(echecs({ ...e4, recorder_key_id: "-invalide" })).to.deep.equal(["E-1", "E-7", "E-8"]);
    // Table 5.3 : l'échange avec le modèle porte la référence à la réponse, la durée et le drapeau d'erreur (E-1 par le schéma, E-3 par la sorte).
    const e1 = EXEMPLE.evenements[0];
    expect(echecs(resceller({ ...e1, execution: { ...e1.execution, result: null, duration_ms: null, is_error: null } }))).to.deep.equal(["E-1", "E-3"]);
    expect(echecs(resceller({ ...e1, execution: { ...e1.execution, duration_ms: null } }))).to.deep.equal(["E-1", "E-3"]);
    expect(echecs(resceller({ ...e1, execution: { ...e1.execution, is_error: null } }))).to.deep.equal(["E-1", "E-3"]);
    const e3b = EXEMPLE.evenements[2];
    expect(echecs(resceller({ ...e3b, execution: { ...e3b.execution, duration_ms: 12 } }))).to.deep.equal(["E-1", "E-3"], "duration_ms doit être null pour une décision d'approbation");
    expect(echecs(e4, { schemas: SCHEMAS, cles: { ...cles, keys: [{ ...cles.keys[0], valid_to: "2026-11-03T13:00:00.000Z" }, cles.keys[1]] } })).to.deep.equal(["E-11"]);
    const sansCles = J.controlesEvenement(e4, { schemas: SCHEMAS });
    expect(sansCles["E-8"].execute).to.equal(false);
    expect(sansCles["E-11"].execute).to.equal(false);
  });
});

// ---------------------------------------------------------------------------
describe("CT-1 : chaînage", function () {
  const journal = () => lireJSON(path.join(VECTEURS, "journal-valide", "evenements.json"));
  const cles = () => lireJSON(path.join(VECTEURS, "journal-valide", "cles.json"));

  it("chainer reconstruit le journal des vecteurs à partir de ses corps (seq, prev_hash, hash, sig)", function () {
    const E = journal();
    const entrees = E.map((e) => {
      const { version, seq, org_id, journal_id, prev_hash, hash, sig, ...reste } = e;
      void version, seq, org_id, journal_id, prev_hash, hash, sig;
      return reste;
    });
    const reconstruit = J.chainer(entrees, { org_id: E[0].org_id, journal_id: E[0].journal_id, cles: { "rec-test-01": CLE_01.clePrivee, "rec-test-02": CLE_02.clePrivee } });
    expect(reconstruit).to.deep.equal(E);
    expect(() => J.chainer(entrees.slice(0, 1), { org_id: E[0].org_id, journal_id: E[0].journal_id, cles: {} })).to.throw(J.ErreurFormat, /aucune clé privée/);
  });

  it("le journal valide des vecteurs passe, et ses hachages sont ceux de attendu.json", function () {
    const E = journal();
    const attendu = lireJSON(path.join(VECTEURS, "journal-valide", "attendu.json"));
    expect(J.verifierChaine(E, { clesPubliques: cles() })).to.deep.equal({ valide: true, diagnostics: [] });
    expect(E.map((e) => e.hash)).to.deep.equal(attendu.hashes.map((h) => h.hash));
    expect(E.map((e) => e.sig)).to.deep.equal(attendu.hashes.map((h) => h.sig));
    expect(E.map((e) => J.octetsJCS(J.corpsEvenement(e)).length)).to.deep.equal(attendu.hashes.map((h) => h.canonical_length));
    expect(J.condenseApprobation(attendu.approbation.A)).to.equal(attendu.approbation.D_A);
    for (const e of E) expect(Object.values(J.controlesEvenement(e, { schemas: SCHEMAS, cles: cles() })).filter((c) => c.ok === false), `seq ${e.seq}`).to.deep.equal([]);
    const pieces = lireJSON(path.join(VECTEURS, "journal-valide", "pieces.json")).pieces;
    for (const p of pieces) expect(J.reference(p.texte).sha256, p.nom).to.equal(p.sha256);
    const refs = E.flatMap((e) => J.referencesEvenement(e).map((r) => r.ref.sha256));
    for (const p of pieces.filter((p) => p.nom !== "politique" && p.nom !== "prompt_systeme")) expect(refs, `pièce ${p.nom} référencée`).to.include(p.sha256);
  });

  it("suppression, modification, insertion, réordonnancement : diagnostics nommés des vecteurs", function () {
    for (const nom of ["journal-supprime", "journal-modifie", "journal-insere", "journal-insere-sans-cle", "journal-reordonne"]) {
      const attendu = lireJSON(path.join(VECTEURS, nom, "attendu.json"));
      const r = J.verifierChaine(lireJSON(path.join(VECTEURS, nom, "evenements.json")), { clesPubliques: cles() });
      expect(r.valide, nom).to.equal(false);
      expect(r.diagnostics.map(({ type, controle, seq }) => ({ type, controle, seq })), nom).to.deep.equal(attendu.diagnostics);
      expect(r.diagnostics.map((d) => d.message), nom).to.deep.equal(attendu.messages);
      // Tous les symptômes de la table 7.2 sont rapportés (section 7.2), dans l'ordre des contrôles de la table 11.4.
      expect(J.CONTROLES_DOSSIER.map((c) => c.id).filter((id) => r.diagnostics.some((d) => d.controle === id)), nom).to.deep.equal(attendu.controles_en_echec);
    }
    expect(lireJSON(path.join(VECTEURS, "journal-supprime", "attendu.json")).controles_en_echec).to.deep.equal(["C-1", "C-2"], "suppression : trou de seq et prev_hash rompu");
    expect(lireJSON(path.join(VECTEURS, "journal-modifie", "attendu.json")).controles_en_echec).to.deep.equal(["E-7", "E-8", "C-2"], "modification : E-7, E-8 sur l'événement, C-2 sur le suivant");
    expect(lireJSON(path.join(VECTEURS, "journal-insere-sans-cle", "attendu.json")).controles_en_echec).to.deep.equal(["E-8", "C-1", "C-2"], "insertion sans la clé : E-8 en plus");
  });

  it("détecte aussi un ts décroissant, un journal différent, une clé inattendue, une origine incorrecte, une rupture après rescellement", function () {
    const E = journal();
    const resceller = (ev) => J.scellerEvenement(J.corpsEvenement(ev), ev.recorder_key_id === "rec-test-01" ? CLE_01.clePrivee : CLE_02.clePrivee);
    const types = (evs) => J.verifierChaine(evs, { clesPubliques: cles() }).diagnostics.map((d) => `${d.type}:${d.controle}:${d.seq}`);
    expect(types(E.map((e) => (e.seq === 3 ? resceller({ ...e, ts: "2026-11-05T09:00:00.000Z" }) : e)))).to.deep.equal(["horodatage:C-1:3", "rupture:C-2:4"]);
    expect(types(E.map((e) => (e.seq === 2 ? resceller({ ...e, journal_id: keccak256(toUtf8Bytes("autre")) }) : e)))).to.deep.equal(["journal:C-1:2", "rupture:C-2:3", "journal:C-1:3"], "les deux liens autour de seq 2 changent de journal");
    expect(types(E.map((e) => (e.seq === 10 ? resceller({ ...e, recorder_key_id: "rec-test-01" }) : e)))).to.deep.equal(["cle:C-3:10", "rupture:C-2:11", "cle:C-3:11"], "seq 10 n'a pas la clé issue de la rotation, et seq 11 n'a plus celle de seq 10");
    expect(types([resceller({ ...E[0], prev_hash: E[1].hash }), ...E.slice(1)])).to.deep.equal(["origine:C-2:1", "rupture:C-2:2"]);
    expect(types(E.slice(3))).to.deep.equal([], "une tranche de journal qui commence après seq 1 est acceptée");
    expect(J.verifierChaine(E.slice(0, 11), { clesPubliques: cles() }).valide).to.equal(true, "la troncature de la fin n'est pas détectable par la chaîne seule");
    expect(J.verifierChaine(E).valide).to.equal(true, "sans clés publiques, les signatures ne sont pas contrôlées");
    expect(J.verifierChaine(E.map((e) => (e.seq === 5 ? { ...e, sig: E[0].sig } : e))).valide).to.equal(true);
    expect(types(E.map((e) => (e.seq === 5 ? { ...e, sig: E[0].sig } : e)))).to.deep.equal(["signature:E-8:5"]);
  });
});

// ---------------------------------------------------------------------------
describe("CT-1 : arbre de Merkle RFC 6962 et preuves d'inclusion", function () {
  // Vecteurs de référence de Certificate Transparency (implémentation de
  // référence de Google, merkletree_unittest) : huit feuilles de 0 à 16 octets.
  const FEUILLES_CT = ["0x", "0x00", "0x10", "0x2021", "0x3031", "0x40414243", "0x5051525354555657", "0x606162636465666768696a6b6c6d6e6f"];
  const RACINES_CT = [
    "0x6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "0xfac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "0xaeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "0xd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "0x4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "0x76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "0xddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "0x5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
  ];
  const CHEMINS_CT = [
    { m: 0, n: 1, path: [] },
    { m: 0, n: 8, path: ["0x96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", "0x5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "0x6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"] },
    { m: 5, n: 8, path: ["0xbc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b", "0xca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0", "0xd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"] },
    { m: 2, n: 3, path: ["0xfac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"] },
    { m: 1, n: 5, path: ["0x6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", "0x5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "0xbc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"] },
  ];

  it("racines des arbres de 1 à 8 feuilles des vecteurs de Certificate Transparency (dont 1, 2, 3 et 7)", function () {
    for (let n = 1; n <= 8; n++) expect(J.racineMerkle(FEUILLES_CT.slice(0, n)), `n = ${n}`).to.equal(RACINES_CT[n - 1]);
    expect(J.feuilleMerkle("0x")).to.equal(J.sha256(Buffer.from([0x00])), "feuille vide : SHA-256 d'un seul octet 0x00");
  });

  it("chemins d'audit RFC 6962 §2.1.1 des vecteurs de Certificate Transparency, et vérification RFC 9162 pour tout (m, n) jusqu'à 8", function () {
    for (const { m, n, path: attendu } of CHEMINS_CT) expect(J.cheminAudit(FEUILLES_CT.slice(0, n), m), `PATH(${m}, ${n})`).to.deep.equal(attendu);
    for (let n = 1; n <= 8; n++) {
      for (let m = 0; m < n; m++) {
        const p = J.preuveInclusion(FEUILLES_CT.slice(0, n), m);
        expect(p.root).to.equal(RACINES_CT[n - 1]);
        expect(J.verifierInclusion(p), `inclusion ${m}/${n}`).to.equal(true);
        expect(J.verifierInclusion({ ...p, leaf_index: (m + 1) % n }), `indice décalé ${m}/${n}`).to.equal(m + 1 === n && n === 1);
        if (p.path.length) {
          expect(J.verifierInclusion({ ...p, path: p.path.slice(0, -1) }), `tronqué ${m}/${n}`).to.equal(false);
          expect(J.verifierInclusion({ ...p, path: [...p.path, p.path[0]] }), `allongé ${m}/${n}`).to.equal(false);
        }
        if (p.path.length > 1) expect(J.verifierInclusion({ ...p, path: [p.path[1], p.path[0], ...p.path.slice(2)] }), `permuté ${m}/${n}`).to.equal(false);
      }
    }
    expect(J.verifierInclusion({ leaf_hash: J.HASH_NUL, leaf_index: 1, tree_size: 1, path: [], root: J.HASH_NUL })).to.equal(false, "m >= n");
    expect(J.verifierInclusion({ leaf_hash: J.HASH_NUL, leaf_index: 0, tree_size: 0, path: [], root: J.HASH_NUL })).to.equal(false, "arbre vide");
    expect(() => J.cheminAudit(FEUILLES_CT, 8)).to.throw(J.ErreurFormat);
  });

  it("période vide : racine nulle (convention PeriodRegistry), distincte de SHA-256(\"\") de la RFC 6962", function () {
    expect(J.racineMerkle([])).to.equal(J.HASH_NUL);
    expect(J.racineMerkle([])).to.not.equal(J.sha256(Buffer.alloc(0)));
    expect(J.sha256(Buffer.alloc(0))).to.equal("0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(J.puissanceDeDeuxInferieure(2)).to.equal(1);
    expect(J.puissanceDeDeuxInferieure(5)).to.equal(4);
    expect(J.puissanceDeDeuxInferieure(8)).to.equal(4);
    expect(J.puissanceDeDeuxInferieure(9)).to.equal(8);
  });

  it("l'exemple numérique de la section 9.4 (cinq feuilles) : feuilles, nœuds, racine, preuve de seq 4", function () {
    const D = EXEMPLE.evenements.map((e) => e.hash);
    const L = D.map(J.feuilleMerkle);
    expect(L).to.deep.equal([
      "0xd5e2098df5be8721f7343aab8ad414a5bea5b55bb0fb0e72eb8fb9bb6c3f5a8b",
      "0x3ef9fdf53c5fd27d37c20efdce9d0d8bfcfd459d491e5cb66dd3f384540d270c",
      "0x8380b74438d71a5fb81aa3b62f1c7e0b06cb0e9c73f5d5a42f44372e203fbf3e",
      "0x3617a8c28e38e476cc671a109baf783cd70e1f24eca0278280a215b28f1c55db",
      "0xa93b6b900d821b68a351fb3e8e986f8298a21254f1c348f108843f7ede2f1ec0",
    ]);
    const N01 = J.noeudMerkle(L[0], L[1]);
    const N23 = J.noeudMerkle(L[2], L[3]);
    const N0123 = J.noeudMerkle(N01, N23);
    expect(N01).to.equal("0xa5b5b030de6510a06da18b109b73e7b85c4afe3e6d0fb89b4bd9b53b3d42f79e");
    expect(N23).to.equal("0x2fb61705d23c09d71bebc1a297940ce119c3bda5b3357d39d76043cb554cfea8");
    expect(N0123).to.equal("0x22264c23c7f8fea323dd1998376576e0fa4d14c67dc577dc7a01e5ae9c2e4cf6");
    expect(J.racineMerkle(D)).to.equal("0x6782bad9bd4717caf61b261a0a7f86fa9263f4b5b76c1d80d4c3bfbe0512ed06");
    expect(J.preuveInclusion(D, 3)).to.deep.equal(EXEMPLE.chemin);
    expect(J.verifierInclusion(EXEMPLE.chemin)).to.equal(true);
  });

  it("rejoue merkle/arbres.json : racines et preuves des arbres de 0, 1, 2, 3, 12 et 1000 feuilles", function () {
    const v = lireJSON(path.join(VECTEURS, "merkle", "arbres.json"));
    expect(v.arbres.map((a) => a.n)).to.deep.equal([0, 1, 2, 3, 5, 8, 12, 1000]);
    for (const a of v.arbres) {
      expect(a.leaves.length).to.equal(a.n);
      expect(J.racineMerkle(a.leaves), `racine n = ${a.n}`).to.equal(a.root);
      for (const p of a.proofs) {
        expect(J.preuveInclusion(a.leaves, p.leaf_index), `preuve ${p.leaf_index}/${a.n}`).to.deep.equal(p);
        expect(J.verifierInclusion(p)).to.equal(true);
      }
    }
    const arbre = (n) => v.arbres.find((a) => a.n === n);
    expect(arbre(0).root).to.equal(J.HASH_NUL);
    expect(arbre(1000).proofs.map((p) => p.leaf_index)).to.include.members([0, 999]);
    expect(arbre(1000).proofs[0].path.length).to.equal(10);
    expect(arbre(12).leaves).to.deep.equal(lireJSON(path.join(VECTEURS, "journal-valide", "evenements.json")).map((e) => e.hash));
    expect(arbre(5).proofs.map((p) => p.leaf_index)).to.deep.equal([0, 1, 2, 3, 4], "toutes les feuilles de l'arbre à cinq feuilles, forme de l'exemple de la section 9.4");
    expect(arbre(5).proofs[4].path.length).to.equal(1, "la cinquième feuille n'a qu'un frère : N0123");
    expect(arbre(8).proofs.every((p) => p.path.length === 3)).to.equal(true, "arbre complet de huit feuilles");
  });
});

// ---------------------------------------------------------------------------
describe("CT-1 : manifeste de période", function () {
  it("l'exemple de la section 10 : construction, forme canonique, periodHash, signature, période vide, continuité, anchorFingerprint", function () {
    const [m1, m2] = EXEMPLE.manifestes;
    const hashes = EXEMPLE.evenements.map((e) => e.hash);
    expect(J.construireManifeste({ org_id: m1.org_id, journal_id: m1.journal_id, period_start: m1.period_start, first_seq: 1, hashes, recorder_key_id: "rec-test-02", nonce: m1.nonce, generated_at: m1.generated_at })).to.deep.equal(m1);
    expect(J.construireManifeste({ org_id: m2.org_id, journal_id: m2.journal_id, period_start: m2.period_start, first_seq: 6, hashes: [], prev_period_hash: J.hachageManifeste(m1), recorder_key_id: "rec-test-02", nonce: m2.nonce, generated_at: m2.generated_at })).to.deep.equal(m2);
    expect(J.canonicaliserJCS(m1)).to.equal(
      '{"count":5,"first_seq":1,"generated_at":"2026-11-03T14:00:00.250Z","journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","last_seq":5,"nonce":"0xcfcd0a8277074d0839e4469fdced701c0fdf2855f1001e17d3fada335da05547","org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","period_end":1793714400,"period_start":1793710800,"prev_period_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","recorder_key_id":"rec-test-02","root":"0x6782bad9bd4717caf61b261a0a7f86fa9263f4b5b76c1d80d4c3bfbe0512ed06","version":0}',
    );
    expect(J.hachageManifeste(m1)).to.equal("0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1");
    expect(J.hachageManifeste(m2)).to.equal("0x3ed80e52f0d52f184986da64ba009947998cfd41624899ad5137594c58f9be4b");
    expect(J.signerManifeste(m1, CLE_02.clePrivee)).to.deep.equal(EXEMPLE.manifesteSig);
    expect(J.signerManifeste(m2, CLE_02.clePrivee).sig).to.equal("0x054847990ed1662c10a2b5cde8d7389a17af5a074d6e068c0a3ed855b79d2368c4cd95e425d0b28a3534b108864018c6f6b9bfc994ab0bdc639adf5f0b9fbb03");
    expect(J.verifierSignatureManifeste(m1, EXEMPLE.manifesteSig, CLE_02.clePublique)).to.equal(true);
    expect(J.verifierSignatureManifeste(m1, EXEMPLE.manifesteSig, CLE_01.clePublique)).to.equal(false);
    expect(J.verifierManifeste(m1)).to.deep.equal([]);
    expect(J.verifierManifeste(m2)).to.deep.equal([]);
    expect(J.verifierContinuiteManifestes(m1, m2)).to.deep.equal({ valide: true, erreurs: [] });
    expect(anchorFingerprint({ orgId: m1.org_id, journalId: m1.journal_id, periodHash: J.hachageManifeste(m1) })).to.equal("0x3200e496c555b46459191c852a7f79b1e0b4156802cac2f2df7b80b0aa9d823b");
    expect(Buffer.from(J.PREFIXE_MANIFESTE, "utf8").toString("hex")).to.equal("6e6f6f7274726163652f6d616e6966657374652f76300a");
    expect(Buffer.from(J.PREFIXE_SIGNATURE_MANIFESTE, "utf8").toString("hex")).to.equal("6e6f6f7274726163652f7369676e61747572652d6d616e6966657374652f76300a");
    const meta = periodMetaDuManifeste(m1, { uri: "ipfs://exemple" });
    expect(meta).to.deep.equal({ orgId: m1.org_id, journalId: m1.journal_id, periodHash: J.hachageManifeste(m1), root: m1.root, periodStart: 1793710800n, periodEnd: 1793714400n, firstSeq: 1n, lastSeq: 5n, version: 0, uri: "ipfs://exemple" });
  });

  it("verifierManifeste et verifierContinuiteManifestes nomment les erreurs", function () {
    const [m1, m2] = EXEMPLE.manifestes;
    expect(J.verifierManifeste({ ...m1, period_end: m1.period_end + 1 }).join(" ")).to.match(/period_end/);
    expect(J.verifierManifeste({ ...m1, count: 4 }).join(" ")).to.match(/count 4/);
    expect(J.verifierManifeste({ ...m1, root: J.HASH_NUL }).join(" ")).to.match(/racine nulle/);
    expect(J.verifierManifeste({ ...m2, root: m1.root }).join(" ")).to.match(/période vide/);
    expect(J.verifierManifeste({ ...m1, period_start: m1.period_start + 1, period_end: m1.period_end + 1 }).join(" ")).to.match(/heure UTC pleine/);
    const c = J.verifierContinuiteManifestes(m1, { ...m2, first_seq: 7, period_start: m2.period_start + 3600, period_end: m2.period_end + 3600, prev_period_hash: J.HASH_NUL });
    expect(c.valide).to.equal(false);
    expect(c.erreurs).to.have.length(3);
    expect(c.erreurs.join(" ")).to.match(/discontinuité temporelle/).and.match(/discontinuité de séquence/).and.match(/prev_period_hash/);
    expect(() => J.construireManifeste({ org_id: m1.org_id, journal_id: m1.journal_id, period_start: 1, first_seq: 1, hashes: [], recorder_key_id: "k", nonce: m1.nonce, generated_at: m1.generated_at })).to.throw(J.ErreurFormat, /heure UTC pleine/);
  });

  it("rejoue manifestes/ : periodHash, signatures, PeriodMeta, anchorFingerprint, continuité, manifeste discontinu", function () {
    const attendu = lireJSON(path.join(VECTEURS, "manifestes", "attendu.json"));
    const cles = lireJSON(path.join(VECTEURS, "cles", "cles.json"));
    const manifestes = {};
    for (const p of attendu.periodes) {
      const m = lireJSON(path.join(VECTEURS, "manifestes", p.fichier));
      const sig = lireJSON(path.join(VECTEURS, "manifestes", p.fichier.replace(".json", ".sig")));
      manifestes[p.fichier] = m;
      expect(J.validerSchema(m, SCHEMAS[J.ID_SCHEMA_MANIFESTE], { registre: SCHEMAS }), p.fichier).to.deep.equal([]);
      expect(J.verifierManifeste(m), p.fichier).to.deep.equal([]);
      expect(J.canonicaliserJCS(m)).to.equal(p.canonical);
      expect(J.hachageManifeste(m), p.fichier).to.equal(p.period_hash);
      expect(sig).to.deep.equal({ version: 0, period_hash: p.period_hash, recorder_key_id: p.recorder_key_id, sig: p.sig });
      expect(J.verifierSignatureManifeste(m, sig, J.normaliserCles(cles).get(sig.recorder_key_id).public_key)).to.equal(true);
      expect(anchorFingerprint({ orgId: m.org_id, journalId: m.journal_id, periodHash: p.period_hash })).to.equal(p.anchor_fingerprint);
      const meta = periodMetaDuManifeste(m, { uri: "" });
      expect(JSON.parse(JSON.stringify(meta, (_k, v) => (typeof v === "bigint" ? Number(v) : v)))).to.deep.equal({ ...p.period_meta, uri: "" });
      expect(m.count === 0).to.equal(m.root === J.HASH_NUL);
    }
    expect(attendu.periodes.map((p) => p.count)).to.deep.equal([9, 3, 0]);
    for (const c of attendu.continuite) expect(J.verifierContinuiteManifestes(manifestes[c.de], manifestes[c.a])).to.deep.equal({ valide: true, erreurs: [] });
    const discontinu = lireJSON(path.join(VECTEURS, "manifestes", attendu.discontinu.fichier));
    expect(J.verifierContinuiteManifestes(manifestes[attendu.discontinu.precedent], discontinu)).to.deep.equal({ valide: false, erreurs: attendu.discontinu.erreurs });
    const sigDiscontinu = lireJSON(path.join(VECTEURS, "manifestes", "discontinu.sig"));
    expect(J.verifierSignatureManifeste(discontinu, sigDiscontinu, CLE_02.clePublique)).to.equal(true, "le manifeste discontinu est bien signé : seule la continuité le trahit");
  });
});

// ---------------------------------------------------------------------------
describe("CT-1 : validation contre les schémas JSON", function () {
  it("accepte les exemples de la spécification et refuse les écarts (membre inconnu, motif, énumération, oneOf, prefixItems)", function () {
    const e4 = EXEMPLE.evenements[3];
    expect(J.validerSchema(e4, SCHEMAS[J.ID_SCHEMA_EVENEMENT], { registre: SCHEMAS })).to.deep.equal([]);
    expect(J.validerSchema(EXEMPLE.dossier, SCHEMAS[J.ID_SCHEMA_DOSSIER], { registre: SCHEMAS })).to.deep.equal([]);
    expect(J.validerSchema(EXEMPLE.cles, SCHEMAS[J.ID_SCHEMA_DOSSIER], { registre: SCHEMAS, fragment: "#/$defs/cles" })).to.deep.equal([]);
    expect(J.validerSchema(EXEMPLE.chemin, SCHEMAS[J.ID_SCHEMA_DOSSIER], { registre: SCHEMAS, fragment: "#/$defs/chemin" })).to.deep.equal([]);
    expect(J.validerSchema({ version: 0, previous: EXEMPLE.evenements[2], next: null }, SCHEMAS[J.ID_SCHEMA_DOSSIER], { registre: SCHEMAS, fragment: "#/$defs/voisins" })).to.deep.equal([]);
    const erreurs = (v) => J.validerSchema(v, SCHEMAS[J.ID_SCHEMA_EVENEMENT], { registre: SCHEMAS }).map((e) => e.chemin);
    expect(erreurs({ ...e4, extra: 1 })).to.deep.equal(["/extra"]);
    expect(erreurs({ ...e4, hash: e4.hash.toUpperCase() })).to.deep.equal(["/hash"]);
    expect(erreurs({ ...e4, policy: { ...e4.policy, decision: "peut-etre" } })).to.include("/policy/decision");
    expect(erreurs({ ...e4, execution: { ...e4.execution, status: "retenue" } })).to.include.members(["/execution/result", "/execution/duration_ms", "/execution/is_error"]);
    expect(erreurs({ ...e4, execution: { ...e4.execution, arguments: { ...e4.execution.arguments, value: 1 } } })).to.include("/execution/arguments/value");
    expect(erreurs({ ...e4, effects: [{ ...e4.effects[0], currency: null }] })).to.include("/effects/0/currency");
    // Un approbateur en double : l'erreur remonte au oneOf de approval ; sur la définition elle-même, elle nomme approvers.
    const doublon = { ...e4.approval, approvers: [e4.approval.approvers[0], e4.approval.approvers[0]] };
    expect(erreurs({ ...e4, approval: doublon })).to.deep.equal(["/approval"]);
    expect(J.validerSchema(doublon, SCHEMAS[J.ID_SCHEMA_EVENEMENT], { registre: SCHEMAS, fragment: "#/$defs/approval" }).map((e) => `${e.chemin} : ${e.message}`)).to.deep.equal(["/approvers : éléments 0 et 1 identiques"]);
    const { intent, ...sansIntent } = e4;
    void intent;
    expect(erreurs(sansIntent)).to.deep.equal(["/"]);
    const dossierFaux = { ...EXEMPLE.dossier, parts: [...EXEMPLE.dossier.parts.slice(1), EXEMPLE.dossier.parts[0]] };
    expect(J.validerSchema(dossierFaux, SCHEMAS[J.ID_SCHEMA_DOSSIER], { registre: SCHEMAS }).length).to.be.greaterThan(0, "l'ordre des douze parties est imposé");
    expect(() => J.validerSchema({}, { $ref: "https://inconnu.example/x" }, { registre: SCHEMAS })).to.throw(J.ErreurFormat, /schéma référencé inconnu/);
  });

  it("uniqueItems est linéaire : 20000 adresses distinctes dans approver_set.members se valident en moins de deux secondes", function () {
    this.timeout(10_000);
    const membres = Array.from({ length: 20000 }, (_, i) => "0x" + (i + 1).toString(16).padStart(40, "0"));
    const app = { version: 0, ticket: "apr-1192", request_hash: J.HASH_NUL, approver_set: { threshold: { required: 1, size: 20000 }, members: membres, source: "test" }, events: [EXEMPLE.evenements[2]] };
    const debut = performance.now();
    expect(J.validerSchema(app, SCHEMAS[J.ID_SCHEMA_DOSSIER], { registre: SCHEMAS, fragment: "#/$defs/approbations" })).to.deep.equal([]);
    expect(performance.now() - debut).to.be.lessThan(2000);
    const doublon = { ...app, approver_set: { ...app.approver_set, members: [...membres.slice(0, 19999), membres[0]] } };
    expect(J.validerSchema(doublon, SCHEMAS[J.ID_SCHEMA_DOSSIER], { registre: SCHEMAS, fragment: "#/$defs/approbations" }).map((e) => e.message)).to.deep.equal(["éléments 0 et 19999 identiques"]);
  });
});

// ---------------------------------------------------------------------------
describe("CT-1 : dossier de preuve", function () {
  const approbationsExemple = {
    approver_set: { threshold: { required: 2, size: 3 }, members: ["0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", "0x90f79bf6eb2c4f870365e785982e1f101e93b906"], source: "comptes Hardhat 1 à 3 (vecteurs CT-1)" },
    events: [EXEMPLE.evenements[2]],
  };
  const dossierExemple = () =>
    J.assemblerDossier({
      evenement: EXEMPLE.evenements[3],
      previous: EXEMPLE.evenements[2],
      next: EXEMPLE.evenements[4],
      hashesPeriode: EXEMPLE.evenements.map((e) => e.hash),
      manifeste: EXEMPLE.manifestes[0],
      manifesteSig: EXEMPLE.manifesteSig,
      cles: EXEMPLE.cles,
      approbations: approbationsExemple,
      generated_at: EXEMPLE.dossier.generated_at,
    });

  it("assemble le dossier de référence de la section 11.1 : index identique, SHA-256 des douze parties, vérification valide, A-4 non exécuté", function () {
    const d = dossierExemple();
    expect(d.index).to.deep.equal(EXEMPLE.dossier);
    expect(Object.keys(d.fichiers).sort()).to.deep.equal(["approbations.json", "chemin.json", "cles.json", "dossier.json", "evenement.json", "manifeste.json", "manifeste.sig", "voisins.json"]);
    expect(J.analyserJSONStrict(d.fichiers["chemin.json"])).to.deep.equal(EXEMPLE.chemin);
    const rapport = J.verifierDossier(d.fichiers, { schemas: SCHEMAS });
    expect(rapport.valide, JSON.stringify(rapport.controles.filter((c) => c.ok === false))).to.equal(true);
    expect(rapport.controles.map((c) => c.id)).to.deep.equal(J.CONTROLES_DOSSIER.map((c) => c.id));
    const a4 = rapport.controles.find((c) => c.id === "A-4");
    expect(a4.execute).to.equal(false);
    expect(a4.detail).to.match(/non vérifiable/);
    expect(rapport.controles.filter((c) => c.id !== "A-4").every((c) => c.execute && c.ok === true)).to.equal(true);
    expect(rapport.partiesAbsentes.map((p) => p.file)).to.deep.equal(["jeton-rfc3161.der", "preuve.ots", "registre.json", "certificat-commit.json", "validateurs.json"]);
    expect(rapport.borne).to.match(/rien n'est prouvé sur la date/);
    expect(rapport.evenement).to.deep.equal({ seq: 4, hash: EXEMPLE.evenements[3].hash, ts: EXEMPLE.evenements[3].ts, tool: "sap.payments.create" });
    expect(rapport.nonExecutesBloquants).to.deep.equal([]);
    // approbations.json est imprimé en section 11.2 : même objet, même SHA-256 que dossier.json de la section 11.1.
    expect(J.analyserJSONStrict(d.fichiers["approbations.json"])).to.deep.equal(EXEMPLE.approbations);
    expect(J.sha256(Buffer.from(d.fichiers["approbations.json"], "utf8"))).to.equal(EXEMPLE.dossier.parts.find((p) => p.name === "approbations").sha256);
  });

  it("une partie présente réduite au littéral null (ou à un tableau) met en échec le seul contrôle qui la porte et rend le dossier invalide", function () {
    const base = lireDossier(path.join(VECTEURS, "dossiers", "valide-seq-7"));
    const cas = { "evenement.json": "E-1", "voisins.json": "C-1", "chemin.json": "M-2", "manifeste.json": "P-1", "manifeste.sig": "P-5", "cles.json": "E-8", "approbations.json": "A-1" };
    for (const contenu of ["null\n", "[]\n", "0\n"]) {
      for (const [file, controle] of Object.entries(cas)) {
        const idx = J.analyserJSONStrict(base["dossier.json"]);
        idx.parts.find((p) => p.file === file).sha256 = J.sha256(Buffer.from(contenu, "utf8"));
        const r = J.verifierDossier({ ...base, [file]: Buffer.from(contenu, "utf8"), "dossier.json": J.texteJSON(idx) }, { schemas: SCHEMAS });
        expect(r.valide, `${file} = ${contenu.trim()}`).to.equal(false);
        expect(J.controlesEnEchec(r), `${file} = ${contenu.trim()}`).to.deep.equal([controle]);
        expect(r.controles.find((c) => c.id === controle).detail, file).to.match(/objet JSON attendu/);
        if (file === "evenement.json") {
          expect(r.evenement, "rien n'est repris de l'index à la place de evenement.json").to.equal(null);
          expect(r.nonExecutesBloquants).to.include.members(["C-1", "C-2", "C-3", "M-1", "M-3", "P-2", "A-2", "A-3"]);
          expect(r.nonExecutesBloquants).to.not.include("A-4", "A-4 non exécuté est toujours admis");
        }
        if (file === "cles.json") expect(r.nonExecutesBloquants).to.include.members(["E-11", "P-5"]);
      }
    }
    // Un texte qui n'est pas du JSON est imputé au même contrôle ; un nombre non entier, à E-2.
    const idx = J.analyserJSONStrict(base["dossier.json"]);
    idx.parts.find((p) => p.file === "chemin.json").sha256 = J.sha256(Buffer.from("{ pas du json", "utf8"));
    expect(J.controlesEnEchec(J.verifierDossier({ ...base, "chemin.json": Buffer.from("{ pas du json", "utf8"), "dossier.json": J.texteJSON(idx) }, { schemas: SCHEMAS }))).to.deep.equal(["M-2"]);
    idx.parts.find((p) => p.file === "chemin.json").sha256 = J.sha256(Buffer.from('{"version":0.0}', "utf8"));
    expect(J.controlesEnEchec(J.verifierDossier({ ...base, "chemin.json": Buffer.from('{"version":0.0}', "utf8"), "dossier.json": J.texteJSON(idx) }, { schemas: SCHEMAS }))).to.deep.equal(["E-2"]);
    // dossier.json qui est du JSON mais pas un objet : D-1, et rien d'autre n'est exécuté.
    const r = J.verifierDossier({ ...base, "dossier.json": "null\n" }, { schemas: SCHEMAS });
    expect(J.controlesEnEchec(r)).to.deep.equal(["D-1"]);
    expect(r.valide).to.equal(false);
  });

  it("cles.json est rattaché au journal et ses clés sont uniques (E-8) ; verifierCles nomme les erreurs", function () {
    const base = lireDossier(path.join(VECTEURS, "dossiers", "valide-seq-7"));
    const ev = J.analyserJSONStrict(base["evenement.json"]);
    const c = J.analyserJSONStrict(base["cles.json"]);
    expect(J.verifierCles(c, ev)).to.deep.equal([]);
    expect(J.verifierCles({ ...c, journal_id: J.HASH_NUL }, ev).join(" ")).to.match(/journal_id/);
    expect(J.verifierCles({ ...c, org_id: J.HASH_NUL }, ev).join(" ")).to.match(/org_id/);
    const tierce = J.cleEd25519DepuisGraine(graine("rec-test-03")).clePublique;
    expect(J.verifierCles({ ...c, keys: [...c.keys, { ...c.keys[0], public_key: tierce }] }).join(" ")).to.match(/key_id rec-test-01 en double/);
    expect(J.verifierCles({ ...c, keys: [c.keys[0], { ...c.keys[1], public_key: c.keys[0].public_key }] }).join(" ")).to.match(/déjà portée/);
    expect(J.verifierCles({ ...c, keys: [{ ...c.keys[0], valid_to: "2026-10-31T00:00:00.000Z" }] }).join(" ")).to.match(/antérieur à valid_from/);
    expect(J.verifierCles(null)).to.deep.equal(["objet attendu"]);
    const avec = (cles) => J.verifierDossier(J.reindexerDossier({ ...base, "cles.json": J.texteJSON(cles) }).fichiers, { schemas: SCHEMAS });
    // Un doublon : E-8, quel que soit l'ordre des entrées (le verdict ne dépend pas de l'ordre de lecture).
    expect(J.controlesEnEchec(avec({ ...c, keys: [{ ...c.keys[0], public_key: tierce }, c.keys[0], c.keys[1]] }))).to.deep.equal(["E-8"]);
    expect(J.controlesEnEchec(avec({ ...c, keys: [c.keys[0], c.keys[1], { ...c.keys[0], public_key: tierce }] }))).to.deep.equal(["E-8"]);
    expect(J.controlesEnEchec(avec({ ...c, journal_id: keccak256(toUtf8Bytes("autre")) }))).to.deep.equal(["E-8"]);
  });

  it("P-3 : un voisin hors de l'intervalle de seq mais horodaté dans la période révèle un manifeste tronqué (fin et début de période)", function () {
    const E = lireJSON(path.join(VECTEURS, "journal-valide", "evenements.json"));
    const cles = lireJSON(path.join(VECTEURS, "cles", "cles.json"));
    const p1 = lireJSON(path.join(VECTEURS, "manifestes", "periode-1.json"));
    const dossier = (ev, previous, next, hashes, m) => J.verifierDossier(J.assemblerDossier({ evenement: ev, previous, next, hashesPeriode: hashes, manifeste: m, manifesteSig: J.signerManifeste(m, CLE_02.clePrivee), cles, generated_at: "2026-11-06T08:30:00.000Z" }).fichiers, { schemas: SCHEMAS });
    // Fin de période tronquée : last_seq 8, le voisin suivant seq 9 (09:59:58.000Z) est dans la période.
    const hashes8 = E.slice(0, 8).map((e) => e.hash);
    const fin = dossier(E[7], E[6], E[8], hashes8, { ...p1, last_seq: 8, count: 8, root: J.racineMerkle(hashes8) });
    expect(J.controlesEnEchec(fin)).to.deep.equal(["P-3"]);
    expect(fin.controles.find((c) => c.id === "P-3").detail).to.match(/next \(seq 9\).*manifeste tronqué/);
    // Début de période tronqué : first_seq 9, le voisin précédent seq 8 (09:31:49.120Z) est dans la période ; le voisin suivant seq 10 (10:04) est bien hors période.
    const debut = dossier(E[8], E[7], E[9], [E[8].hash], { ...p1, first_seq: 9, last_seq: 9, count: 1, root: J.racineMerkle([E[8].hash]) });
    expect(J.controlesEnEchec(debut)).to.deep.equal(["P-3"]);
    expect(debut.controles.find((c) => c.id === "P-3").detail).to.match(/previous \(seq 8\).*manifeste tronqué/);
    // Le manifeste complet de la période 1 : P-3 passe pour le même dossier de seq 9 (next seq 10 hors période, à partir de period_end).
    const complet = dossier(E[8], E[7], E[9], E.slice(0, 9).map((e) => e.hash), p1);
    expect(J.controlesEnEchec(complet)).to.deep.equal([]);
  });

  it("A-2 : la décision précède l'appel relayé (seq, approval.at <= ts) ; le dossier d'une décision la contient dans events", function () {
    const base = lireDossier(path.join(VECTEURS, "dossiers", "valide-seq-7"));
    const ev = J.analyserJSONStrict(base["evenement.json"]);
    const a = J.analyserJSONStrict(base["approbations.json"]);
    const resceller = (e) => J.scellerEvenement(J.corpsEvenement(e), CLE_01.clePrivee);
    const avec = (fichiers) => J.verifierDossier(J.reindexerDossier(fichiers).fichiers, { schemas: SCHEMAS });
    const tardive = avec({ ...base, "approbations.json": J.texteJSON({ ...a, events: [resceller({ ...a.events[0], seq: 8 })] }) });
    expect(tardive.controles.find((c) => c.id === "A-2").detail).to.match(/seq 8 n'est pas antérieur/);
    const at = avec({ ...base, "evenement.json": J.texteJSON(resceller({ ...ev, approval: { ...ev.approval, at: "2026-11-05T09:31:49.000Z" } })) });
    expect(at.controles.find((c) => c.id === "A-2").detail).to.match(/approval.at .* postérieur/);
    const decision = lireDossier(path.join(VECTEURS, "dossiers", "valide-seq-6"));
    expect(J.verifierDossier(decision, { schemas: SCHEMAS }).valide).to.equal(true);
    const ad = J.analyserJSONStrict(decision["approbations.json"]);
    const sansElle = avec({ ...decision, "approbations.json": J.texteJSON({ ...ad, events: [resceller({ ...ad.events[0], approval: { ...ad.events[0].approval, reason: "autre" } })] }) });
    expect(sansElle.controles.find((c) => c.id === "A-2").detail).to.match(/ne figure pas dans events/);
  });

  it("un dossier sans approbation déclare approbations.json absent avec sa raison ; reindexerDossier recalcule l'index", function () {
    const d = J.assemblerDossier({
      evenement: EXEMPLE.evenements[1],
      previous: EXEMPLE.evenements[0],
      next: EXEMPLE.evenements[2],
      hashesPeriode: EXEMPLE.evenements.map((e) => e.hash),
      manifeste: EXEMPLE.manifestes[0],
      manifesteSig: EXEMPLE.manifesteSig,
      cles: EXEMPLE.cles,
      generated_at: EXEMPLE.dossier.generated_at,
    });
    const partie = d.index.parts.find((p) => p.name === "approbations");
    expect(partie).to.deep.equal({ name: "approbations", file: "approbations.json", sha256: null, present: false, reason_if_absent: J.RAISON_AUCUNE_APPROBATION });
    const rapport = J.verifierDossier(d.fichiers, { schemas: SCHEMAS });
    expect(rapport.valide, JSON.stringify(rapport.controles.filter((c) => c.ok === false))).to.equal(true);
    expect(rapport.controles.find((c) => c.id === "A-2").execute).to.equal(false);
    expect(() => J.assemblerDossier({ ...d, evenement: EXEMPLE.evenements[3], previous: null, next: null, hashesPeriode: EXEMPLE.evenements.map((e) => e.hash), manifeste: EXEMPLE.manifestes[0], manifesteSig: EXEMPLE.manifesteSig, cles: EXEMPLE.cles, generated_at: "2026-11-04T09:15:00.000Z" })).to.throw(J.ErreurFormat, /approbations requises/);
    const modifie = { ...d.fichiers, "voisins.json": J.texteJSON({ version: 0, previous: null, next: null }) };
    const r2 = J.reindexerDossier(modifie);
    expect(r2.index.parts.find((p) => p.name === "voisins").sha256).to.equal(J.sha256(Buffer.from(modifie["voisins.json"], "utf8")));
    expect(r2.index.parts.find((p) => p.name === "approbations").reason_if_absent).to.equal(J.RAISON_AUCUNE_APPROBATION);
    expect(J.controlesEnEchec(J.verifierDossier(r2.fichiers, { schemas: SCHEMAS }))).to.deep.equal(["C-1"], "previous null alors que seq = 2");
  });

  it("une entrée qui n'est pas un dossier est inutilisable, pas invalide", function () {
    expect(() => J.verifierDossier({}, { schemas: SCHEMAS })).to.throw(J.DossierInutilisable, /dossier.json absent/);
    expect(() => J.verifierDossier({ "dossier.json": "{" }, { schemas: SCHEMAS })).to.throw(J.DossierInutilisable, /illisible/);
    expect(() => J.verifierDossier(dossierExemple().fichiers, {})).to.throw(J.DossierInutilisable, /schémas/);
    const r = J.verifierDossier({ "dossier.json": '{"version":0}' }, { schemas: SCHEMAS });
    expect(r.valide).to.equal(false);
    expect(J.controlesEnEchec(r)).to.deep.equal(["D-1"]);
    expect(r.controles.filter((c) => c.id !== "D-1").every((c) => !c.execute)).to.equal(true);
  });

  it("rejoue dossiers/ : le dossier valide et chaque dossier invalide donnent exactement les contrôles attendus", function () {
    const racine = path.join(VECTEURS, "dossiers");
    const noms = fs.readdirSync(racine).sort();
    expect(noms).to.include("valide-seq-7");
    expect(noms.filter((n) => n.startsWith("invalide-")).length).to.be.at.least(6);
    for (const nom of noms) {
      const attendu = lireJSON(path.join(racine, nom, "attendu.json"));
      const rapport = J.verifierDossier(lireDossier(path.join(racine, nom)), { schemas: SCHEMAS });
      expect(rapport.valide, nom).to.equal(attendu.valide);
      expect(J.controlesEnEchec(rapport), nom).to.deep.equal(attendu.controles_en_echec);
      if (attendu.controle) expect(attendu.controles_en_echec, nom).to.include(attendu.controle);
    }
    const cibles = noms.map((n) => lireJSON(path.join(racine, n, "attendu.json")).controle).filter(Boolean);
    for (const c of J.CONTROLES_DOSSIER) expect(cibles, `au moins un dossier vise ${c.id} (section 11.5)`).to.include(c.id);
    expect(noms.filter((n) => n.startsWith("valide-"))).to.deep.equal(["valide-seq-6", "valide-seq-7"]);
    const valide = J.verifierDossier(lireDossier(path.join(racine, "valide-seq-7")), { schemas: SCHEMAS });
    expect(valide.evenement.seq).to.equal(7);
    expect(valide.controles.find((c) => c.id === "A-3").detail).to.match(/2 approbateur\(s\) distinct\(s\) sur un seuil de 2\/3/);
  });
});

// ---------------------------------------------------------------------------
describe("CT-1 : ligne de commande scripts/verify/dossier.mjs", function () {
  this.timeout(60_000);
  const racine = path.join(VECTEURS, "dossiers");

  it("dossier valide : code 0, rapport lisible VALIDE, rapport JSON", function () {
    const r = lancer(["verify", "dossier.mjs"], [path.join(racine, "valide-seq-7")]);
    expect(r.code, r.stderr).to.equal(0);
    expect(r.stdout).to.match(/Résultat {6}: VALIDE/);
    expect(r.stdout).to.match(/\[non exécuté\] A-4/);
    expect(r.stdout).to.match(/Borne/);
    const j = lancer(["verify", "dossier.mjs"], [path.join(racine, "valide-seq-7"), "--json"]);
    expect(j.code).to.equal(0);
    const rapport = JSON.parse(j.stdout);
    expect(rapport.valide).to.equal(true);
    expect(rapport.controlesEnEchec).to.deep.equal([]);
    expect(rapport.controles).to.have.length(J.CONTROLES_DOSSIER.length);
    expect(rapport.evenement.seq).to.equal(7);
  });

  it("chaque dossier invalide : code 1 et le contrôle attendu en échec", function () {
    for (const nom of fs.readdirSync(racine).filter((n) => n.startsWith("invalide-")).sort()) {
      const attendu = lireJSON(path.join(racine, nom, "attendu.json"));
      const r = lancer(["verify", "dossier.mjs"], [path.join(racine, nom), "--json"]);
      expect(r.code, nom).to.equal(1);
      const rapport = JSON.parse(r.stdout);
      expect(rapport.valide, nom).to.equal(false);
      expect(rapport.controlesEnEchec, nom).to.deep.equal(attendu.controles_en_echec);
      const lisible = lancer(["verify", "dossier.mjs"], [path.join(racine, nom)]);
      expect(lisible.code, nom).to.equal(1);
      expect(lisible.stdout, nom).to.match(new RegExp(`Résultat {6}: INVALIDE — contrôle\\(s\\) en échec : ${attendu.controles_en_echec.join(", ")}`));
    }
  });

  it("une partie inexploitable (evenement.json = null) rend le dossier INVALIDE, code 1, sans reprendre l'index", function () {
    const r = lancer(["verify", "dossier.mjs"], [path.join(racine, "invalide-partie-nulle")]);
    expect(r.code).to.equal(1);
    expect(r.stdout).to.match(/Résultat {6}: INVALIDE — contrôle\(s\) en échec : E-1 ; contrôle\(s\) non exécuté\(s\) sans raison admise : /);
    expect(r.stdout).to.not.match(/^Événement/m);
    const j = JSON.parse(lancer(["verify", "dossier.mjs"], [path.join(racine, "invalide-partie-nulle"), "--json"]).stdout);
    expect(j.valide).to.equal(false);
    expect(j.evenement).to.equal(null);
    expect(j.nonExecutesBloquants).to.include.members(["C-1", "M-1", "P-2"]);
  });

  it("entrée inutilisable : code 2 (répertoire absent, répertoire sans dossier.json, dossier.json qui n'est pas du JSON, option inconnue, schémas introuvables)", function () {
    const vide = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-dossier-"));
    expect(lancer(["verify", "dossier.mjs"], [path.join(vide, "inexistant")]).code).to.equal(2);
    const r = lancer(["verify", "dossier.mjs"], [vide, "--json"]);
    expect(r.code).to.equal(2);
    expect(r.stderr).to.match(/dossier.json absent/);
    expect(JSON.parse(r.stdout).valide).to.equal(null);
    fs.writeFileSync(path.join(vide, "dossier.json"), "{ pas du json");
    expect(lancer(["verify", "dossier.mjs"], [vide]).code).to.equal(2);
    expect(lancer(["verify", "dossier.mjs"], [path.join(racine, "valide-seq-7"), "--inconnue"]).code).to.equal(2);
    expect(lancer(["verify", "dossier.mjs"], [path.join(racine, "valide-seq-7"), "--schemas", path.join(vide, "nulle-part")]).code).to.equal(2);
    expect(lancer(["verify", "dossier.mjs"], []).code).to.equal(2);
    expect(lancer(["verify", "dossier.mjs"], ["--aide"]).code).to.equal(0);
    fs.rmSync(vide, { recursive: true, force: true });
  });
});

// ---------------------------------------------------------------------------
describe("CT-1 : génération déterministe des vecteurs", function () {
  this.timeout(120_000);

  it("rejouer scripts/vecteurs/generer-ct1.mjs produit exactement les mêmes fichiers que spec/vecteurs/ct-1", function () {
    const sortie = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-vecteurs-"));
    const r = lancer(["vecteurs", "generer-ct1.mjs"], ["--sortie", sortie]);
    expect(r.code, r.stderr).to.equal(0);
    const lister = (racine) => {
      const out = [];
      const marcher = (d) => {
        for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
          const p = path.join(d, e.name);
          if (e.isDirectory()) marcher(p);
          else out.push(path.relative(racine, p));
        }
      };
      marcher(racine);
      return out.sort();
    };
    // Seules les entrées que le générateur possède sont comparées : d'autres
    // composants peuvent déposer leurs propres fichiers dans spec/vecteurs/ct-1.
    const produits = lister(sortie);
    const possedees = new Set(produits.map((f) => f.split(path.sep)[0]));
    const attendus = lister(VECTEURS).filter((f) => possedees.has(f.split(path.sep)[0]));
    expect(produits).to.deep.equal(attendus);
    expect(produits.length).to.be.at.least(100);
    for (const f of produits) {
      expect(J.sha256(fs.readFileSync(path.join(sortie, f))), f).to.equal(J.sha256(fs.readFileSync(path.join(VECTEURS, f))));
    }
    fs.rmSync(sortie, { recursive: true, force: true });
    const index = fs.readFileSync(path.join(VECTEURS, "INDEX.md"), "utf8");
    for (const d of fs.readdirSync(path.join(VECTEURS, "dossiers"))) expect(index, d).to.include(`\`${d}/\``);
  });
});
