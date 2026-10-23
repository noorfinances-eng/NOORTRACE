import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";
import * as O from "../scripts/lib/ots.mjs";
import * as G from "../scripts/vecteurs/ct6/ots.mjs";
import { manifestesCT1 } from "../scripts/vecteurs/ct6/rfc3161.mjs";

// CONTRÔLE 5 DE CT-6 (spec/CT-6-verificateur.md §10) : format .ots officiel,
// exécution des opérations du profil v0, en-têtes Bitcoin (double SHA-256,
// nBits, preuve de travail, chaînage jusqu'au point de contrôle), vérifications
// O-1 à O-7, statut du contrôle, faits et proposition de l'énoncé ; vecteurs
// spec/vecteurs/ct-6/ots rejoués un par un, et leur génération déterministe.
// Les cas particuliers sont construits ici avec l'encodeur du module.

const VECTEURS = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-6", "ots");
const ATTENDU = JSON.parse(fs.readFileSync(path.join(VECTEURS, "attendu.json"), "utf8"));
const lireJSON = (f) => JSON.parse(fs.readFileSync(path.join(VECTEURS, f), "utf8"));
const CHAINE = lireJSON("entetes/chaine.json");
const ANCRES = { bitcoin: ATTENDU.bitcoin_anchor };
const PH = manifestesCT1().map((m) => m.periodHash);
const preuve = (nom) => fs.readFileSync(path.join(VECTEURS, "preuves", `${nom}.ots`));
const statuts = (r) => Object.fromEntries(r.checks.map((c) => [c.id, c.reason ? `${c.status}:${c.reason}` : c.status]));
const echecs = (r) => r.checks.filter((c) => c.status === "echoue").map((c) => c.id);
const verifier = (octets, { periodHash = PH[0], entetes = CHAINE, ancres = ANCRES, langue = "fr" } = {}) => O.verifierPreuve(octets, { periodHash, entetes, ancres, langue });
const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
const E1 = Buffer.from(PH[0].slice(2), "hex");
const OPS1 = G.operationsPeriode(1);
const TOUT1 = [...OPS1.calendrier, ...OPS1.bitcoin];
const bitcoin = (hauteur) => ({ type: "attestation", attestation: { genre: "bitcoin", hauteur } });
const attente = (uri) => ({ type: "attestation", attestation: { genre: "en_attente", uri } });
const enTete = Buffer.concat([O.EN_TETE_MAGIQUE, Buffer.from([0x01, 0x08]), E1]);

describe("CT-6 contrôle 5 : format .ots (§10.2, EX-10.2)", function () {
  it("varuint LEB128 : aller-retour, forme non minimale et plus de 9 octets refusées", function () {
    for (const n of [0, 1, 127, 128, 300, 358391, 2 ** 32 - 1]) {
      const b = O.encoderVaruint(n);
      const lu = O.lireOts(Buffer.concat([enTete, Buffer.from([0x00]), O.ETIQUETTE_BITCOIN, O.encoderVaruint(b.length), b]));
      expect(lu.arbre[0].attestation.hauteur).to.equal(n);
    }
    expect(O.encoderVaruint(358391).toString("hex")).to.equal("f7ef15"); // R2-F25
    // f7 ef 95 00 : même valeur, forme non minimale (R2-F07) : refusée ici.
    const nonMinimal = Buffer.concat([enTete, Buffer.from([0x00]), O.ETIQUETTE_BITCOIN, Buffer.from("04f7ef9500", "hex")]);
    expect(() => O.lireOts(nonMinimal)).to.throw(O.ErreurOts, /non minimale/);
    const dix = Buffer.concat([enTete, Buffer.from([0x00]), O.ETIQUETTE_BITCOIN, Buffer.from("0a" + "80".repeat(9) + "01", "hex")]);
    expect(() => O.lireOts(dix)).to.throw(O.ErreurOts, /9 octets/);
    const hauteurTropGrande = O.encoderVaruint(2 ** 32);
    expect(() => O.lireOts(Buffer.concat([enTete, Buffer.from([0x00]), O.ETIQUETTE_BITCOIN, O.encoderVaruint(hauteurTropGrande.length), hauteurTropGrande]))).to.throw(O.ErreurOts, /2\^32/);
  });

  it("en-tête magique, version 01 et opération de fichier 08 exigés ; fin de fichier exacte", function () {
    const ok = preuve("periode-1");
    expect(() => O.lireOts(ok)).not.to.throw();
    const mauvais = (i, v) => {
      const b = Buffer.from(ok);
      b[i] = v;
      return b;
    };
    expect(() => O.lireOts(mauvais(1, 0x50))).to.throw(O.ErreurOts, /magique/);
    expect(() => O.lireOts(mauvais(31, 0x02))).to.throw(O.ErreurOts, /version/);
    expect(() => O.lireOts(mauvais(32, 0x02))).to.throw(O.ErreurOts, /08/);
    expect(() => O.lireOts(Buffer.concat([ok, Buffer.from([0])]))).to.throw(O.ErreurOts, /après l'arbre/);
    expect(() => O.lireOts(ok.subarray(0, ok.length - 1))).to.throw(O.ErreurOts, /tronqué/);
  });

  it("étiquette d'opération inconnue, ff ff, argument vide ou de plus de 4096 octets : fichier illisible", function () {
    expect(() => O.lireOts(Buffer.concat([enTete, Buffer.from([0x09, 0x00]), O.ETIQUETTE_BITCOIN, Buffer.from("0101", "hex")]))).to.throw(O.ErreurOts, /inconnue 0x09/);
    expect(() => O.lireOts(Buffer.concat([enTete, Buffer.from([0xff, 0xff])]))).to.throw(O.ErreurOts, /inconnue 0xff/);
    expect(() => O.lireOts(Buffer.concat([enTete, Buffer.from([0xf0, 0x00])]))).to.throw(O.ErreurOts, /au moins 1/);
    expect(() => O.lireOts(Buffer.concat([enTete, Buffer.from([0xf0]), O.encoderVaruint(4097), Buffer.alloc(4097)]))).to.throw(O.ErreurOts, /au plus 4096/);
  });

  it("chemin de 255 opérations accepté, 256 refusé (R2-F18)", function () {
    const imbrique = (n) => O.encoderOts(E1, O.chemin(Array.from({ length: n }, () => ({ op: O.OP.sha256 })), [bitcoin(1)]));
    expect(() => O.lireOts(imbrique(255))).not.to.throw();
    expect(() => O.lireOts(imbrique(256))).to.throw(O.ErreurOts, /255/);
  });

  it("attestations : charge Bitcoin consommée exactement ; URI en attente aux caractères permis ; attestation inconnue opaque", function () {
    const chargeEnTrop = Buffer.concat([enTete, Buffer.from([0x00]), O.ETIQUETTE_BITCOIN, Buffer.from("03e90700", "hex")]);
    expect(() => O.lireOts(chargeEnTrop)).to.throw(O.ErreurOts, /non consommée/);
    expect(() => O.lireOts(O.encoderOts(E1, [attente("https://a.example/x?y")]))).to.throw(O.ErreurOts, /caractères/);
    const inconnue = { type: "attestation", attestation: { genre: "inconnue", etiquette: Buffer.from("30fe8087b5c7ead7", "hex"), charge: Buffer.from("cafe", "hex") } };
    const lu = O.lireOts(O.encoderOts(E1, [inconnue, bitcoin(5)]));
    expect(lu.arbre.map((b) => b.attestation.genre)).to.deep.equal(["bitcoin", "inconnue"]);
    expect(lu.arbre[1].attestation.charge.toString("hex")).to.equal("cafe");
  });

  it("l'encodeur écrit dans l'ordre de python-opentimestamps : attestations triées par hauteur, puis opérations ; ff devant chaque branche sauf la dernière", function () {
    const b = O.encoderArbre([bitcoin(1002), bitcoin(1001)]);
    expect(b.toString("hex")).to.equal("ff00" + O.ETIQUETTE_BITCOIN.toString("hex") + "02e907" + "00" + O.ETIQUETTE_BITCOIN.toString("hex") + "02ea07");
  });
});

describe("CT-6 contrôle 5 : en-têtes Bitcoin (§10.3, EX-10.9)", function () {
  it("en-tête réel du bloc 358391 (exemple de §10.3, R2-F30) : hachage affiché, preuve de travail sous nBits, racine attestée par hello-world.txt.ots", function () {
    const md = fs.readFileSync(path.join(PROJECT_ROOT, "spec", "CT-6-verificateur.md"), "utf8");
    const exemple = JSON.parse(/<!-- schema: entetes-bitcoin -->\n```json\n([\s\S]*?)\n```/.exec(md)[1]);
    expect(O.controlerEntetes(exemple)).to.deep.equal([]);
    const h = Buffer.from(exemple.headers[0].slice(2), "hex");
    expect(O.hachageAffiche(h)).to.equal("0x000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319");
    const { nBits, racine } = O.champsEntete(h);
    const { cible, negatif, debordement } = O.setCompact(nBits);
    expect([negatif, debordement, cible <= O.POW_LIMIT.mainnet, O.entierLE(O.dSHA(h)) <= cible]).to.deep.equal([false, false, true, true]);
    expect(racine.toString("hex")).to.equal("007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a");
  });

  it("SetCompact et GetCompact (arith_uint256.cpp) : cibles de regtest et de mainnet, signe, débordement, aller-retour", function () {
    expect(O.setCompact(0x207fffff).cible).to.equal(0x7fffffn << 232n);
    expect(O.setCompact(0x1d00ffff).cible).to.equal(0xffffn << 208n);
    expect(O.setCompact(0x1d00ffff).cible <= O.POW_LIMIT.mainnet).to.equal(true);
    expect(O.setCompact(0x01123456).cible).to.equal(0x12n);
    expect(O.setCompact(0x04923456)).to.deep.include({ negatif: true });
    expect(O.setCompact(0xff123456).debordement).to.equal(true);
    expect(O.setCompact(0x00000000).cible).to.equal(0n);
    for (const x of [0x207fffff, 0x1d00ffff, 0x1b0404cb, 0x170331db]) expect(O.getCompact(O.setCompact(x).cible)).to.equal(x);
    expect(O.travail(O.setCompact(0x207fffff).cible)).to.equal(2n);
  });

  it("réajustement de difficulté sur mainnet (règle 5) : Δ = 14 jours conserve nBits ; Δ borné à [¼, 4×] ; cible bornée par powLimit", function () {
    expect(O.nBitsReajuste(0x1b0404cb, 1209600)).to.equal(0x1b0404cb);
    expect(O.nBitsReajuste(0x1b0404cb, 1)).to.equal(O.nBitsReajuste(0x1b0404cb, 302400));
    expect(O.nBitsReajuste(0x1b0404cb, 10 ** 9)).to.equal(O.nBitsReajuste(0x1b0404cb, 4838400));
    expect(O.nBitsReajuste(0x1d00ffff, 4838400)).to.equal(0x1d00ffff);
    expect(O.nBitsReajuste(0x1d00ffff, 302400)).to.equal(0x1c3fffc0);
  });

  it("chaîne de test rattachée au point de contrôle ; chaînage, point de contrôle, réseau, nBits, médiane et travail contrôlés", function () {
    const c = O.preparerEntetes(CHAINE);
    expect(O.rattacherChaine(c, ATTENDU.bitcoin_anchor).status).to.equal("reussi");
    const autre = (modif) => {
      const e = structuredClone(CHAINE);
      modif(e);
      return O.rattacherChaine(O.preparerEntetes(e), ATTENDU.bitcoin_anchor);
    };
    // Un en-tête altéré sous le point de contrôle casse le chaînage.
    expect(autre((e) => (e.headers[3] = e.headers[3].slice(0, 20) + "ff" + e.headers[3].slice(22))).detail.fr).to.match(/prev différent/);
    expect(O.rattacherChaine(c, { ...ATTENDU.bitcoin_anchor, checkpoint: { height: 1000, hash: "0x" + "00".repeat(32) } }).detail.fr).to.match(/différent du point de contrôle/);
    expect(O.rattacherChaine(c, { ...ATTENDU.bitcoin_anchor, checkpoint: { height: 2000, hash: ATTENDU.bitcoin_anchor.checkpoint.hash } }).detail.fr).to.match(/hors des en-têtes/);
    expect(O.rattacherChaine(c, { ...ATTENDU.bitcoin_anchor, network: "mainnet" }).detail.fr).to.match(/réseau regtest/);
    // nBits plus facile que regtest, mais miné : refusé par la règle 5 (ou 4 si au-dessus de powLimit).
    const racines = G.preuvesTest(manifestesCT1()).racines;
    const entetes = G.chaineTest(racines, { fin: 1001 });
    const facile = G.miner({ prev: O.dSHA(entetes[entetes.length - 1]), racine: Buffer.alloc(32, 7), nTime: G.N_TIME_990 + 12 * 600, nBits: 0x2100ffff });
    const avecFacile = { ...CHAINE, headers: [...entetes, facile].map((h) => "0x" + h.toString("hex")) };
    expect(O.rattacherChaine(O.preparerEntetes(avecFacile), ATTENDU.bitcoin_anchor).detail.fr).to.match(/powLimit/);
    // nTime non supérieur à la médiane des onze précédents.
    const vieux = G.miner({ prev: O.dSHA(entetes[entetes.length - 1]), racine: Buffer.alloc(32, 7), nTime: G.N_TIME_990 });
    const avecVieux = { ...CHAINE, headers: [...entetes, vieux].map((h) => "0x" + h.toString("hex")) };
    expect(O.rattacherChaine(O.preparerEntetes(avecVieux), ATTENDU.bitcoin_anchor).detail.fr).to.match(/médiane/);
  });

  it("N-2 : controlerEntetes relève clé inconnue, en-tête mal formé, hauteur finale ≥ 2^32", function () {
    expect(O.controlerEntetes(CHAINE)).to.deep.equal([]);
    expect(O.controlerEntetes({ ...CHAINE, extra: 1 })).to.deep.equal(["clé inconnue extra"]);
    expect(O.controlerEntetes({ ...CHAINE, headers: ["0x00"] })).to.deep.equal(["headers[0] : 80 octets en hexadécimal minuscule 0x attendus"]);
    expect(O.controlerEntetes({ ...CHAINE, start_height: 4294967295 })).to.deep.equal(["start_height + n − 1 ≥ 2^32"]);
    expect(O.controlerEntetes([])).to.deep.equal(["le fichier d'en-têtes n'est pas un objet JSON"]);
  });
});

describe("CT-6 contrôle 5 : vecteurs spec/vecteurs/ct-6/ots (annexe A.4)", function () {
  it("les fichiers ont le SHA-256 de attendu.json ; la chaîne a la forme de EX-A.6", function () {
    for (const p of ATTENDU.proofs) expect("0x" + sha256(fs.readFileSync(path.join(VECTEURS, p.file))).toString("hex"), p.file).to.equal(p.sha256);
    for (const [f, e] of Object.entries(ATTENDU.headers)) expect("0x" + sha256(fs.readFileSync(path.join(VECTEURS, f))).toString("hex"), f).to.equal(e.sha256);
    const c = O.preparerEntetes(CHAINE);
    expect([c.s, c.t, CHAINE.network]).to.deep.equal([990, 1020, "regtest"]);
    expect(O.champsEntete(c.h(990)).prev).to.deep.equal(Buffer.alloc(32));
    for (let i = 990; i <= 1020; i++) {
      const e = O.champsEntete(c.h(i));
      expect([e.version, e.nBits, e.nTime], String(i)).to.deep.equal([0x20000000, 0x207fffff, 1793880000 + 600 * (i - 990)]);
      // nNonce est le plus petit entier qui satisfait la cible.
      const h = Buffer.from(c.h(i));
      for (let n = 0; n < e.nNonce; n++) {
        h.writeUInt32LE(n, 76);
        expect(O.entierLE(O.dSHA(h)) > O.setCompact(0x207fffff).cible, `${i} nNonce ${n}`).to.equal(true);
      }
    }
    expect(ATTENDU.bitcoin_anchor.checkpoint).to.deep.equal({ height: 1000, hash: O.hachageAffiche(c.h(1000)) });
  });

  it("en-têtes, ancre bitcoin et faits du contrôle 5 suivent les schémas entetes-bitcoin-v0, ancres-confiance-v0 et rapport-verification-v0", function () {
    const lire = (n) => JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "spec", "schemas", n), "utf8"));
    const [entetesS, ancresS, rapportS] = ["entetes-bitcoin-v0.schema.json", "ancres-confiance-v0.schema.json", "rapport-verification-v0.schema.json"].map(lire);
    const registre = J.registreSchemas([entetesS, ancresS, rapportS]);
    for (const f of Object.keys(ATTENDU.headers)) expect(J.validerSchema(lireJSON(f), entetesS, { registre }), f).to.deep.equal([]);
    const ancres = { version: 0, label: "test", prepared_by: "test", prepared_at: "2026-11-10T08:00:00.000Z", tsa_authorities: [], revocation: { crls: [], statements: [] }, bitcoin: ATTENDU.bitcoin_anchor, registry: null, recorders: [] };
    expect(J.validerSchema(ancres, ancresS, { registre })).to.deep.equal([]);
    for (const c of ATTENDU.cases.filter((x) => x.facts)) expect(J.validerSchema(c.facts, rapportS, { registre, fragment: "#/$defs/faits/properties/bitcoin" }), c.proof).to.deep.equal([]);
  });

  it("chaque cas de attendu.json est rejoué : statuts O-1 à O-7, contrôle 5, avertissements et faits identiques", function () {
    expect(ATTENDU.cases.length).to.equal(16);
    for (const c of ATTENDU.cases) {
      const r = O.verifierPreuve(fs.readFileSync(path.join(VECTEURS, c.proof)), { periodHash: c.dossier_period_hash, entetes: c.headers ? lireJSON(c.headers) : null, ancres: c.anchors ? ANCRES : null });
      const etiquette = `${c.proof} ${c.headers} ${c.anchors}`;
      expect(r.checks.map((x) => ({ id: x.id, status: x.status, reason: x.reason })), etiquette).to.deep.equal(c.checks);
      expect([r.status, r.reason], etiquette).to.deep.equal([c.control_status, c.control_reason]);
      expect(r.warnings.map((w) => w.id), etiquette).to.deep.equal(c.warnings);
      expect(r.facts, etiquette).to.deep.equal(c.facts);
    }
  });

  it("une variante par vérification visée : la seule vérification en échec est la cible", function () {
    for (const [nom, cible] of [["o1-octet-en-trop", "O-1"], ["o3-resultat-trop-long", "O-3"], ["o4-mauvaise-hauteur", "O-4"]]) expect(echecs(verifier(preuve(nom))), nom).to.deep.equal([cible]);
    expect(echecs(verifier(preuve("periode-2")))).to.deep.equal(["O-2"]);
    expect(echecs(verifier(preuve("periode-1"), { entetes: lireJSON("entetes/chaine-sans-travail.json") }))).to.deep.equal(["O-5"]);
    const courte = verifier(preuve("periode-1"), { entetes: lireJSON("entetes/chaine-courte.json") });
    expect([statuts(courte)["O-6"], courte.status, courte.reason]).to.deep.equal(["non_execute:ancre_absente", "non_execute", "ancre_absente"]);
    const attenteSeule = verifier(preuve("o7-en-attente"));
    expect([statuts(attenteSeule)["O-7"], attenteSeule.status, attenteSeule.reason]).to.deep.equal(["non_execute:partie_absente", "non_execute", "partie_absente"]);
    expect(attenteSeule.warnings.map((w) => w.id)).to.deep.equal(["AV-O-2"]);
  });

  it("preuve valide : faits de EX-10.14, résumé et proposition de EX-10.15 dans les deux langues", function () {
    const r = verifier(preuve("periode-1"));
    const h1001 = O.hachageAffiche(O.preparerEntetes(CHAINE).h(1001));
    expect(r.facts).to.deep.equal({
      file_digest: PH[0],
      network: "regtest",
      checkpoint: ATTENDU.bitcoin_anchor.checkpoint,
      attestations: [{ kind: "bitcoin", height: 1001, uri: null, tag: null, status: "reussi" }],
      retained_height: 1001,
      block_hash: h1001,
      block_time: "2026-11-05T13:50:00Z",
      median_bound: "2026-11-05T14:50:00Z",
      confirmations: 20,
      cumulative_work: "40",
    });
    expect(r.anchors_used).to.deep.equal(["/bitcoin"]);
    expect(r.summary).to.equal("bloc Bitcoin 1001 du réseau regtest, 20 confirmations (réseau d'essai)");
    expect(r.proposition.fr).to.equal(`le manifeste d'empreinte ${PH[0]} existait avant la création du bloc Bitcoin 1001 (${h1001}, réseau regtest), sous 20 blocs dont le travail se rattache au point de contrôle 1000 du réviseur ; heure inscrite par le mineur : 2026-11-05T13:50:00Z UTC, précision non garantie par le protocole ; borne sous hypothèse : 2026-11-05T14:50:00Z UTC (réseau d'essai, sans valeur probante)`);
    expect(r.proposition.en).to.equal(`the manifest with digest ${PH[0]} existed before Bitcoin block 1001 (${h1001}, regtest network) was created, under 20 blocks whose work connects to the reviewer's checkpoint 1000; time written by the miner: 2026-11-05T13:50:00Z UTC, accuracy not guaranteed by the protocol; bound under assumption: 2026-11-05T14:50:00Z UTC (test network, no evidential value)`);
    expect(r.warnings).to.deep.equal([{ id: "AV-O-3", check: "O-5", detail: "réseau regtest : réseau d'essai, sans valeur probante hors des tests" }]);
    expect(verifier(preuve("periode-1"), { langue: "en" }).summary).to.equal("Bitcoin block 1001 on network regtest, 20 confirmations (test network)");
  });

  it("deux attestations : la concordante de plus petite hauteur est retenue, l'autre lève AV-O-1 (EX-10.8)", function () {
    const r = verifier(preuve("deux-attestations"));
    expect(r.status).to.equal("reussi");
    expect(r.facts.retained_height).to.equal(1001);
    expect(r.facts.attestations.map((a) => [a.height, a.status])).to.deep.equal([[1001, "reussi"], [1002, "echoue"]]);
    expect(r.warnings.map((w) => w.id).sort()).to.deep.equal(["AV-O-1", "AV-O-3"]);
  });

  it("sans en-têtes : O-4 à O-6 non exécutées (partie_absente), O-1 à O-3 et O-7 exécutées (EX-4.5) ; sans ancres : ancre_absente, pas d'AV-O-3", function () {
    const sansEntetes = verifier(preuve("periode-1"), { entetes: null });
    expect(statuts(sansEntetes)).to.deep.equal({ "O-1": "reussi", "O-2": "reussi", "O-3": "reussi", "O-4": "non_execute:partie_absente", "O-5": "non_execute:partie_absente", "O-6": "non_execute:partie_absente", "O-7": "reussi" });
    expect([sansEntetes.status, sansEntetes.reason, sansEntetes.facts]).to.deep.equal(["non_execute", "partie_absente", null]);
    const sansAncres = verifier(preuve("periode-1"), { ancres: null });
    expect([sansAncres.status, sansAncres.reason, sansAncres.warnings]).to.deep.equal(["non_execute", "ancre_absente", []]);
    const ancreNulle = verifier(preuve("periode-1"), { ancres: { bitcoin: null } });
    expect([ancreNulle.status, ancreNulle.reason]).to.deep.equal(["non_execute", "ancre_absente"]);
    // Une preuve d'un autre manifeste échoue sans ancre ni en-têtes (EX-5.3).
    expect(verifier(preuve("periode-2"), { entetes: null, ancres: null }).status).to.equal("echoue");
  });

  it("periodHash non calculable : O-2 non exécutée (prerequis_en_echec) ; O-3 à O-7 examinent la preuve pour elle-même (EX-10.6)", function () {
    const r = verifier(preuve("periode-1"), { periodHash: null });
    expect(statuts(r)["O-2"]).to.equal("non_execute:prerequis_en_echec");
    expect(["O-3", "O-4", "O-5", "O-6", "O-7"].map((id) => statuts(r)[id])).to.deep.equal(["reussi", "reussi", "reussi", "reussi", "reussi"]);
    expect([r.status, r.reason]).to.deep.equal(["non_execute", "prerequis_en_echec"]);
  });

  it("opération hors profil (ripemd160, 03) : attestation sous elle non exécutée (hors_perimetre_version), AV-O-2", function () {
    const horsProfil = O.encoderOts(E1, O.chemin([{ op: O.OP.ripemd160 }, ...TOUT1], [bitcoin(1001)]));
    const r = verifier(horsProfil);
    expect(statuts(r)).to.include({ "O-1": "reussi", "O-3": "reussi", "O-4": "non_execute:hors_perimetre_version", "O-6": "non_execute:hors_perimetre_version", "O-7": "reussi" });
    expect([r.status, r.reason]).to.deep.equal(["non_execute", "hors_perimetre_version"]);
    expect(r.warnings.map((w) => w.id)).to.include("AV-O-2");
  });

  it("attestation hors des en-têtes fournis : O-4 non exécutée (ancre_absente)", function () {
    const r = verifier(O.encoderOts(E1, O.chemin(TOUT1, [bitcoin(2000)])));
    expect([statuts(r)["O-4"], r.status, r.reason]).to.deep.equal(["non_execute:ancre_absente", "non_execute", "ancre_absente"]);
  });

  it("profondeur suffisante avec un min_confirmations plus faible : median_bound nul si t < h + 11", function () {
    const ancres = { bitcoin: { ...ATTENDU.bitcoin_anchor, min_confirmations: 3 } };
    const r = verifier(preuve("periode-1"), { entetes: lireJSON("entetes/chaine-courte.json"), ancres });
    expect(r.status).to.equal("reussi");
    expect([r.facts.confirmations, r.facts.median_bound, r.facts.cumulative_work]).to.deep.equal([3, null, "6"]);
    expect(r.proposition.fr).not.to.match(/borne sous hypothèse/);
  });

  it("attestation en attente et attestation inconnue à côté d'une attestation Bitcoin : AV-O-2, contrôle réussi ; ordre de EX-6.15 (O-5 avant O-7)", function () {
    const inconnue = { type: "attestation", attestation: { genre: "inconnue", etiquette: Buffer.from("06869a0d73d71b45", "hex"), charge: Buffer.from("01", "hex") } };
    const r = verifier(O.encoderOts(E1, [...O.chemin(TOUT1, [bitcoin(1001)]), ...O.chemin(OPS1.calendrier, [attente(G.URI_CALENDRIER), inconnue])]));
    expect(r.status).to.equal("reussi");
    expect(r.warnings.map((w) => [w.id, w.check])).to.deep.equal([["AV-O-3", "O-5"], ["AV-O-2", "O-7"], ["AV-O-2", "O-7"]]);
    expect(r.facts.attestations.map((a) => a.kind).sort()).to.deep.equal(["bitcoin", "en_attente", "inconnue"]);
  });
});

describe("CT-6 contrôle 5 : génération déterministe des vecteurs ots", function () {
  this.timeout(60_000);
  it("deux générations dans des répertoires vides donnent les octets du dépôt", function () {
    const lister = (rep) => {
      const out = {};
      const parcourir = (d) => {
        for (const e of fs.readdirSync(d, { withFileTypes: true })) {
          const p = path.join(d, e.name);
          if (e.isDirectory()) parcourir(p);
          else out[path.relative(rep, p)] = sha256(fs.readFileSync(p)).toString("hex");
        }
      };
      parcourir(rep);
      return out;
    };
    const a = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-ct6-ots-"));
    const b = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-ct6-ots-"));
    try {
      G.genererOts({ racine: a });
      G.genererOts({ racine: b });
      const la = lister(path.join(a, "ots"));
      expect(la).to.deep.equal(lister(path.join(b, "ots")));
      expect(la).to.deep.equal(lister(VECTEURS));
      expect(Object.keys(la).length).to.equal(15);
    } finally {
      fs.rmSync(a, { recursive: true, force: true });
      fs.rmSync(b, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// Corrections de la revue de CT-6 : chaque règle corrigée a son test.
describe("CT-6 contrôle 5 : règles précisées par la revue", function () {
  it("URI d'attestation en attente de 0 à 1000 octets, comme la bibliothèque de référence (EX-10.2, R2-F20)", function () {
    const avec = (uri) => O.encoderOts(E1, O.chemin(TOUT1, [attente(uri), bitcoin(1001)]));
    expect(O.lireOts(avec("")).arbre.length).to.equal(1);
    const r = verifier(avec(""));
    expect([r.status, statuts(r)["O-1"]]).to.deep.equal(["reussi", "reussi"]);
    expect(r.facts.attestations.find((a) => a.kind === "en_attente").uri).to.equal("");
    expect(() => O.lireOts(avec("a".repeat(1000)))).not.to.throw();
    expect(() => O.lireOts(avec("a".repeat(1001)))).to.throw(O.ErreurOts, /au plus 1000/);
    expect(() => O.lireOts(avec("a b"))).to.throw(O.ErreurOts, /caractères/);
  });

  it("point de contrôle hors des en-têtes fournis (c < s ou c > t) : O-5 non exécutée (ancre_absente), sans AV-O-3 (EX-10.9, règle 3)", function () {
    const c = O.preparerEntetes(CHAINE);
    const auDessus = O.rattacherChaine(c, { ...ATTENDU.bitcoin_anchor, checkpoint: { height: 2000, hash: ATTENDU.bitcoin_anchor.checkpoint.hash } });
    expect([auDessus.status, auDessus.reason]).to.deep.equal(["non_execute", "ancre_absente"]);
    const depuis1001 = lireJSON("entetes/chaine-depuis-1001.json");
    const r = verifier(preuve("periode-1"), { entetes: depuis1001 });
    expect(statuts(r)).to.include({ "O-4": "non_execute:ancre_absente", "O-5": "non_execute:ancre_absente", "O-6": "non_execute:ancre_absente" });
    expect([r.status, r.reason]).to.deep.equal(["non_execute", "ancre_absente"]);
    expect(r.warnings).to.deep.equal([]);
    // Un hachage différent à la hauteur du point de contrôle reste un échec.
    const faux = O.rattacherChaine(c, { ...ATTENDU.bitcoin_anchor, checkpoint: { height: 1000, hash: "0x" + "00".repeat(32) } });
    expect(faux.status).to.equal("echoue");
  });

  it("point de contrôle à la hauteur du dernier en-tête (t = c) : O-5 réussie sans travail recalculé, et son détail le dit (EX-10.9, 7.2)", function () {
    const entetes = { ...CHAINE, headers: CHAINE.headers.slice(0, 1001 - CHAINE.start_height + 1) };
    const h1001 = Buffer.from(entetes.headers.at(-1).slice(2), "hex");
    const ancres = { bitcoin: { ...ATTENDU.bitcoin_anchor, checkpoint: { height: 1001, hash: O.hachageAffiche(h1001) }, min_confirmations: 1 } };
    const r = verifier(O.encoderOts(E1, O.chemin(TOUT1, [bitcoin(1001)])), { entetes, ancres });
    expect([r.status, statuts(r)["O-5"]]).to.deep.equal(["reussi", "reussi"]);
    expect([r.facts.confirmations, r.facts.cumulative_work]).to.deep.equal([1, "0"]);
    const o5 = r.checks.find((c) => c.id === "O-5").detail;
    expect(o5).to.include("aucun en-tête au-dessus du point de contrôle, aucune preuve de travail recalculée");
    expect(o5).not.to.match(/nBits/);
  });

  it("contrôle 5 : réussi seulement si O-2, O-4, O-6 et O-7 réussissent (EX-10.12)", function () {
    const r = verifier(preuve("periode-1"), { periodHash: null });
    expect(statuts(r)).to.include({ "O-2": "non_execute:prerequis_en_echec", "O-4": "reussi", "O-6": "reussi", "O-7": "reussi" });
    expect([r.status, r.reason, r.facts]).to.deep.equal(["non_execute", "prerequis_en_echec", null]);
  });

  it("opération hors profil à côté d'une branche du profil : O-3 réussie, contrôle 5 réussi, AV-O-2 (EX-10.7)", function () {
    const r = verifier(preuve("branche-hors-profil"));
    expect([statuts(r)["O-3"], r.status]).to.deep.equal(["reussi", "reussi"]);
    expect(r.checks.find((c) => c.id === "O-3").detail).to.match(/hors profil non exécutées : 03/);
    expect(r.warnings.map((w) => [w.id, w.check])).to.deep.equal([["AV-O-2", "O-4"], ["AV-O-3", "O-5"]]);
  });

  it("fuzzing déterministe des preuves : evaluerPreuve ne rend que des statuts, jamais une exception (EX-15.2)", function () {
    this.timeout(120_000);
    let x = 0x2545f491;
    const alea = () => {
      x ^= x << 13;
      x ^= x >>> 17;
      x ^= x << 5;
      return (x >>> 0) / 4294967296;
    };
    for (const nom of ["periode-1", "attente-uri-vide", "branche-hors-profil"]) {
      const base = preuve(nom);
      for (let k = 0; k < 500; k++) {
        const m = Buffer.from(base);
        for (let i = 0; i < 1 + Math.floor(alea() * 3); i++) m[Math.floor(alea() * m.length)] = Math.floor(alea() * 256);
        let r;
        expect(() => (r = O.evaluerPreuve(m, { periodHash: PH[0], entetes: CHAINE, ancres: ANCRES })), `${nom} mutation ${k}`).to.not.throw();
        expect(["reussi", "echoue", "non_execute"]).to.include(r.status);
      }
    }
  });
});
