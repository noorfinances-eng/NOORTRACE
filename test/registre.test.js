import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { encodeRlp, id as idEvenement, keccak256 as keccakEthers } from "ethers";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import { analyserEnveloppe, chargerJeuValidateurs, clePubliqueDe, hachageJeuValidateurs, signerProposition, signerVote, verifierCertificat } from "../scripts/lib/certificat-commit.mjs";
import { hachageManifeste, validerSchema } from "../scripts/lib/journal.mjs";
import * as R from "../scripts/lib/registre.mjs";
import * as G from "../scripts/vecteurs/ct6/registre.mjs";

// CONTRÔLE 8 DU VÉRIFICATEUR (spec/CT-6-verificateur.md, section 11) : hachage
// BFT du bloc, RLP, bloom, encodage des reçus et trie Merkle-Patricia, journaux
// d'événements, lecture des parties, vérifications R-1 à R-10 et N-4 une à une,
// énoncé et faits ; rejeu des vecteurs spec/vecteurs/ct-6/registre (capture
// unique, jeux de parties, variantes, trie synthétique) et déterminisme du
// générateur.

const REP = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-6", "registre");
const lireJSON = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
const copie = (v) => JSON.parse(JSON.stringify(v));
const ATTENDU = lireJSON(path.join(REP, "attendu.json"));
const TRIE = lireJSON(path.join(REP, "trie.json"));
const CAPTURE = G.lireCapture(path.join(REP, "capture"));
const SCHEMAS = G.schemasRegistre();
const MANIFESTES = [1, 2].map((n) => lireJSON(path.join(PROJECT_ROOT, `spec/vecteurs/ct-1/manifestes/periode-${n}.json`)));
const CLES = lireJSON(path.join(PROJECT_ROOT, "spec/vecteurs/ct-1/dossiers/valide-seq-7/cles.json")).keys.map((k) => ({ key_id: k.key_id, public_key: k.public_key }));
const ANCRES_TEST = { registry: ATTENDU.ancres.registry, recorders: ATTENDU.ancres.recorders };
const P1 = G.partiesPeriode(CAPTURE, 1);
const P2 = G.partiesPeriode(CAPTURE, 2);

function texte(v) {
  return JSON.stringify(v, null, 2) + "\n";
}

function parties(p) {
  const o = (v) => (v === null ? { present: false, raison: "absent du test" } : { present: true, octets: Buffer.from(texte(v)) });
  return { registre: o(p.registre), certificat_commit: o(p.certificat_commit), validateurs: o(p.validateurs) };
}

function controle(p, { periode = 1, ancres = ANCRES_TEST, cles = CLES, langue = "fr", periodHash, manifeste } = {}) {
  const m = manifeste === undefined ? MANIFESTES[periode - 1] : manifeste;
  return R.verifierControle8({
    parties: p.registre !== undefined && p.registre?.present === undefined ? parties(p) : p,
    manifeste: m,
    periodHash: periodHash === undefined ? hachageManifeste(MANIFESTES[periode - 1]) : periodHash,
    cles,
    ancres,
    schemas: SCHEMAS,
    langue,
  });
}

function statut(r, id) {
  const v = id === "N-4" ? r.n4 : r.verifications.find((x) => x.id === id);
  if (!v) return undefined;
  return v.status === "non_execute" ? `non_execute:${v.reason}` : v.status;
}

function echecs(r) {
  return [...r.verifications, ...(r.n4 ? [r.n4] : [])].filter((v) => v.status === "echoue").map((v) => v.id);
}

const indice = (p, role) => p.registre.entries.findIndex((e) => e.role === role);

// ---------------------------------------------------------------------------
// Chaîne « forgée » sous le jeu substitué : le réviseur qui déclarerait ce jeu
// dans ses ancres accepterait ses blocs. Sert à atteindre R-9 et R-10 avec des
// journaux altérés dont les racines, hachages et certificats sont cohérents.
// ---------------------------------------------------------------------------

const CLES_SUBSTITUT = new Map([1, 2, 3, 4].map((n) => [`v${n}`, "0x" + createHash("sha256").update(`noortrace/vecteurs/v0/ct-6/validateur-substitue/v${n}`, "utf8").digest("hex")]));
const JEU_SUBSTITUT = G.jeuSubstitue();
const ANCRES_SUBSTITUT = {
  registry: { ...copie(ATTENDU.ancres.registry), validator_sets: [{ from_height: 1, to_height: null, validators: JEU_SUBSTITUT, source: "jeu substitué (test)" }] },
  recorders: copie(ATTENDU.ancres.recorders),
};

/** Applique `muter(entries)`, puis recalcule racines et hachages et re-signe chaque certificat par le jeu substitué. */
function forger(p, muter = () => {}) {
  const q = copie(p);
  muter(q.registre.entries);
  const valsetHash = hachageJeuValidateurs(JEU_SUBSTITUT);
  for (const e of q.registre.entries) {
    e.block.receiptsRoot = R.racineRecus(e.receipts);
    e.block.hash = R.hachageBlocBFT(e.block);
  }
  for (const c of q.certificat_commit.certificates) {
    const e = q.registre.entries.find((x) => x.block.number === c.height);
    const corps = JSON.parse(analyserEnveloppe(c.proposal.line).corpsBrut);
    const h = Number(BigInt(c.height));
    const contexte = (validatorId) => ({ chainId: c.chainId, valsetHash, validatorId });
    c.valsetHash = valsetHash;
    c.blockHash = e.block.hash;
    c.proposal = {
      line: signerProposition(
        {
          height: h,
          round: 0,
          proposer: "v1",
          blockHash: e.block.hash,
          parentHash: e.block.parentHash,
          timestamp: Number(BigInt(e.block.timestamp)),
          stateRoot: e.block.stateRoot,
          receiptsRoot: e.block.receiptsRoot,
          txRoot: e.block.transactionsRoot,
          gasUsed: Number(BigInt(e.block.gasUsed)),
          gasLimit: Number(BigInt(e.block.gasLimit)),
          baseFeeHex: e.block.baseFeePerGas,
          txsRaw: (corps.txsRaw ?? []).map((t) => Buffer.from(t, "base64")),
        },
        contexte("v1"),
        CLES_SUBSTITUT.get("v1"),
      ),
    };
    c.precommits = ["v4", "v1", "v3"].map((v) => ({ line: signerVote({ height: h, round: 0, voter: v, type: 2, blockHash: e.block.hash }, contexte(v), CLES_SUBSTITUT.get(v)) }));
  }
  q.validateurs.sets = [{ from_height: 1, to_height: null, validators: JEU_SUBSTITUT, source: "jeu substitué (test)" }];
  return q;
}

function journal(p, role) {
  const e = p.registre.entries[indice(p, role)];
  return e.receipts[e.transaction_index].logs[e.log_index];
}

function remplacerMot(donnees, i, motHex) {
  const b = Buffer.from(donnees.slice(2), "hex");
  Buffer.from(motHex.slice(2).padStart(64, "0"), "hex").copy(b, 32 * i);
  return "0x" + b.toString("hex");
}

// ---------------------------------------------------------------------------

describe("CT-6 contrôle 8 : constantes, RLP, hachage BFT du bloc", function () {
  it("les sujets des trois événements sont keccak256 de leur signature, et docType celui de « noortrace/periode/v0 »", function () {
    for (const [role, signature] of Object.entries(R.SIGNATURES_EVENEMENTS)) expect(idEvenement(signature)).to.equal(R.SUJETS_EVENEMENTS[role]);
    expect(idEvenement("noortrace/periode/v0")).to.equal(R.DOC_TYPE_PERIODE);
  });

  it("le RLP maison égale encodeRlp d'ethers sur des chaînes et listes de toutes tailles (règle 1)", function () {
    const cas = [
      Buffer.alloc(0),
      Buffer.from([0x00]),
      Buffer.from([0x7f]),
      Buffer.from([0x80]),
      Buffer.alloc(55, 0xaa),
      Buffer.alloc(56, 0xbb),
      Buffer.alloc(1024, 0xcc),
      [],
      [Buffer.from([1]), [Buffer.alloc(30, 2), [Buffer.alloc(0)]]],
      Array.from({ length: 20 }, (_, i) => Buffer.alloc(i, i)),
    ];
    const versEthers = (x) => (Array.isArray(x) ? x.map(versEthers) : "0x" + x.toString("hex"));
    for (const c of cas) expect("0x" + R.rlp(c).toString("hex")).to.equal(encodeRlp(versEthers(c)));
    expect(R.octetsEntier(0n).length).to.equal(0);
    expect(R.octetsEntier(256n).toString("hex")).to.equal("0100");
    expect(R.rlp(R.octetsEntier(0)).toString("hex")).to.equal("80");
  });

  it("BFTBlockHash du bloc 8316 de la fixture publique : préimage de 212 octets et hachage imprimés par la spécification (EX-11.4)", function () {
    const bloc = lireJSON(path.join(PROJECT_ROOT, "test/fixtures/certificat-commit/bloc-8316.json")).result;
    const preimage =
      "6e6f6f722f76312f626674626c6f636b68617368" +
      "293cde1df216315a74cfa45851f246fd1e32f6d92734c26ac567be95968f1bc2" +
      "000000000000207c000000006ad8b09f" +
      "6d3c48fd05042b6c6c65bec56affb2db5d7b1571a4f4df22b81f8410246de64a" +
      "2b733fd11b9a29ec7ee2135b50c9e4b8e878088c95d613fbe287f9a22d91612b" +
      "9a980c5c887bb493cffb54eb12dbbabfcaa6f27bedbbadd166797b91b4c75220" +
      "000000000006a8d20000000001c9c380" +
      "0000000000000000000000000000000000000000000000000000000000000001";
    expect(R.preimageBloc(bloc).toString("hex")).to.equal(preimage);
    expect(R.hachageBlocBFT(bloc)).to.equal("0x8d74ec1247ecaa63a37d374b5757ef22b532577c4bd8145e2cc13f282cf2410c");
    expect(R.hachageBlocBFT(bloc)).to.equal(bloc.hash);
    const certificat = lireJSON(path.join(PROJECT_ROOT, "test/fixtures/certificat-commit/certificat-8316.json")).result;
    expect(R.hachageBlocBFT(bloc)).to.equal(certificat.blockHash);
  });

  it("chaque bloc de la capture : BFTBlockHash = hash servi = blockHash certifié = attendu.json ; un champ engagé modifié change le hachage", function () {
    for (const b of ATTENDU.blocs) {
      const bloc = CAPTURE.blocs.get(b.height);
      expect(R.hachageBlocBFT(bloc)).to.equal(bloc.hash).and.to.equal(b.bft_block_hash).and.to.equal(CAPTURE.certificats.get(b.height).blockHash);
      expect("0x" + R.preimageBloc(bloc).toString("hex")).to.equal(b.bft_preimage);
      for (const champ of ["parentHash", "stateRoot", "transactionsRoot", "receiptsRoot"]) {
        const x = { ...bloc, [champ]: "0x" + "00".repeat(31) + "01" };
        expect(R.hachageBlocBFT(x)).to.not.equal(bloc.hash);
      }
      for (const champ of ["number", "timestamp", "gasUsed", "gasLimit", "baseFeePerGas"]) {
        const x = { ...bloc, [champ]: "0x" + (BigInt(bloc[champ]) + 1n).toString(16) };
        expect(R.hachageBlocBFT(x)).to.not.equal(bloc.hash);
      }
      // Les champs non engagés (logsBloom, miner, extraData…) ne changent rien (R3 F5).
      expect(R.hachageBlocBFT({ ...bloc, logsBloom: "0x" + "ff".repeat(256), miner: "0x" + "11".repeat(20), extraData: "0x1234" })).to.equal(bloc.hash);
    }
  });

  it("instantRFC3339 : secondes UNIX en « AAAA-MM-JJThh:mm:ssZ », sans fraction, pour tout u64", function () {
    for (const s of [0, 951782400, 1792707656, 4102444799, 253402300799]) expect(R.instantRFC3339(BigInt(s))).to.equal(new Date(s * 1000).toISOString().replace(".000Z", "Z"));
    expect(R.instantRFC3339(1n)).to.equal("1970-01-01T00:00:01Z");
    expect(R.instantRFC3339((1n << 64n) - 1n)).to.match(/^\d{12}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  });
});

describe("CT-6 contrôle 8 : reçus, bloom et racine des reçus (EX-11.5)", function () {
  it("bloom recalculé égal au logsBloom servi (un reçu par bloc dans la capture)", function () {
    for (const b of ATTENDU.blocs) {
      const bloc = CAPTURE.blocs.get(b.height);
      const recu = CAPTURE.recus.get(bloc.transactions[0].toLowerCase());
      expect("0x" + R.bloomRecu(recu.logs).toString("hex")).to.equal(bloc.logsBloom.toLowerCase());
    }
    expect(R.bloomRecu([]).equals(Buffer.alloc(256))).to.equal(true);
  });

  it("encodage de consensus : type ‖ RLP([statut, gaz, bloom, journaux]) égal à attendu.json ; un reçu de type 2 encodé comme ancien donne une autre racine", function () {
    for (const b of ATTENDU.blocs) {
      const e = P1.registre.entries.find((x) => BigInt(x.block.number) === BigInt(b.height)) ?? P2.registre.entries.find((x) => BigInt(x.block.number) === BigInt(b.height));
      const recus = e ? e.receipts : null;
      if (!recus) continue;
      expect(recus.map((r) => "0x" + R.encodageRecu(r).toString("hex"))).to.deep.equal(b.receipt_encodings);
      expect(R.racineRecus(recus)).to.equal(b.receipts_root).and.to.equal(b.receipts_root_served);
      expect(R.racineRecus(recus.map((r) => ({ ...r, type: "0x0" })))).to.not.equal(b.receipts_root);
    }
  });

  it("statut : 0x1 encodé par l'octet 01, 0x0 par la chaîne vide ; types hors 0 à 4 et statuts hors {0, 1} refusés", function () {
    const base = { type: "0x0", status: "0x1", cumulativeGasUsed: "0x5208", logs: [] };
    const un = R.encodageRecu(base);
    const zero = R.encodageRecu({ ...base, status: "0x0" });
    // Charge de 264 octets (statut 1, gaz 3, bloom 259, journaux 1) : en-tête f9 0108, puis le statut.
    expect(un.subarray(0, 4).toString("hex")).to.equal("f9010801");
    expect(zero.subarray(0, 4).toString("hex")).to.equal("f9010880");
    expect(R.encodageRecu({ ...base, type: "0x2" })[0]).to.equal(2);
    expect(() => R.encodageRecu({ ...base, type: "0x5" })).to.throw();
    expect(() => R.encodageRecu({ ...base, status: "0x2" })).to.throw();
  });

  it("rejoue trie.json : racines des listes de reçus synthétiques et des couples génériques (confrontées à go-ethereum)", function () {
    for (const x of TRIE.recus) {
      expect(x.receipts).to.have.length(x.n);
      expect(R.racineRecus(x.receipts)).to.equal(x.root);
    }
    for (const g of TRIE.generique) {
      const couples = g.pairs.map((p) => ({ cle: Buffer.from(p.key.slice(2), "hex"), valeur: Buffer.from(p.value.slice(2), "hex") }));
      expect("0x" + R.racineTrie(couples).toString("hex")).to.equal(g.root);
      // L'ordre d'insertion ne compte pas.
      expect("0x" + R.racineTrie([...couples].reverse()).toString("hex")).to.equal(g.root);
    }
    expect(TRIE.vide).to.equal("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");
    expect("0x" + R.racineTrie([]).toString("hex")).to.equal(TRIE.vide);
  });

  it("le trie : une valeur différente, un reçu en moins, deux reçus permutés changent la racine ; clé en double refusée", function () {
    const recus = TRIE.recus.find((x) => x.n === 17).receipts;
    const racine = R.racineRecus(recus);
    expect(R.racineRecus(recus.slice(0, 16))).to.not.equal(racine);
    const permutes = [...recus];
    [permutes[3], permutes[4]] = [permutes[4], permutes[3]];
    expect(R.racineRecus(permutes)).to.not.equal(racine);
    const altere = copie(recus);
    altere[16].cumulativeGasUsed = "0x" + (BigInt(altere[16].cumulativeGasUsed) + 1n).toString(16);
    expect(R.racineRecus(altere)).to.not.equal(racine);
    expect(() => R.racineTrie([{ cle: Buffer.from([1]), valeur: Buffer.from([1]) }, { cle: Buffer.from([1]), valeur: Buffer.from([2]) }])).to.throw(/double/);
  });

  it("codage hex-prefix (feuille et extension, longueur paire et impaire)", function () {
    expect(R.hexPrefix([1, 2, 3, 4, 5], false).toString("hex")).to.equal("112345");
    expect(R.hexPrefix([0, 1, 2, 3, 4, 5], false).toString("hex")).to.equal("00012345");
    expect(R.hexPrefix([0xf, 1, 0xc, 0xb, 8], true).toString("hex")).to.equal("3f1cb8");
    expect(R.hexPrefix([0, 0xf, 1, 0xc, 0xb, 8], true).toString("hex")).to.equal("200f1cb8");
  });
});

describe("CT-6 contrôle 8 : journaux d'événements (EX-11.9)", function () {
  it("décode les sept journaux de la capture comme attendu.json (et comme l'ABI de go-ethereum, confrontation/)", function () {
    for (const b of ATTENDU.blocs) {
      const recu = CAPTURE.recus.get(b.transaction_hash);
      const j = recu.logs[0];
      const { erreurs, valeurs } = R.decoderJournal(b.role, { address: j.address.toLowerCase(), topics: j.topics, data: j.data });
      expect(erreurs).to.deep.equal([]);
      expect(valeurs).to.deep.equal(b.event);
    }
  });

  it("refuse une forme fautive : nombre de sujets, topics[0], adresse aux octets de tête non nuls, longueur de data, position et remplissage de uri", function () {
    const clo = journal(P1, "cloture");
    const anc = journal(P1, "ancre");
    const ins = journal(P1, "inscription");
    const erreur = (role, j) => R.decoderJournal(role, j).erreurs.join(" ; ");
    expect(erreur("cloture", { ...clo, topics: clo.topics.slice(0, 3) })).to.match(/3 sujet\(s\) au lieu de 4/);
    expect(erreur("ancre", { ...anc, topics: [clo.topics[0], ...anc.topics.slice(1)] })).to.match(/n'est pas celui de Anchored/);
    expect(erreur("ancre", { ...anc, topics: [anc.topics[0], anc.topics[1], "0x01" + anc.topics[2].slice(4)] })).to.match(/octets de tête non nuls/);
    expect(erreur("ancre", { ...anc, data: anc.data + "00" })).to.match(/33 octets au lieu de 32/);
    expect(erreur("inscription", { ...ins, data: ins.data.slice(0, 66) })).to.match(/32 octets au lieu de 64/);
    expect(erreur("cloture", { ...clo, data: remplacerMot(clo.data, 8, "0x160") })).to.match(/position de uri/);
    expect(erreur("cloture", { ...clo, data: remplacerMot(clo.data, 3, "0x" + "01".repeat(9)) })).to.match(/uint64 attendu/);
    expect(erreur("cloture", { ...clo, data: remplacerMot(clo.data, 7, "0x" + "01".repeat(5)) })).to.match(/uint32 attendu/);
    // uri vide : 352 octets ; un octet de remplissage non nul après un uri de 1 octet.
    const avecUri = remplacerMot(clo.data, 10, "0x1") + "61" + "00".repeat(30) + "01";
    expect(erreur("cloture", { ...clo, data: avecUri })).to.match(/remplissage de uri non nuls/);
    expect(R.decoderJournal("cloture", { ...clo, data: remplacerMot(clo.data, 10, "0x1") + "61" + "00".repeat(31) }).valeurs.uri).to.equal("a");
    expect(R.decoderJournal("cloture", { ...clo, topics: clo.topics.slice(0, 3) }, "en").erreurs[0]).to.match(/3 topic\(s\) instead of 4/);
  });

  it("empreinte de l'ancre = keccak256(org_id ‖ journal_id ‖ periodHash), égale à celle de CT-1 §10.4", function () {
    const m = MANIFESTES[0];
    const attendu = lireJSON(path.join(PROJECT_ROOT, "spec/vecteurs/ct-1/manifestes/attendu.json")).periodes[0].anchor_fingerprint;
    expect(R.empreinteAncre(m.org_id, m.journal_id, hachageManifeste(m))).to.equal(attendu).and.to.equal(ATTENDU.manifestes["periode-1"].anchor_fingerprint);
  });
});

describe("CT-6 contrôle 8 : lecture des parties et ancre registry", function () {
  it("lirePartie : fichier absent, limite de taille, UTF-8, imbrication de plus de 128 niveaux, clé en double, schéma", function () {
    const opts = { schemas: SCHEMAS, idSchema: R.ID_SCHEMA_REGISTRE, limite: R.LIMITES.registre };
    expect(R.lirePartie({ present: true, octets: null }, "registre", opts).erreur).to.match(/absent du répertoire/);
    expect(R.lirePartie({ present: true, octets: Buffer.from("{}") }, "registre", { ...opts, limite: 1 }).erreur).to.match(/limite/);
    expect(R.lirePartie({ present: true, octets: Buffer.from("{}"), tropGrand: true }, "registre", opts).erreur).to.match(/limite/);
    expect(R.lirePartie({ present: true, octets: Buffer.from([0x7b, 0xff, 0x7d]) }, "registre", opts).erreur).to.match(/UTF-8/);
    expect(R.lirePartie({ present: true, octets: Buffer.from("[".repeat(129) + "]".repeat(129)) }, "registre", opts).erreur).to.match(/128 niveaux/);
    expect(R.profondeurJSON('{"a":"[[[[","b":[[1]]}')).to.equal(3);
    expect(R.lirePartie({ present: true, octets: Buffer.from('{"version":0,"version":0}') }, "registre", opts).erreur).to.match(/double/);
    expect(R.lirePartie({ present: true, octets: Buffer.from('{"version":1}') }, "registre", opts).erreur).to.match(/non conforme au schéma/);
    expect(R.lirePartie({ present: true, octets: Buffer.from(texte(P1.registre)) }, "registre", opts).valeur.entries).to.have.length(4);
  });

  it("les parties de chaque jeu de vecteurs sont conformes aux schémas registre-v0 et validateurs-v0, rôles compris", function () {
    const reps = ["periode-1", "periode-2", ...fs.readdirSync(path.join(REP, "variantes")).map((v) => `variantes/${v}`)];
    for (const r of reps) {
      const reg = lireJSON(path.join(REP, r, "registre.json"));
      const cert = lireJSON(path.join(REP, r, "certificat-commit.json"));
      const val = lireJSON(path.join(REP, r, "validateurs.json"));
      const sansAncre = r.endsWith("invalide-r1-sans-ancre");
      expect(validerSchema(reg, SCHEMAS[R.ID_SCHEMA_REGISTRE], { registre: SCHEMAS }), r).to.deep.equal([]);
      expect(R.ecartsRoles(reg).length > 0, r).to.equal(sansAncre);
      expect(validerSchema(cert, SCHEMAS[R.ID_SCHEMA_REGISTRE], { registre: SCHEMAS, fragment: "#/$defs/certificat_commit" }), r).to.deep.equal([]);
      expect(validerSchema(val, SCHEMAS[R.ID_SCHEMA_VALIDATEURS], { registre: SCHEMAS }), r).to.deep.equal([]);
    }
  });

  it("defautsAncreRegistre (N-1) : jeux qui se recouvrent, from_height > to_height, identifiant ou clé en double ; jeuAncrePourHauteur", function () {
    const reg = copie(ATTENDU.ancres.registry);
    expect(R.defautsAncreRegistre(reg)).to.deep.equal([]);
    expect(R.defautsAncreRegistre(null)).to.deep.equal([]);
    const deux = { ...reg, validator_sets: [{ ...reg.validator_sets[0], to_height: 100 }, { ...reg.validator_sets[0], from_height: 100 }] };
    expect(R.defautsAncreRegistre(deux).join()).to.match(/se recouvrent/);
    const disjoints = { ...reg, validator_sets: [{ ...reg.validator_sets[0], to_height: 99 }, { ...reg.validator_sets[0], validators: JEU_SUBSTITUT, from_height: 100 }] };
    expect(R.defautsAncreRegistre(disjoints)).to.deep.equal([]);
    expect(R.jeuAncrePourHauteur(disjoints, 99n).indice).to.equal(0);
    expect(R.jeuAncrePourHauteur(disjoints, 100n).indice).to.equal(1);
    expect(R.jeuAncrePourHauteur({ ...reg, validator_sets: [{ ...reg.validator_sets[0], from_height: 20000 }] }, 16648n)).to.equal(null);
    expect(R.defautsAncreRegistre({ ...reg, validator_sets: [{ ...reg.validator_sets[0], from_height: 10, to_height: 5 }] }).join()).to.match(/from_height 10 > to_height 5/);
    const double = copie(reg);
    double.validator_sets[0].validators[1].id = "v1";
    expect(R.defautsAncreRegistre(double).join()).to.match(/en double/);
    const memeCle = copie(reg);
    memeCle.validator_sets[0].validators[1].pubKeyHex = memeCle.validator_sets[0].validators[0].pubKeyHex;
    expect(R.defautsAncreRegistre(memeCle).join()).to.match(/même clé publique/);
  });

  it("partiesDuDossier : présentes avec leurs octets, absentes avec la raison de l'index, fichier manquant", function () {
    const index = lireJSON(path.join(PROJECT_ROOT, "spec/vecteurs/ct-1/dossiers/valide-seq-7/dossier.json"));
    expect(R.partiesDuDossier(index, {})).to.deep.equal({
      registre: { present: false, raison: "hors périmètre CT-1" },
      certificat_commit: { present: false, raison: "hors périmètre CT-1" },
      validateurs: { present: false, raison: "hors périmètre CT-1" },
    });
    const complet = copie(index);
    for (const p of complet.parts) if (["registre", "certificat_commit"].includes(p.name)) Object.assign(p, { present: true, sha256: "0x" + "00".repeat(32), reason_if_absent: null });
    const r = R.partiesDuDossier(complet, { "registre.json": Buffer.from("{}") });
    expect(r.registre.octets.toString()).to.equal("{}");
    expect(r.certificat_commit).to.deep.equal({ present: true, octets: null });
    expect(controle(r).verifications.find((v) => v.id === "R-1").detail).to.match(/certificat-commit\.json déclaré présent mais absent/);
  });

  it("entreeRegistre : en-tête réduit aux dix champs engagés, reçus réduits aux quatre champs, minuscules, index du reçu prouvé", function () {
    const t = CAPTURE.description.transactions[0];
    const bloc = CAPTURE.blocs.get(t.bloc);
    const e = R.entreeRegistre({ role: "inscription", bloc, recus: [CAPTURE.recus.get(t.hash)], transactionHash: t.hash.toUpperCase().replace("0X", "0x") });
    expect(Object.keys(e.block)).to.deep.equal(R.CHAMPS_ENTETE);
    expect(Object.keys(e.receipts[0])).to.deep.equal(["type", "status", "cumulativeGasUsed", "logs"]);
    expect(e.receipts[0].logs[0].address).to.equal(e.receipts[0].logs[0].address.toLowerCase());
    expect(e.transaction_index).to.equal(0);
    expect(() => R.entreeRegistre({ role: "x", bloc, recus: [], transactionHash: t.hash })).to.throw(/un reçu par transaction/);
  });
});

describe("CT-6 contrôle 8 : vérifications R-1 à R-10 et N-4", function () {
  it("dossier complet de la période 1 avec les ancres de test : les dix vérifications et N-4 réussissent ; ancres employées ; faits ; énoncé", function () {
    const r = controle(P1);
    expect(r.statut).to.equal("reussi");
    expect(r.raison).to.equal(null);
    expect(r.verifications.map((v) => v.id)).to.deep.equal(["R-1", "R-2", "R-3", "R-4", "R-5", "R-6", "R-7", "R-8", "R-9", "R-10"]);
    for (const v of [...r.verifications, r.n4]) {
      expect(v.status, v.id).to.equal("reussi");
      expect(v.controls).to.deep.equal([8]);
      expect(v.reason).to.equal(null);
      expect(v.admitted).to.equal(null);
      expect(v.detail).to.be.a("string").and.not.equal("");
    }
    expect(r.ancresEmployees).to.deep.equal(["/registry", "/registry/validator_sets/0", "/recorders/1"]);
    expect(r.avertissements).to.deep.equal([]);
    expect(r.faits.chain_id).to.equal("noortrace-2124-dev");
    expect(r.faits.entries.map((e) => e.role)).to.deep.equal(["inscription", "inscription", "ancre", "cloture"]);
    expect(r.faits.certificates.every((c) => c.set_size === 4 && c.quorum === 3 && c.signers.join() === "v1,v3,v4")).to.equal(true);
    expect(r.inscriptionsProuvees.map((x) => x.key_id)).to.deep.equal(["rec-test-01", "rec-test-02"]);
    // Énoncé de EX-11.22, reconstruit ici à partir des faits.
    const f = r.faits;
    const [i1, i2, a, c] = f.entries;
    const m = MANIFESTES[0];
    const attendu =
      `sur le registre noortrace-2124-dev, la clôture de cette période (organisation ${m.org_id}, journal ${m.journal_id}) figure au bloc ${c.block_number} (heure déclarée par le bloc : ${c.block_time} UTC), émise par le contrat PeriodRegistry ${c.emitter}, ` +
      `et son ancre ${a.event.fingerprint} au bloc ${a.block_number} (heure déclarée ${a.block_time} UTC), émise par AttestationRegistry ${a.emitter} pour l'émetteur ${a.event.issuer}, ` +
      `clé de chaîne inscrite au bloc ${i2.block_number} pour la clé d'enregistreur rec-test-02, que le réviseur tient pour la clé de chaîne de rec-test-02 ; ` +
      `chacun de ces blocs est signé par 3 des 4 validateurs du jeu ${f.certificates[0].valset_hash} que le réviseur déclare (${ATTENDU.ancres.registry.validator_sets[0].source})`;
    expect(r.enonce.fr).to.equal(attendu);
    expect(r.enonce.en).to.match(/^on registry noortrace-2124-dev, the closing of this period .* which the reviewer holds as the chain key of rec-test-02; each of these blocks is signed by 3 of the 4 validators of set 0x[0-9a-f]{64} declared by the reviewer \(/);
    expect(i1.event.chainKey).to.equal(ATTENDU.ancres.recorders[0].chain_key);
    expect(a.event.issuer).to.equal(ATTENDU.ancres.recorders[1].chain_key);
    expect(r.resume).to.equal(`noortrace-2124-dev : inscriptions blocs ${i1.block_number} et ${i2.block_number}, ancre bloc ${a.block_number}, clôture bloc ${c.block_number}, 3 validateurs sur 4 à chaque bloc`);
    expect(controle(P1, { langue: "en" }).resume).to.match(/^noortrace-2124-dev: registrations blocks \d+ and \d+, anchor block \d+, closing block \d+, 3 of 4 validators in each block$/);
  });

  it("parties absentes (EX-4.3, EX-5.6) : aucune vérification au rapport ; raison hors_perimetre_version ou partie_absente, dans l'ordre de EX-6.5", function () {
    const absent = (raison) => ({ present: false, raison });
    const ct1 = R.verifierControle8({ parties: { registre: absent("hors périmètre CT-1"), certificat_commit: absent("hors périmètre CT-1"), validateurs: absent("hors périmètre CT-1") }, manifeste: MANIFESTES[0], periodHash: hachageManifeste(MANIFESTES[0]), cles: CLES, ancres: ANCRES_TEST, schemas: SCHEMAS });
    expect([ct1.statut, ct1.raison, ct1.verifications.length, ct1.n4]).to.deep.equal(["non_execute", "hors_perimetre_version", 0, null]);
    expect(ct1.resume).to.equal("registre.json, certificat-commit.json, validateurs.json absents (hors périmètre CT-1)");
    const p = parties(P1);
    const autre = controle({ ...p, certificat_commit: absent("certificat élagué") });
    expect([autre.statut, autre.raison, autre.verifications.length]).to.deep.equal(["non_execute", "partie_absente", 0]);
    const mixte = controle({ ...p, registre: absent("hors périmètre CT-1"), certificat_commit: absent("certificat élagué") });
    expect(mixte.raison).to.equal("hors_perimetre_version");
  });

  it("periodHash non calculable (EX-5.4) : seules R-9 et R-10 non exécutées (prerequis_en_echec), R-1 à R-8 exécutées, N-4 absente", function () {
    const r = controle(P1, { periodHash: null, manifeste: null });
    expect(r.statut).to.equal("non_execute");
    expect(r.raison).to.equal("prerequis_en_echec");
    const statuts = Object.fromEntries(r.verifications.map((v) => [v.id, v.status === "non_execute" ? `${v.status}:${v.reason}` : v.status]));
    expect(statuts).to.deep.equal({ "R-1": "reussi", "R-2": "reussi", "R-3": "reussi", "R-4": "reussi", "R-5": "reussi", "R-6": "reussi", "R-7": "reussi", "R-8": "reussi", "R-9": "non_execute:prerequis_en_echec", "R-10": "non_execute:prerequis_en_echec" });
    expect(r.n4).to.equal(null);
    // Le manifeste fourni sans periodHash n'est pas employé : N-4 ne figure pas non plus.
    expect(controle(P1, { periodHash: null }).n4).to.equal(null);
  });

  it("R-1 : fichier déclaré présent mais absent, taille dépassée, deux clôtures, certificat en double ou orphelin, index hors limites", function () {
    const p = parties(P1);
    const verifierR1 = (pp, motif) => {
      const r = controle(pp);
      expect(statut(r, "R-1")).to.equal("echoue");
      expect(r.verifications.find((v) => v.id === "R-1").detail).to.match(motif);
      expect(r.verifications.slice(1).every((v) => v.reason === "prerequis_en_echec")).to.equal(true);
      expect(statut(r, "N-4")).to.equal("non_execute:prerequis_en_echec");
      expect(r.statut).to.equal("echoue");
    };
    verifierR1({ ...p, registre: { present: true, octets: null } }, /absent du répertoire/);
    verifierR1({ ...p, certificat_commit: { present: true, octets: p.certificat_commit.octets, tropGrand: true } }, /limite/);
    const deuxClotures = copie(P1);
    deuxClotures.registre.entries[0] = copie(deuxClotures.registre.entries[indice(P1, "cloture")]);
    verifierR1(deuxClotures, /2 entrée\(s\) cloture/);
    const doublon = copie(P1);
    doublon.certificat_commit.certificates.push(copie(doublon.certificat_commit.certificates[0]));
    verifierR1(doublon, /deux certificats de hauteur/);
    const orphelin = copie(P1);
    orphelin.certificat_commit.certificates.push(copie(P2.certificat_commit.certificates[2]));
    verifierR1(orphelin, /ne sert aucune entrée/);
    const sansCert = copie(P1);
    sansCert.certificat_commit.certificates.shift();
    verifierR1(sansCert, /aucun certificat de cette hauteur/);
    const horsLimites = copie(P1);
    horsLimites.registre.entries[0].log_index = 5;
    verifierR1(horsLimites, /log_index 5/);
    const tx = copie(P1);
    tx.registre.entries[0].transaction_index = 1;
    verifierR1(tx, /transaction_index 1/);
  });

  it("sans fichier d'ancres : R-2, R-4, R-5, R-8 non exécutées (ancre_absente), N-4 absente, contrôle non exécuté (ancre_absente), aucun fait", function () {
    const r = controle(P1, { ancres: null });
    expect([r.statut, r.raison, r.n4, r.faits, r.enonce]).to.deep.equal(["non_execute", "ancre_absente", null, null, null]);
    expect(["R-2", "R-4", "R-5", "R-8"].map((id) => statut(r, id))).to.deep.equal(Array(4).fill("non_execute:ancre_absente"));
    expect(["R-1", "R-3", "R-6", "R-7", "R-9", "R-10"].map((id) => statut(r, id))).to.deep.equal(Array(6).fill("reussi"));
    expect(r.verifications.find((v) => v.id === "R-2").detail).to.equal("aucun fichier d'ancres");
    expect(r.verifications.find((v) => v.id === "R-5").admitted).to.equal(true);
    const sansRegistre = controle(P1, { ancres: { registry: null, recorders: [] } });
    expect(sansRegistre.verifications.find((v) => v.id === "R-2").detail).to.equal("le fichier d'ancres ne donne pas d'ancre registry");
    expect(sansRegistre.ancresEmployees).to.deep.equal([]);
  });

  it("R-2 : jeu de l'ancre qui ne couvre pas la hauteur (ancre_absente, R-5 suit) ; jeu substitué (échec, R-5 prerequis_en_echec) ; le certificat forgé est pourtant valide pour son propre jeu", function () {
    const ancres = copie(ANCRES_TEST);
    ancres.registry.validator_sets[0].from_height = 16650;
    const r = controle(P1, { ancres });
    expect(statut(r, "R-2")).to.equal("non_execute:ancre_absente");
    expect(statut(r, "R-5")).to.equal("non_execute:ancre_absente");
    expect(r.statut).to.equal("non_execute");
    const v = G.variantes(CAPTURE).find((x) => x.nom === "invalide-r2-jeu-substitue");
    const r2 = controle(v.parties);
    expect(echecs(r2)).to.deep.equal(["R-2"]);
    expect(statut(r2, "R-3")).to.equal("reussi");
    expect(statut(r2, "R-5")).to.equal("non_execute:prerequis_en_echec");
    for (const c of v.parties.certificat_commit.certificates) {
      const propre = { chainId: c.chainId, valsetHash: c.valsetHash, h: c.height, r: c.round, hash: c.blockHash, prop: c.proposal.line, cmts: c.precommits.map((x) => x.line) };
      expect(verifierCertificat(propre, chargerJeuValidateurs({ validators: JEU_SUBSTITUT })).valide).to.equal(true);
    }
    // Le même faux passe le contrôle 8 si le réviseur déclare le jeu substitué : l'ancre est la seule source de confiance.
    expect(controle(v.parties, { ancres: ANCRES_SUBSTITUT }).statut).to.equal("reussi");
  });

  it("R-3 : validateurs.json absent (partie_absente, sans effet) ; mal formé ou d'un autre jeu (échec)", function () {
    const sans = controle({ ...P1, validateurs: null });
    expect([statut(sans, "R-3"), sans.statut]).to.deep.equal(["non_execute:partie_absente", "reussi"]);
    const malForme = parties(P1);
    malForme.validateurs = { present: true, octets: Buffer.from('{"version":0,"sets":[]}') };
    expect(statut(controle(malForme), "R-3")).to.equal("echoue");
    const horsHauteur = copie(P1);
    horsHauteur.validateurs.sets[0].to_height = 100;
    expect(controle(horsHauteur).verifications.find((v) => v.id === "R-3").detail).to.match(/aucun jeu pour cette hauteur/);
  });

  it("R-4 : identifiant de chaîne de l'ancre différent (échec) ; R-5 reste réussie (le chainId des lignes est celui du certificat)", function () {
    const ancres = G.appliquerModifications(ANCRES_TEST, [{ pointer: "/registry/chain_id", value: "noortrace-9999-test" }]);
    const r = controle(P1, { ancres });
    expect(echecs(r)).to.deep.equal(["R-4"]);
    expect(r.verifications.find((v) => v.id === "R-4").detail).to.match(/noortrace-9999-test/);
  });

  it("R-5 : une ligne invalide suffit à l'échec ; quorum non atteint ; signataire en double ; AV-R-2 pour une ligne non canonique acceptée", function () {
    const h = P1.registre.entries[indice(P1, "cloture")].block.number;
    const avec = (f) => {
      const p = copie(P1);
      f(p.certificat_commit.certificates.find((c) => c.height === h));
      return controle(p);
    };
    const quorum = avec((c) => c.precommits.pop());
    expect(echecs(quorum)).to.deep.equal(["R-5"]);
    expect(quorum.verifications.find((v) => v.id === "R-5").detail).to.match(/quorum de 3 sur 4 : insuffisant/);
    const double = avec((c) => (c.precommits[2] = copie(c.precommits[0])));
    expect(echecs(double)).to.deep.equal(["R-5"]);
    const signature = avec((c) => {
      const env = analyserEnveloppe(c.precommits[1].line);
      const sig = Buffer.from(env.sig);
      sig[10] ^= 1;
      c.precommits[1].line = c.precommits[1].line.replace(env.sig.toString("base64"), sig.toString("base64"));
    });
    expect(echecs(signature)).to.deep.equal(["R-5"]);
    const autreBloc = avec((c) => (c.proposal.line = copie(P1.certificat_commit.certificates[0].proposal.line)));
    expect(echecs(autreBloc)).to.deep.equal(["R-5"]);
    const nonCanonique = avec((c) => (c.precommits[0].line = '{"Domain":' + c.precommits[0].line.slice('{"domain":'.length)));
    expect([nonCanonique.statut, nonCanonique.avertissements.map((a) => a.id)]).to.deep.equal(["reussi", ["AV-R-2"]]);
    expect(nonCanonique.avertissements[0]).to.include({ check: "R-5" });
    // Les champs décodés et les affirmations du nœud ne sont pas lus (EX-11.3, EX-3.5).
    const affirmations = avec((c) => {
      c.canonical = { blockHash: "0x" + "00".repeat(32), matchesCertificate: false };
      c.validatorSet = [];
      c.validatorSetHash = "0x" + "00".repeat(32);
      c.validatorSetMatchesCertificate = false;
      c.quorum = { validators: 99, required: 99, precommits: 0 };
      c.precommits[0].sig = "0x00";
      c.precommits[0].validatorId = "v2";
      c.h = "0x1";
    });
    expect(affirmations.statut).to.equal("reussi");
  });

  it("R-6 : un champ engagé modifié (échec ; R-8 et R-9 de l'entrée prerequis_en_echec) ; block.hash différent du hachage recalculé (échec)", function () {
    const v = G.variantes(CAPTURE).find((x) => x.nom === "invalide-r6-entete-modifie");
    const r = controle(v.parties);
    expect(echecs(r)).to.deep.equal(["R-6"]);
    expect([statut(r, "R-8"), statut(r, "R-9")]).to.deep.equal(["non_execute:prerequis_en_echec", "non_execute:prerequis_en_echec"]);
    const p = copie(P1);
    p.registre.entries[0].block.hash = "0x" + "22".repeat(32);
    const r2 = controle(p);
    expect(echecs(r2)).to.deep.equal(["R-6"]);
    expect(r2.verifications.find((x) => x.id === "R-6").detail).to.match(/différent de block\.hash/);
    expect(statut(r2, "R-10")).to.equal("non_execute:prerequis_en_echec");
  });

  it("R-7 : reçu falsifié qui garde le blockHash certifié ; reçu ajouté ; type de reçu changé", function () {
    const e = indice(P1, "cloture");
    const avec = (f) => {
      const p = copie(P1);
      f(p.registre.entries[e]);
      return controle(p);
    };
    expect(echecs(avec((x) => (x.receipts[0].logs[0].topics[2] = "0x" + "11".repeat(32))))).to.deep.equal(["R-7"]);
    expect(echecs(avec((x) => x.receipts.push(copie(x.receipts[0]))))).to.deep.equal(["R-7"]);
    expect(echecs(avec((x) => (x.receipts[0].type = "0x0"))).filter((id) => id !== "R-9")).to.deep.equal(["R-7"]);
    expect(echecs(avec((x) => (x.receipts[0].status = "0x0")))).to.deep.equal(["R-7"]);
  });

  it("R-8 : journal émis par un autre contrat que celui de l'ancre pour le rôle", function () {
    for (const [role, cle] of [["cloture", "period_registry"], ["ancre", "attestation_registry"], ["inscription", "recorder_registry"]]) {
      const ancres = G.appliquerModifications(ANCRES_TEST, [{ pointer: `/registry/contracts/${cle}`, value: "0x" + "33".repeat(20) }]);
      const r = controle(P1, { ancres });
      expect(echecs(r), role).to.deep.equal(["R-8"]);
    }
  });

  it("R-9 : sur une chaîne forgée cohérente, chaque valeur de PeriodSubmitted et d'Anchored est comparée au manifeste", function () {
    const sain = controle(forger(P1), { ancres: ANCRES_SUBSTITUT });
    expect(sain.statut).to.equal("reussi");
    const cas = [
      ["cloture", (j) => (j.data = remplacerMot(j.data, 3, "0x" + (MANIFESTES[0].period_start + 1).toString(16))), /periodStart/],
      ["cloture", (j) => (j.data = remplacerMot(j.data, 4, "0x" + (MANIFESTES[0].period_end + 1).toString(16))), /periodEnd/],
      ["cloture", (j) => (j.data = remplacerMot(j.data, 5, "0x2")), /firstSeq/],
      ["cloture", (j) => (j.data = remplacerMot(j.data, 6, "0x8")), /lastSeq/],
      ["cloture", (j) => (j.data = remplacerMot(j.data, 7, "0x1")), /version/],
      ["cloture", (j) => (j.data = remplacerMot(j.data, 2, "0x" + "44".repeat(32))), /root/],
      ["cloture", (j) => (j.data = remplacerMot(j.data, 0, "0x" + "44".repeat(32))), /orgId/],
      ["cloture", (j) => (j.data = remplacerMot(j.data, 1, "0x" + "44".repeat(32))), /journalId/],
      ["cloture", (j) => (j.data = remplacerMot(j.data, 9, "0x1")), /publishedAt/],
      ["cloture", (j) => (j.topics[2] = "0x" + "11".repeat(32)), /periodHash/],
      ["cloture", (j) => (j.topics = j.topics.slice(0, 3)), /3 sujet/],
      ["ancre", (j) => (j.topics[1] = "0x" + "11".repeat(32)), /empreinte/],
      ["ancre", (j) => (j.data = "0x" + "55".repeat(32)), /docType/],
    ];
    for (const [role, muter, motif] of cas) {
      const p = forger(P1, (entrees) => {
        const e = entrees.find((x) => x.role === role);
        muter(e.receipts[e.transaction_index].logs[e.log_index]);
      });
      const r = controle(p, { ancres: ANCRES_SUBSTITUT });
      expect(echecs(r), String(motif)).to.include("R-9");
      expect(r.verifications.find((v) => v.id === "R-9").detail).to.match(motif);
    }
    // Manifeste d'une autre période : la clôture et l'ancre ne correspondent plus.
    const autre = controle(P1, { periode: 2 });
    expect(echecs(autre)).to.include("R-9");
  });

  it("R-10 : clé inconnue de cles.json ; clé du manifeste inscrite sous une autre clé de chaîne que l'émetteur de l'ancre ; org_id différent ; cles.json inexploitable ; AV-R-1", function () {
    const v = G.variantes(CAPTURE).find((x) => x.nom === "invalide-r10-inscription-cle-inconnue");
    const inconnue = controle(v.parties);
    expect(echecs(inconnue)).to.deep.equal(["R-10"]);
    expect(inconnue.verifications.find((x) => x.id === "R-10").detail).to.match(/absente de cles\.json/);
    const cleChaine01 = "0x" + "00".repeat(12) + ATTENDU.ancres.recorders[0].chain_key.slice(2);
    const autreCle = forger(P1, (entrees) => {
      const e = entrees.filter((x) => x.role === "inscription")[1];
      e.receipts[0].logs[0].topics[2] = cleChaine01;
    });
    const r = controle(autreCle, { ancres: ANCRES_SUBSTITUT });
    expect(echecs(r)).to.deep.equal(["R-10"]);
    expect(r.verifications.find((x) => x.id === "R-10").detail).to.match(/rec-test-02, clé du manifeste, inscrite sous 0xaa2a/);
    const autreOrg = forger(P1, (entrees) => (entrees[0].receipts[0].logs[0].topics[1] = "0x" + "66".repeat(32)));
    expect(echecs(controle(autreOrg, { ancres: ANCRES_SUBSTITUT }))).to.deep.equal(["R-10"]);
    const sansCles = controle(P1, { cles: null });
    expect([statut(sansCles, "R-10"), sansCles.statut]).to.deep.equal(["non_execute:prerequis_en_echec", "reussi"]);
    expect(sansCles.inscriptionsProuvees).to.deep.equal([]);
    // Sans l'inscription de rec-test-02 (clé du manifeste) : R-10 réussit sur rec-test-01, AV-R-1, et l'énoncé ne dit plus « clé de chaîne inscrite ».
    const p = copie(P1);
    const h = p.registre.entries[1].block.number;
    p.registre.entries.splice(1, 1);
    p.certificat_commit.certificates = p.certificat_commit.certificates.filter((c) => c.height !== h);
    const sansCleManifeste = controle(p);
    expect([sansCleManifeste.statut, statut(sansCleManifeste, "R-10"), sansCleManifeste.avertissements.map((a) => a.id)]).to.deep.equal(["reussi", "reussi", ["AV-R-1"]]);
    expect(sansCleManifeste.enonce.fr).to.not.include("clé de chaîne inscrite");
    expect(sansCleManifeste.enonce.fr).to.include("que le réviseur tient pour la clé de chaîne de rec-test-02");
  });

  it("N-4 : absente si l'ancre ne donne pas de chain_key pour la clé du manifeste ; échec si elle diffère ; prerequis_en_echec si l'ancre n'a pas passé R-6 et R-7", function () {
    const sans = copie(ANCRES_TEST);
    sans.recorders[1].chain_key = null;
    const r = controle(P1, { ancres: sans });
    expect(r.n4).to.equal(null);
    expect(r.ancresEmployees).to.not.include("/recorders/1");
    expect(r.enonce.fr).to.not.include("que le réviseur tient pour");
    const autre = G.appliquerModifications(ANCRES_TEST, [{ pointer: "/recorders/1/chain_key", value: ATTENDU.ancres.recorders[0].chain_key }]);
    const r2 = controle(P1, { ancres: autre });
    expect([echecs(r2), r2.statut]).to.deep.equal([["N-4"], "echoue"]);
    const p = copie(P1);
    p.registre.entries[indice(p, "ancre")].receipts[0].logs[0].data = "0x" + "77".repeat(32);
    const r3 = controle(p);
    expect(statut(r3, "N-4")).to.equal("non_execute:prerequis_en_echec");
  });

  it("les détails suivent la langue choisie (EX-8.3) ; les statuts et identifiants n'en dépendent pas", function () {
    const fr = controle(P1, { ancres: null });
    const en = controle(P1, { ancres: null, langue: "en" });
    expect(en.verifications.map((v) => [v.id, v.status, v.reason])).to.deep.equal(fr.verifications.map((v) => [v.id, v.status, v.reason]));
    expect(en.verifications.find((v) => v.id === "R-2").detail).to.equal("no anchors file");
    expect(en.verifications.find((v) => v.id === "R-6").detail).to.match(/^recomputed BFTBlockHash equal/);
  });
});

describe("CT-6 contrôle 8 : règles précisées par la revue", function () {
  it("R-10 : la clé du manifeste réinscrite sous une autre clé de chaîne, à côté de son inscription sous l'émetteur de l'ancre : R-10 réussit, AV-R-3 (EX-11.19)", function () {
    const cleChaine01 = "0x" + "00".repeat(12) + ATTENDU.ancres.recorders[0].chain_key.slice(2);
    const reinscrite = forger(P1, (entrees) => {
      const i = entrees.findIndex((x) => x.role === "inscription" && x.receipts[0].logs[0].topics[2].endsWith(ATTENDU.ancres.recorders[1].chain_key.slice(2)));
      const autre = copie(entrees[i]);
      autre.block.number = "0x" + (BigInt(autre.block.number) + 1n).toString(16);
      autre.receipts[0].logs[0].topics[2] = cleChaine01;
      entrees.splice(i + 1, 0, autre);
    });
    const hauteurs = reinscrite.registre.entries.map((e) => e.block.number);
    const nouvelle = hauteurs.find((h) => !reinscrite.certificat_commit.certificates.some((c) => c.height === h));
    // Le certificat du bloc ajouté : celui du bloc voisin, re-signé par forger.
    const p = copie(P1);
    const modele = copie(p.certificat_commit.certificates[1]);
    modele.height = nouvelle;
    const avecCertificat = forger({ ...p, registre: reinscrite.registre, certificat_commit: { ...p.certificat_commit, certificates: [...p.certificat_commit.certificates.slice(0, 2), modele, ...p.certificat_commit.certificates.slice(2)] } });
    const r = controle(avecCertificat, { ancres: ANCRES_SUBSTITUT });
    expect([statut(r, "R-10"), r.statut]).to.deep.equal(["reussi", "reussi"]);
    expect(r.avertissements.map((a) => [a.id, a.check])).to.deep.equal([["AV-R-3", "R-10"]]);
    expect(r.avertissements[0].detail).to.match(/sous la clé de chaîne 0xaa2a.*autre que l'émetteur de l'ancre/);
    // Seule l'ancienne inscription jointe (sous une autre clé de chaîne que l'émetteur) : R-10 échoue.
    const seule = forger(P1, (entrees) => {
      const e = entrees.find((x) => x.role === "inscription" && x.receipts[0].logs[0].topics[2].endsWith(ATTENDU.ancres.recorders[1].chain_key.slice(2)));
      e.receipts[0].logs[0].topics[2] = cleChaine01;
    });
    expect(echecs(controle(seule, { ancres: ANCRES_SUBSTITUT }))).to.deep.equal(["R-10"]);
  });

  it("N-4 exige R-5 réussie pour le certificat du bloc de l'ancre : sinon non exécutée, avec la raison de R-5 (EX-12.5)", function () {
    const hAncre = BigInt(P1.registre.entries[indice(P1, "ancre")].block.number);
    const trou = G.appliquerModifications(ANCRES_TEST, [{ pointer: "/registry/validator_sets", value: [{ ...ATTENDU.ancres.registry.validator_sets[0], from_height: 1, to_height: Number(hAncre - 1n) }, { ...ATTENDU.ancres.registry.validator_sets[0], from_height: Number(hAncre + 1n), to_height: null }] }]);
    const r = controle(P1, { ancres: trou });
    expect([statut(r, "R-2"), statut(r, "R-5"), statut(r, "N-4"), r.statut, r.raison]).to.deep.equal(["non_execute:ancre_absente", "non_execute:ancre_absente", "non_execute:ancre_absente", "non_execute", "ancre_absente"]);
    expect(r.n4.detail).to.match(/R-5 n'a pas réussi pour le certificat du bloc de l'ancre/);
    const substitue = G.variantes(CAPTURE).find((x) => x.nom === "invalide-r2-jeu-substitue");
    expect(statut(controle(substitue.parties), "N-4")).to.equal("non_execute:prerequis_en_echec");
  });

  it("deux jeux de l'ancre : la proposition de l'énoncé nomme chaque groupe de blocs avec son jeu (EX-11.22)", function () {
    const v = ATTENDU.variantes.find((x) => x.nom === "valide-deux-jeux");
    const r = controle(P1, { ancres: G.appliquerModifications(ANCRES_TEST, v.modifications_ancres) });
    expect(r.statut).to.equal("reussi");
    expect(r.enonce.fr).to.match(/ ; les blocs \d+, \d+ et \d+ sont signés par 3 des 4 validateurs du jeu 0x[0-9a-f]{64} que le réviseur déclare \([^)]*\(premier jeu déclaré : hauteurs 1 à \d+\)\) et le bloc \d+ par 3 des 4 validateurs du jeu 0x[0-9a-f]{64} que le réviseur déclare \([^)]*\(second jeu déclaré : hauteurs \d+ et suivantes\)\)$/);
    expect(r.enonce.en).to.match(/; blocks \d+, \d+ and \d+ are signed by 3 of the 4 validators of set 0x[0-9a-f]{64} declared by the reviewer \(.*\) and block \d+ by 3 of the 4 validators of set /);
    expect(r.ancresEmployees).to.include.members(["/registry/validator_sets/0", "/registry/validator_sets/1"]);
  });
});

describe("CT-6 contrôle 8 : rejeu des vecteurs spec/vecteurs/ct-6/registre", function () {
  const lireParties = (j) => {
    const rep = path.join(REP, j.parties);
    const o = (f) => ({ present: true, octets: fs.readFileSync(path.join(rep, f)) });
    return {
      registre: o("registre.json"),
      certificat_commit: o("certificat-commit.json"),
      validateurs: j.validateurs_present ? o("validateurs.json") : { present: false, raison: "absent de ce jeu" },
    };
  };
  const rejouer = (j) => {
    const periode = Number(/periode-(\d)/.exec(j.manifeste)[1]);
    const ancres = j.ancres ? G.appliquerModifications(ANCRES_TEST, j.modifications_ancres) : null;
    return controle(lireParties(j), { periode, ancres });
  };

  it("chaque jeu de parties valide : statuts, avertissements, faits et énoncé de attendu.json", function () {
    expect(ATTENDU.jeux_de_parties).to.have.length(5);
    for (const j of ATTENDU.jeux_de_parties) {
      const r = rejouer(j);
      expect(G.resumer(r), j.nom).to.deep.equal({ control_status: j.control_status, control_reason: j.control_reason, failed_checks: j.failed_checks, not_executed: j.not_executed, warnings: j.warnings, n4_present: j.n4_present });
      expect(r.enonce, j.nom).to.deep.equal(j.statement);
      expect(r.faits, j.nom).to.deep.equal(j.facts);
    }
  });

  it("chaque variante : une seule vérification visée en échec (ou un avertissement), et les non-exécutions qui en dépendent", function () {
    const cibles = ATTENDU.variantes.map((v) => v.cible).filter(Boolean);
    expect(cibles).to.deep.equal(["R-1", "R-2", "R-3", "R-4", "R-5", "R-6", "R-7", "R-8", "R-9", "R-10", "N-4"]);
    for (const v of ATTENDU.variantes) {
      const r = rejouer(v);
      const resume = G.resumer(r);
      expect(resume, v.nom).to.deep.equal({ control_status: v.control_status, control_reason: v.control_reason, failed_checks: v.failed_checks, not_executed: v.not_executed, warnings: v.warnings, n4_present: v.n4_present });
      if (v.cible) expect(resume.failed_checks, v.nom).to.deep.equal([v.cible]);
      expect(Object.fromEntries([...r.verifications, ...(r.n4 ? [r.n4] : [])].map((x) => [x.id, x.status === "non_execute" ? `non_execute:${x.reason}` : x.status])), v.nom).to.deep.equal(v.statuses);
    }
  });

  it("la capture : sept transactions, un fichier par réponse JSON-RPC, validators.json sans clé privée, rien d'autre", function () {
    const d = CAPTURE.description;
    expect(d.transactions.map((t) => t.role)).to.deep.equal(["inscription", "inscription", "inscription", "ancre", "ancre", "cloture", "cloture"]);
    const attendus = new Set(["capture.json", "validators.json", "CAPTURE.md"]);
    for (const t of d.transactions) {
      attendus.add(t.fichiers.bloc).add(t.fichiers.certificat);
      for (const f of t.fichiers.recus) attendus.add(f);
    }
    expect(new Set(fs.readdirSync(path.join(REP, "capture")))).to.deep.equal(attendus);
    const v = lireJSON(path.join(REP, "capture", "validators.json"));
    expect(Object.keys(v)).to.deep.equal(["validators"]);
    for (const x of v.validators) {
      expect(Object.keys(x).sort()).to.deep.equal(["id", "pubKeyHex"]);
      expect(x.pubKeyHex).to.match(/^0x04[0-9a-f]{128}$/);
    }
    expect(hachageJeuValidateurs(v)).to.equal(ATTENDU.capture.valset_hash);
    // Les clés de chaîne des enregistreurs viennent des graines publiées (annexe A.5).
    for (const t of d.transactions.filter((x) => x.role === "inscription")) {
      const graine = createHash("sha256").update(`noortrace/vecteurs/v0/cle-chaine/${t.key_id}`).digest("hex");
      expect(t.chain_key).to.equal(adresseDe(graine));
    }
  });

  it("le générateur reproduit octet pour octet chaque fichier de registre/ (hors capture/), et rien d'autre", function () {
    const { fichiers } = G.construireRegistre(CAPTURE);
    for (const [relatif, contenu] of fichiers) expect(fs.readFileSync(path.join(REP, relatif), "utf8"), relatif).to.equal(contenu);
    const surDisque = [];
    const parcourir = (rel) => {
      for (const e of fs.readdirSync(path.join(REP, rel), { withFileTypes: true })) {
        const r = rel ? `${rel}/${e.name}` : e.name;
        if (e.isDirectory()) parcourir(r);
        else surDisque.push(r);
      }
    };
    for (const e of G.ENTREES_GENEREES) {
      if (fs.statSync(path.join(REP, e)).isDirectory()) parcourir(e);
      else surDisque.push(e);
    }
    expect(surDisque.sort()).to.deep.equal([...fichiers.keys()].sort());
    expect(G.ENTREES_GENEREES).to.not.include("capture");
  });
});

function adresseDe(clePriveeHex) {
  const pub = clePubliqueDe("0x" + clePriveeHex);
  return "0x" + keccakEthers("0x" + pub.slice(4)).slice(-40);
}
