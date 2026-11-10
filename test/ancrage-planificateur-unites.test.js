// Planificateur d'ancrage (lot C) : unités hors traces. Requête TimeStampReq
// d'EX-5.1 (famille requetes/, refusées, octets des .tsq), échéances et
// cadence (EX-4.1 à EX-4.4, AN-2), admission par le noyau sur les séries de
// spec/vecteurs/ct-1/points-de-controle (AN-3), sélection et comptages
// (EX-4.6, EX-4.11, AN-4), coût (famille cout/, EX-12.1, EX-12.2, AN-59,
// AN-60), complétude au registre (famille completude/, EX-10.7, AN-61),
// supervision (EX-8.15, AN-43), et les conduites du planificateur que les
// traces n'exercent pas (relève d'un point par le secours, statuts PKI,
// codes HTTP, calendriers insuffisants, give_up, échecs du registre, rôle
// aucun, registre absent, entrées hostiles). Aucun essai n'exige le réseau.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as N from "@noortrace/noyau";
import {
  requeteTimeStampReq, relireTimeStampReq, encoderOidDer, ErreurRequeteDer, nonceEntier, nonceHex,
  echeances, tableEcheances, constaterCadence,
  admettrePoint, admettreManifeste, verifierSerie, REGLES_ADMISSION,
  pointsAAncrer, compterJetons, tableComptages,
  cout, GAZ_ANCRE_MAX, GAZ_CLOTURE_MAX,
  verifierCompletudeRegistre,
  Supervision, METRIQUES_ANCRAGE, EVENEMENTS_JOURNAL,
  creerPlanificateur, ErreurPlanificateur, noncesVecteurs, noncesAleatoires, nonceVecteur, DOC_TYPE_PERIODE_PLANIFICATEUR, TAILLE_CAPTURE_REPRESENTEE,
} from "@noortrace/ancrage/planificateur";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SPEC = path.join(RACINE, "spec");
const CT5 = path.join(SPEC, "vecteurs", "ct-5");
const CT1 = path.join(SPEC, "vecteurs", "ct-1");
const lire = (...p) => JSON.parse(fs.readFileSync(path.join(SPEC, "vecteurs", ...p), "utf8"));
const trace = (nom) => lire("ct-5", "planification", `${nom}.json`);
const nonceEtiquette = (label) => "0x" + Buffer.from(N.sha256(N.utf8(label))).subarray(0, 8).toString("hex");

const ORG = "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab";
const JOURNAL = "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b";
const PERIODE = 1793710800;
const K1 = { org_id: ORG, journal_id: JOURNAL, period_start: PERIODE, tree_size: 2, checkpoint_hash: "0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4", checkpoint_ts: "2026-11-03T13:42:00.000Z" };
const K2 = { org_id: ORG, journal_id: JOURNAL, period_start: PERIODE, tree_size: 4, checkpoint_hash: "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff", checkpoint_ts: "2026-11-03T13:53:00.000Z" };
const CLOTURE = { org_id: ORG, journal_id: JOURNAL, period_start: PERIODE, period_hash: "0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1", generated_at: "2026-11-03T14:00:00.250Z" };
const SHA = (texte) => "0x" + Buffer.from(N.sha256(N.utf8(texte))).toString("hex");
const GRANTED = (request_id, attempt, nonce, gen_time, nom) => ({
  request_id, attempt, transport: "reponse", http_status: 200, pki_status: 0, failure_info: null, retry_after_s: null, nonce_in_response: nonce, imprint_matches: true,
  checks_passed: ["T-1", "T-2", "T-3", "T-4", "T-5", "T-6", "T-7", "T-8", "T-9"], gen_time, accuracy_s: 1, token_sha256: SHA(`jeton ${nom}`), token_size: 2104,
});
const ERREUR = (request_id, attempt, champs) => ({
  request_id, attempt, transport: "reponse", http_status: 200, pki_status: null, failure_info: null, retry_after_s: null, nonce_in_response: null, imprint_matches: null,
  checks_passed: [], gen_time: null, accuracy_s: null, token_sha256: null, token_size: null, ...champs,
});
const INCLUSION = (request_id, bloc) => ({ request_id, block_number: bloc, capture_sha256: SHA(`capture ${request_id} ${bloc}`) });
const e = (t, type, data = {}) => ({ t, type, data });

/** Rejoue des entrées sur une configuration ; rend les actions et la file. */
function scenario(config, inputs, options = {}) {
  const p = creerPlanificateur(config, { gigues: options.gigues ?? [], nonces: noncesVecteurs(), fileInitiale: options.fileInitiale ?? [], ...options.planificateur });
  const actions = [];
  for (const i of inputs) actions.push(...p.traiter(i));
  return { actions, file: p.file(), planificateur: p };
}
const configReference = () => structuredClone(trace("heure-nominale-reference").config);
const actionsDe = (actions, filtre) => actions.filter((a) => a.action === filtre.action && (!filtre.request || a.request_id?.startsWith(filtre.request)));

describe("ancrage, planificateur : requête TimeStampReq d'EX-5.1 (AN-5, AN-6)", function () {
  const famille = lire("ct-5", "requetes", "requetes.json");

  it("chaque cas de requetes/ est reconstruit octet pour octet, SHA-256 et taille compris, égal au fichier .tsq", function () {
    expect(famille.cases).to.have.lengthOf(6);
    for (const c of famille.cases) {
      const nonce = nonceEtiquette(c.input.nonce_label);
      expect(nonce).to.equal(c.expected.nonce);
      const q = requeteTimeStampReq({ imprint: c.input.digest, nonce, policy_oid: c.input.policy_oid, cert_req: c.input.cert_req });
      expect(N.octetsVersHex(q.octets)).to.equal(c.expected.der);
      expect(q.sha256).to.equal(c.expected.sha256);
      expect(q.taille).to.equal(c.expected.size);
      expect(Buffer.compare(Buffer.from(q.octets), fs.readFileSync(path.join(CT5, "requetes", c.expected.file)))).to.equal(0);
      const relue = relireTimeStampReq(q.octets);
      expect(relue).to.deep.equal({ imprint: c.input.digest, nonce: c.expected.nonce, policy_oid: c.input.policy_oid, cert_req: true });
    }
  });

  it("les constructions de refusees.json sont refusées avec la règle et le message attendus", function () {
    const refusees = lire("ct-5", "requetes", "refusees.json");
    expect(refusees.cases).to.have.lengthOf(5);
    for (const c of refusees.cases) {
      let erreur = null;
      try {
        if (c.input.der) relireTimeStampReq(N.hexVersOctets(c.input.der));
        else requeteTimeStampReq({ imprint: c.input.digest, nonce: c.input.nonce, policy_oid: c.input.policy_oid, cert_req: c.input.cert_req });
      } catch (err) {
        erreur = err;
      }
      expect(erreur, c.id).to.be.instanceOf(ErreurRequeteDer);
      expect(erreur.regle).to.equal(c.expected.rule);
      expect(erreur.message).to.equal(c.expected.message);
    }
  });

  it("nonce : bit de poids fort à 1 → octet 00 de tête et 70 octets ; bit nul → 69 ; politique de test → 81 ou 82 (EX-5.1, EX-8.6)", function () {
    const base = { imprint: K2.checkpoint_hash, policy_oid: null };
    expect(requeteTimeStampReq({ ...base, nonce: "0x74a6f4979421411e" }).taille).to.equal(69);
    expect(requeteTimeStampReq({ ...base, nonce: "0xf4a6f4979421411e" }).taille).to.equal(70);
    expect(N.octetsVersHex(requeteTimeStampReq({ ...base, nonce: "0xf4a6f4979421411e" }).octets)).to.include("020900f4a6f4979421411e");
    expect(requeteTimeStampReq({ ...base, nonce: 1n }).taille).to.equal(62);
    expect(requeteTimeStampReq({ ...base, policy_oid: "1.3.6.1.4.1.99999.1.1", nonce: "0xf4a6f4979421411e" }).taille).to.equal(82);
    expect(N.octetsVersHex(encoderOidDer("1.3.6.1.4.1.99999.1.1"))).to.equal("0x060a2b06010401868d1f0101");
    expect(nonceHex(nonceEntier("0x1"))).to.equal("0x0000000000000001");
  });

  it("entrées hostiles : algorithme autre que SHA-256, empreinte sans 0x, OID mal formé, octets en trop, longueur non minimale, extension", function () {
    const base = { imprint: K2.checkpoint_hash, nonce: 7n, policy_oid: null };
    expect(() => requeteTimeStampReq({ ...base, hash: "sha512" })).to.throw(ErreurRequeteDer, /SHA-256/);
    expect(() => requeteTimeStampReq({ ...base, imprint: K2.checkpoint_hash.slice(2) })).to.throw(ErreurRequeteDer);
    expect(() => requeteTimeStampReq({ ...base, policy_oid: "1.40.1" })).to.throw(ErreurRequeteDer);
    expect(() => requeteTimeStampReq({ ...base, policy_oid: "a.b" })).to.throw(ErreurRequeteDer);
    expect(() => requeteTimeStampReq({ ...base, nonce: "12" })).to.throw(ErreurRequeteDer);
    const bons = requeteTimeStampReq(base).octets;
    expect(() => relireTimeStampReq(Uint8Array.from([...bons, 0x00]))).to.throw(ErreurRequeteDer, /au-delà/);
    const longueurLongue = Uint8Array.from([0x30, 0x81, bons[1], ...bons.subarray(2)]);
    expect(() => relireTimeStampReq(longueurLongue)).to.throw(ErreurRequeteDer, /non minimale/);
    const avecExtension = Uint8Array.from([0x30, bons[1] + 2, ...bons.subarray(2), 0xa0, 0x00]);
    expect(() => relireTimeStampReq(avecExtension)).to.throw(ErreurRequeteDer, /extensions/);
    expect(() => relireTimeStampReq(new Uint8Array(300))).to.throw(ErreurRequeteDer, /au plus 200/);
    expect(() => relireTimeStampReq("texte")).to.throw(ErreurRequeteDer);
    const certReqFaux = Uint8Array.from(bons);
    certReqFaux[certReqFaux.length - 1] = 0x00;
    expect(() => relireTimeStampReq(certReqFaux)).to.throw(ErreurRequeteDer, /certReq/);
  });
});

describe("ancrage, planificateur : échéances, cadence et table (EX-4.1 à EX-4.4, AN-2)", function () {
  const config = configReference();

  it("EX-4.2 : D_k = period_start + k × c_T pour k = 1 … n_T − 1, la clôture tenant lieu de n_T", function () {
    const r = echeances({ periodStart: PERIODE, intervalS: 300 });
    expect(r.n_T).to.equal(12);
    expect(r.liste).to.have.lengthOf(11);
    expect(r.liste[0]).to.deep.equal({ k: 1, at: "2026-11-03T13:05:00.000Z", at_ms: (PERIODE + 300) * 1000 });
    expect(r.liste[10].at).to.equal("2026-11-03T13:55:00.000Z");
    expect(r.cloture).to.deep.equal({ k: 12, at: "2026-11-03T14:00:00.000Z", at_ms: (PERIODE + 3600) * 1000 });
    expect(echeances({ periodStart: PERIODE, intervalS: 3600 }).liste).to.deep.equal([]);
    expect(echeances({ periodStart: PERIODE, intervalS: 720 }).liste.map((x) => x.k)).to.deep.equal([1, 2, 3, 4]);
    expect(() => echeances({ periodStart: PERIODE + 1, intervalS: 300 })).to.throw(RangeError);
    expect(() => echeances({ periodStart: PERIODE, intervalS: 500 })).to.throw(RangeError);
  });

  it("EX-4.1 : constat de cadence à c_K + 1 s, point_manquant à 2 × c_K ; une série alignée est conforme", function () {
    const serie = lire("ct-1", "points-de-controle", "periode-1.json");
    const r = constaterCadence({ periodStart: 1793869200, checkpointIntervalS: 60, points: serie });
    expect(r.conforme).to.equal(true);
    expect(r.tolerance_s).to.equal(61);
    const exemple = constaterCadence({ periodStart: PERIODE, checkpointIntervalS: 60, points: [K1, K2] });
    expect(exemple.ecarts).to.deep.equal([{ de: null, a: K1.checkpoint_ts, gap_s: 2520 }, { de: K1.checkpoint_ts, a: K2.checkpoint_ts, gap_s: 660 }]);
    expect(exemple.points_manquants).to.deep.equal([{ last_checkpoint_ts: K1.checkpoint_ts, gap_s: 660 }]);
    const limite = constaterCadence({ periodStart: PERIODE, checkpointIntervalS: 60, points: [{ ...K1, checkpoint_ts: "2026-11-03T13:00:00.000Z" }, { ...K2, checkpoint_ts: "2026-11-03T13:01:01.000Z" }] });
    expect(limite.ecarts).to.deep.equal([]);
    expect(() => constaterCadence({ periodStart: PERIODE, checkpointIntervalS: 60, points: [K2, K1] })).to.throw(RangeError);
    expect(() => constaterCadence({ periodStart: PERIODE, checkpointIntervalS: 7, points: [] })).to.throw(RangeError);
  });

  it("EX-4.3 : le point sélectionné à D_k est le premier de checkpoint_ts ≥ D_k ; un jeton satisfait toutes ses échéances ; sans_objet sans nouvel événement", function () {
    const K3 = { ...K2, checkpoint_hash: "0x3feb86ac4d6d8c054bef224f131f0276d2f1c9c9db2a6ce06adec173378d8867", checkpoint_ts: "2026-11-03T13:54:00.000Z" };
    const K4 = { ...K2, tree_size: 5, checkpoint_hash: "0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107", checkpoint_ts: "2026-11-03T14:00:00.250Z" };
    const ancres = [
      { checkpoint_hash: K1.checkpoint_hash, jeton: { gen_time: "2026-11-03T13:42:04Z", accuracy_s: 1 }, registre: { received_at: "2026-11-03T13:42:03.000Z" } },
      { checkpoint_hash: K2.checkpoint_hash, jeton: { gen_time: "2026-11-03T13:53:03Z", accuracy_s: 1 }, registre: { received_at: "2026-11-03T13:53:02.000Z" } },
      { checkpoint_hash: K4.checkpoint_hash, jeton: { gen_time: "2026-11-03T14:00:02Z", accuracy_s: 1 }, registre: { received_at: "2026-11-03T14:00:02.000Z" } },
    ];
    const t = tableEcheances({ periodStart: PERIODE, configuration: config, points: [K1, K2, K3, K4], ancres, cloture: { jeton: { gen_time: "2026-11-03T14:00:05Z", accuracy_s: 1 }, registre: { received_at: "2026-11-03T14:00:04.000Z" }, generated_at: CLOTURE.generated_at } });
    expect(t.echeances.map((x) => [x.k, x.state, x.tree_size])).to.deep.equal([[1, "satisfaite", 2], [2, "satisfaite", 2], [3, "satisfaite", 2], [4, "satisfaite", 2], [5, "satisfaite", 2], [6, "satisfaite", 2], [7, "satisfaite", 2], [8, "satisfaite", 2], [9, "satisfaite", 4], [10, "satisfaite", 4], [11, "satisfaite", 5]]);
    expect(t.echeances[7].d_jeton_s).to.equal(125);
    expect(t.echeances[10].d_jeton_s).to.equal(303);
    expect(t.cloture).to.deep.equal({ k: 12, at: "2026-11-03T14:00:00.000Z", state: "satisfaite", d_jeton_s: 6, d_registre_s: 3 });
    expect(t.ancres.map((a) => a.d_registre_s)).to.deep.equal([3, 2, 1]);
    expect(t.alertes.filter((a) => a.code !== "point_manquant")).to.deep.equal([]);
    expect(t.fenetres.W_date_max_s).to.equal(300 + 2225);
    // Sans jeton sur K2, D_9 et D_10 sont sans_objet si K2 n'engage rien de plus que le dernier contresigné… ici il engage (4 > 2) : en_attente puis remplacee par D_11.
    const t2 = tableEcheances({ periodStart: PERIODE, configuration: config, points: [K1, K2, K3, K4], ancres: ancres.filter((a) => a.checkpoint_hash !== K2.checkpoint_hash) });
    expect(t2.echeances.slice(8).map((x) => x.state)).to.deep.equal(["remplacee", "remplacee", "satisfaite"]);
    expect(t2.alertes.filter((a) => a.code === "checkpoint_anchor_late").map((a) => a.k)).to.deep.equal([9, 10]);
    // Preuve de vie : K3 (même tree_size que K2 contresigné) sélectionné seul serait sans_objet.
    const t3 = tableEcheances({ periodStart: PERIODE, configuration: config, points: [K1, K2, { ...K3, checkpoint_ts: "2026-11-03T13:55:00.000Z" }], ancres: ancres.slice(0, 2) });
    expect(t3.echeances[10].state).to.equal("sans_objet");
    const idle = tableEcheances({ periodStart: PERIODE, configuration: { ...config, rfc3161: { ...config.rfc3161, checkpoints: { ...config.rfc3161.checkpoints, countersign_idle: true } } }, points: [K1, K2, { ...K3, checkpoint_ts: "2026-11-03T13:55:00.000Z" }], ancres: ancres.slice(0, 2) });
    expect(idle.echeances[10].state).to.equal("en_attente");
  });

  it("AN-2 : jeton_anterieur_au_point quand genTime + précision < checkpoint_ts − clock_tolerance_s, contresignature_tardive au-delà de c_T, inclusion_late au-delà de inclusion_alert_s", function () {
    const t = tableEcheances({
      periodStart: PERIODE,
      configuration: config,
      points: [K1, K2],
      ancres: [
        { checkpoint_hash: K1.checkpoint_hash, jeton: { gen_time: "2026-11-03T13:39:30Z", accuracy_s: 1 }, registre: { received_at: "2026-11-03T13:43:30.000Z" } },
        { checkpoint_hash: K2.checkpoint_hash, jeton: { gen_time: "2026-11-03T13:58:30Z", accuracy_s: 1 } },
      ],
    });
    const codes = t.alertes.map((a) => a.code);
    expect(codes).to.include("jeton_anterieur_au_point");
    expect(codes).to.include("contresignature_tardive");
    expect(codes).to.include("inclusion_late");
    const propre = tableEcheances({ periodStart: PERIODE, configuration: config, points: [K1], ancres: [{ checkpoint_hash: K1.checkpoint_hash, jeton: { gen_time: "2026-11-03T13:40:01Z", accuracy_s: 1 }, registre: { received_at: "2026-11-03T13:42:59.000Z" } }] });
    expect(propre.alertes.filter((a) => a.code !== "point_manquant")).to.deep.equal([]);
    expect(() => tableEcheances({ periodStart: PERIODE, configuration: config, points: [K1], ancres: [{ checkpoint_hash: "0x12" }] })).to.throw(TypeError);
    expect(() => tableEcheances({ periodStart: PERIODE, configuration: {}, points: [] })).to.throw(TypeError);
  });
});

describe("ancrage, planificateur : admission par le noyau (AN-3)", function () {
  const attendu = lire("ct-1", "points-de-controle", "attendu.json");
  const cles = lire("ct-1", "journal-valide", "cles.json");
  const evenements = lire("ct-1", "journal-valide", "evenements.json");
  const manifeste = (nom) => lire("ct-1", "manifestes", path.posix.basename(nom));
  const admettreSerie = (points, m) => {
    const hashes = evenements.filter((x) => x.seq >= m.first_seq && x.seq <= m.last_seq).map((x) => N.hacherEvenement(x));
    const serie = [];
    for (const p of points) {
      const r = admettrePoint({ point: p, serie, cles, evenements, hashesPeriode: hashes, periodStart: m.period_start, org_id: m.org_id, journal_id: m.journal_id, firstSeq: m.first_seq });
      if (!r.admis) return { refus: r, admis: serie.length };
      expect(r.empreinte).to.equal(N.hacherPoint(p));
      serie.push(p);
    }
    return { refus: null, admis: serie.length };
  };

  it("les trois séries valides de CT-1 sont admises point par point, empreinte recalculée, et valides pour verifierSerie", function () {
    for (const per of attendu.periodes) {
      const points = lire("ct-1", "points-de-controle", per.file);
      const m = manifeste(per.manifest);
      const r = admettreSerie(points, m);
      expect(r.refus, per.file).to.equal(null);
      expect(r.admis).to.equal(per.count);
      expect(verifierSerie({ points, manifeste: m, evenements, cles }).valide).to.equal(true);
    }
  });

  it("chaque série invalide de CT-1 est refusée au premier point fautif, avec la règle de refus correspondante", function () {
    const correspondance = {
      "invalides/periode-1-antidate.json": ["monotonie", 33],
      "invalides/periode-1-tree-size-decroissant.json": ["monotonie", 33],
      "invalides/periode-1-chainage-faux.json": ["chainage", 20],
      "invalides/periode-1-signature.json": ["signature", 10],
      "invalides/periode-1-cle-perimee.json": ["signature", 60],
      "invalides/periode-1-tree-size-trop-grand.json": ["last_seq", 60],
      "invalides/periode-1-cle-inconnue.json": ["signature", 10],
      "invalides/periode-1-last-hash.json": ["last_hash", 32],
      "invalides/periode-1-cle-last-seq-0.json": ["signature", 0],
    };
    for (const inv of attendu.invalides) {
      const m = manifeste(inv.manifest);
      const r = admettreSerie(lire("ct-1", "points-de-controle", inv.file), m);
      if (inv.file === "invalides/periode-1-sans-cloture.json") {
        // Règle 4 (dernier point) : une règle de série à la clôture, pas une règle d'admission d'un point ; verifierSerie la nomme.
        expect(r.refus).to.equal(null);
        expect(verifierSerie({ points: lire("ct-1", "points-de-controle", inv.file), manifeste: m, evenements, cles }).rules_failed).to.deep.equal(["dernier_point"]);
        continue;
      }
      expect(r.refus, inv.file).to.not.equal(null);
      expect([r.refus.regle, r.admis], inv.file).to.deep.equal(correspondance[inv.file]);
      expect(REGLES_ADMISSION).to.include(r.refus.regle);
    }
  });

  it("racine : root nulle pour tree_size ≥ 1, non nulle pour 0, ou différente de la racine recalculée ; last_hash et last_seq recalculés", function () {
    const points = lire("ct-1", "points-de-controle", "periode-1.json");
    const m = manifeste("periode-1.json");
    const hashes = evenements.filter((x) => x.seq >= 1 && x.seq <= 9).map((x) => N.hacherEvenement(x));
    const p13 = points[13];
    const serie = points.slice(0, 13);
    const base = { serie, cles, hashesPeriode: hashes, periodStart: m.period_start, firstSeq: m.first_seq };
    expect(admettrePoint({ ...base, point: p13 }).admis).to.equal(true);
    // Le contenu signé ne peut être altéré sans casser la signature, contrôlée avant le contenu (AN-3, ordre des règles).
    expect(admettrePoint({ ...base, point: { ...p13, root: N.ZERO32 } }).regle).to.equal("signature");
    expect(admettrePoint({ ...base, point: { ...p13, last_hash: "0x" + "22".repeat(32) } }).regle).to.equal("signature");
    // Les règles de contenu se constatent contre les événements de la période : racine différente, événements insuffisants.
    const autresHashes = hashes.map((h, i) => (i === 4 ? "0x" + "11".repeat(32) : h));
    expect(admettrePoint({ ...base, point: p13, hashesPeriode: autresHashes }).regle).to.equal("racine");
    expect(admettrePoint({ ...base, point: p13, hashesPeriode: hashes.slice(0, 4) }).regle).to.equal("last_seq");
    expect(admettrePoint({ ...base, point: p13, hashesPeriode: hashes.slice(0, 5) }).admis).to.equal(true);
    expect(admettrePoint({ ...base, point: points[0], serie: [], hashesPeriode: [] }).admis).to.equal(true);
    // Sans les événements, root et last_hash ne sont pas évaluées : le point est admis sur la seule série (signature, chaînage, monotonie).
    expect(admettrePoint({ point: p13, serie, cles, periodStart: m.period_start }).admis).to.equal(true);
    expect(admettrePoint({ point: { ...p13, root: "0x" + "11".repeat(32) }, serie, cles, periodStart: m.period_start }).regle).to.equal("signature");
    expect(admettrePoint({ ...base, point: p13, periodStart: m.period_start + 3600 }).regle).to.equal("period_start");
    expect(admettrePoint({ ...base, point: p13, org_id: "0x" + "ab".repeat(32) }).regle).to.equal("period_start");
    // La monotonie se constate sur le vecteur CT-1 « antidate » (essai précédent) ; ici, un checkpoint_ts altéré casse d'abord la signature.
    expect(admettrePoint({ ...base, point: { ...p13, checkpoint_ts: "2026-11-05T08:59:59.000Z" } }).regle).to.equal("signature");
  });

  it("entrées hostiles : point non objet, champ manquant, hexadécimal majuscule, signature de mauvaise taille, clés inexploitables, série non tableau", function () {
    const points = lire("ct-1", "points-de-controle", "periode-1.json");
    const m = manifeste("periode-1.json");
    const base = { serie: [], cles, periodStart: m.period_start };
    expect(admettrePoint({ ...base, point: null }).regle).to.equal("format");
    expect(admettrePoint({ ...base, point: [] }).regle).to.equal("format");
    const sansSig = { ...points[0] };
    delete sansSig.sig;
    expect(admettrePoint({ ...base, point: sansSig }).regle).to.equal("format");
    expect(admettrePoint({ ...base, point: { ...points[0], root: points[0].root.toUpperCase() } }).regle).to.equal("format");
    expect(admettrePoint({ ...base, point: { ...points[0], sig: "0x00" } }).regle).to.equal("format");
    expect(admettrePoint({ ...base, point: { ...points[0], checkpoint_ts: "2026-11-05T09:00:00Z" } }).regle).to.equal("format");
    expect(admettrePoint({ ...base, point: points[0], cles: { version: 0, keys: [] } }).regle).to.equal("signature");
    expect(admettrePoint({ ...base, point: points[0], cles: 42 }).regle).to.equal("signature");
    expect(() => admettrePoint({ ...base, point: points[0], serie: "x" })).to.throw(TypeError);
    expect(() => admettrePoint({ ...base, point: points[0], periodStart: 12.5 })).to.throw(RangeError);
    expect(() => admettrePoint({ ...base, point: points[0], hashesPeriode: ["0x12"] })).to.throw(TypeError);
  });

  it("manifeste : admis sous la clé en vigueur, refusé sur signature fausse, clé inconnue, forme hors schéma, signature mal formée", function () {
    const m = manifeste("periode-1.json");
    const sig = lire("ct-1", "manifestes", "periode-1.sig");
    const ok = admettreManifeste({ manifeste: m, signature: sig, cles });
    expect(ok).to.deep.equal({ admis: true, empreinte: N.hacherManifeste(m), regle: null, detail: null });
    expect(admettreManifeste({ manifeste: m, signature: sig.sig, cles }).admis).to.equal(true);
    expect(admettreManifeste({ manifeste: m, signature: { sig: "0x" + "00".repeat(64) }, cles }).regle).to.equal("signature");
    expect(admettreManifeste({ manifeste: { ...m, recorder_key_id: "rec-test-09" }, signature: sig, cles }).regle).to.equal("signature");
    expect(admettreManifeste({ manifeste: { ...m, count: 8 }, signature: sig, cles }).regle).to.equal("format");
    expect(admettreManifeste({ manifeste: m, signature: "0x12", cles }).regle).to.equal("signature");
    expect(admettreManifeste({ manifeste: "x", signature: sig, cles }).regle).to.equal("format");
  });
});

describe("ancrage, planificateur : sélection et comptages (EX-4.6, EX-4.11, AN-4), coût (AN-59, AN-60), complétude (AN-61)", function () {
  it("EX-4.6 : nouveaux_evenements ancre chaque point dont tree_size dépasse le dernier ancré, tous ancre chaque point, aucun n'ancre rien", function () {
    const serie = lire("ct-1", "points-de-controle", "periode-1.json");
    const nouveaux = pointsAAncrer({ points: serie, regle: "nouveaux_evenements" });
    expect(nouveaux.map((p) => [p.tree_size, p.checkpoint_ts])).to.deep.equal([[5, "2026-11-05T09:13:00.000Z"], [8, "2026-11-05T09:32:00.000Z"], [9, "2026-11-05T10:00:00.300Z"]]);
    expect(pointsAAncrer({ points: serie, regle: "tous" })).to.have.lengthOf(61);
    expect(pointsAAncrer({ points: serie, regle: "aucun" })).to.deep.equal([]);
    expect(() => pointsAAncrer({ points: serie, regle: "parfois" })).to.throw(RangeError);
    expect(() => pointsAAncrer({ points: [serie[1], serie[0]], regle: "tous" })).to.throw(RangeError);
    expect(() => pointsAAncrer({ points: [{ checkpoint_hash: "0x1", tree_size: 1, checkpoint_ts: serie[0].checkpoint_ts }], regle: "tous" })).to.throw(TypeError);
  });

  it("EX-4.11 : la table des comptages pour les cadences admises (N_h = 8 760) et les comptages d'une configuration", function () {
    const table = tableComptages();
    expect(table.map((l) => [l.c_T, l.jetons_par_heure, l.dont_points, l.jetons_par_jour, l.jetons_par_an, l.qualifies_par_an_principal, l.qualifies_par_an_autre, l.autres_par_an_autre])).to.deep.equal([
      [60, 60, 59, 1440, 525600, 525600, 8760, 516840],
      [120, 30, 29, 720, 262800, 262800, 8760, 254040],
      [180, 20, 19, 480, 175200, 175200, 8760, 166440],
      [300, 12, 11, 288, 105120, 105120, 8760, 96360],
      [600, 6, 5, 144, 52560, 52560, 8760, 43800],
      [900, 4, 3, 96, 35040, 35040, 8760, 26280],
      [1800, 2, 1, 48, 17520, 17520, 8760, 8760],
      [3600, 1, 0, 24, 8760, 8760, 8760, 0],
    ]);
    const c = configReference();
    const r = compterJetons(c);
    expect(r.par_heure).to.deep.equal({ jetons: 12, jetons_points: 11, jetons_qualifies: 1, jetons_autres: 11, jeton_cloture: 1, ancres: 62, ancres_points: 61, submit_period: 1, soumissions_ots: 1 });
    expect(r.par_jour.ancres).to.equal(1488);
    expect(r.par_an.jetons).to.equal(105120);
    expect(compterJetons(c, { heuresParAn: 8784 }).par_an.jeton_cloture).to.equal(8784);
    c.rfc3161.checkpoints.provider_role = "principal";
    expect(compterJetons(c).par_heure.jetons_qualifies).to.equal(12);
    c.opentimestamps.checkpoint = "mi_periode";
    expect(compterJetons(c).par_heure.soumissions_ots).to.equal(2);
    c.registry.checkpoints = "aucun";
    expect(compterJetons(c).par_heure.ancres).to.equal(1);
    expect(() => compterJetons(c, { heuresParAn: 9000 })).to.throw(RangeError);
    expect(() => compterJetons({ ...c, checkpoint_interval_s: 7 })).to.throw(RangeError);
    expect(() => compterJetons(null)).to.throw(TypeError);
  });

  it("EX-12.1, EX-12.2, AN-59 : les onze cas de cout/ rendent exactement les six grandeurs ; avec a = 1 les jetons égalent la table de 4.6", function () {
    const famille = lire("ct-5", "cout", "cout.json");
    expect(famille.cases).to.have.lengthOf(11);
    for (const cas of famille.cases) expect(cout(cas.input), cas.id).to.deep.equal(cas.expected);
    const a1 = famille.cases.find((c) => c.id === "points-chez-principal-a1-dix-journaux");
    expect(cout(a1.input).qualified_tokens_per_journal).to.equal(tableComptages()[3].qualifies_par_an_principal);
    expect(GAZ_ANCRE_MAX).to.equal(96977);
    expect(GAZ_CLOTURE_MAX).to.equal(314256);
  });

  it("AN-60 : les prix des vecteurs sont des unités symboliques (1, 0,2, 10 000) ; les entrées hostiles sont refusées", function () {
    const famille = lire("ct-5", "cout", "cout.json");
    for (const cas of famille.cases) {
      expect([0, 1]).to.include(cas.input.unit_price_qualified);
      expect([0, 0.2]).to.include(cas.input.unit_price_second_rank);
      expect([0, 10000]).to.include(cas.input.subscription_fee);
    }
    const base = famille.cases[0].input;
    expect(() => cout({ ...base, journals: 0 })).to.throw(RangeError);
    expect(() => cout({ ...base, activity_ratio: 1.5 })).to.throw(RangeError);
    expect(() => cout({ ...base, unit_price_qualified: -1 })).to.throw(RangeError);
    expect(() => cout({ ...base, checkpoints_provider_role: "autre" })).to.throw(RangeError);
    expect(() => cout({ ...base, rfc3161_checkpoint_interval_s: 500 })).to.throw(RangeError);
    expect(() => cout({ ...base, hours_per_year: 9000 })).to.throw(RangeError);
    expect(() => cout({ ...base, subscription_quota: -5 })).to.throw(RangeError);
    expect(() => cout({ ...base, billable_retry_ratio: 11 })).to.throw(RangeError);
    expect(() => cout({ ...base, countersign_idle: "non" })).to.throw(TypeError);
    expect(() => cout(null)).to.throw(TypeError);
  });

  it("EX-10.7, AN-61 : les six cas de completude/ sont reproduits ; les entrées hostiles sont refusées", function () {
    const famille = lire("ct-5", "completude", "completude.json");
    expect(famille.cases).to.have.lengthOf(6);
    for (const cas of famille.cases) expect(verifierCompletudeRegistre(cas.input), cas.id).to.deep.equal(cas.expected);
    const base = famille.cases[0].input;
    expect(() => verifierCompletudeRegistre({ ...base, to_block: base.from_block })).to.throw(RangeError);
    expect(() => verifierCompletudeRegistre({ ...base, issuers: ["0xAA2A59656361352E96EF2EED355316EF8B29DAB7"] })).to.throw(TypeError);
    expect(() => verifierCompletudeRegistre({ ...base, anchors: [{ ...base.anchors[0], fingerprint: "0x12" }] })).to.throw(TypeError);
    expect(() => verifierCompletudeRegistre({ ...base, journals: [] })).to.throw(TypeError);
    expect(() => verifierCompletudeRegistre({ ...base, from_block: -2 })).to.throw(RangeError);
    // Une ancre répétée (même empreinte à deux blocs) : la seconde est rattachée mais hors ordre seulement si son checkpoint_ts précède.
    const doublon = { ...base, anchors: [...base.anchors, { ...base.anchors[0], block_number: 30101 }] };
    expect(verifierCompletudeRegistre(doublon).out_of_order).to.deep.equal([base.anchors[0].fingerprint]);
  });
});

describe("ancrage, planificateur : supervision (EX-8.15, AN-43)", function () {
  it("les noms de métriques sont exactement ceux de la table d'EX-8.15, avec leurs étiquettes", function () {
    expect(Object.keys(METRIQUES_ANCRAGE)).to.deep.equal([
      "noortrace_anchor_pending", "noortrace_anchoring_queue_entries", "noortrace_anchoring_attempts_total", "noortrace_anchoring_last_success_age_s",
      "noortrace_anchoring_deadlines_total", "noortrace_anchoring_window_s", "noortrace_anchoring_d_jeton_s", "noortrace_anchoring_d_point_s",
      "noortrace_anchoring_d_registre_s", "noortrace_anchoring_ots_pending_age_s",
    ]);
    expect(METRIQUES_ANCRAGE.noortrace_anchoring_attempts_total.etiquettes).to.deep.equal(["kind", "provider", "outcome"]);
    expect(METRIQUES_ANCRAGE.noortrace_anchor_pending.etiquettes).to.deep.equal(["anchor"]);
    for (const ev of ["anchoring_started", "anchoring_queue_rebuilt", "checkpoint_countersigned", "checkpoint_closing_fallback", "point_manquant", "anchor_queue_truncated_line", "ordre_ancres_non_respecte"]) expect(EVENEMENTS_JOURNAL).to.include(ev);
  });

  it("le format d'exposition texte porte HELP, TYPE, séries étiquetées, seaux d'histogramme ; les étiquettes hors table sont refusées", function () {
    const s = new Supervision();
    s.jauge("noortrace_anchor_pending", { anchor: "rfc3161" }, 2);
    s.compter("noortrace_anchoring_deadlines_total", { state: "satisfaite" }, 3);
    s.observer("noortrace_anchoring_d_point_s", {}, 120);
    const texte = s.metriques();
    expect(texte).to.include("# TYPE noortrace_anchor_pending gauge\nnoortrace_anchor_pending{anchor=\"rfc3161\"} 2\n");
    expect(texte).to.include("noortrace_anchoring_deadlines_total{state=\"satisfaite\"} 3");
    expect(texte).to.include("noortrace_anchoring_d_point_s_bucket{le=\"120\"} 1");
    expect(texte).to.include("noortrace_anchoring_d_point_s_sum 120");
    expect(texte).to.include("noortrace_anchoring_d_point_s_count 1");
    expect(texte.endsWith("\n")).to.equal(true);
    expect(() => s.jauge("noortrace_anchor_pending", { anchor: "rfc3161", host: "x" }, 1)).to.throw(TypeError);
    // R-F-2 (lot H1) : une valeur d'étiquette hors motif n'est plus refusée mais normalisée (minuscules, caractères hors de [a-z0-9_:.-] remplacés par _).
    s.jauge("noortrace_anchor_pending", { anchor: "réseau" }, 1);
    expect(s.metriques()).to.include('noortrace_anchor_pending{anchor="r_seau"} 1');
    expect(() => s.jauge("noortrace_inconnue", {}, 1)).to.throw(RangeError);
    expect(() => s.compter("noortrace_anchor_pending", { anchor: "ots" })).to.throw(RangeError);
    expect(() => s.compter("noortrace_anchoring_deadlines_total", { state: "x" }, -1)).to.throw(RangeError);
  });

  it("releverActions tire les jauges de la file et les histogrammes des lignes ; window_s ne compte qu'un prestataire extérieur", function () {
    const t = trace("heure-nominale-reference");
    const { rejouerTrace } = { rejouerTrace: null };
    void rejouerTrace;
    const r = scenario(t.config, t.inputs);
    const maintenant = N.decoderHorodatage("2026-11-03T14:01:00.000Z");
    const interne = new Supervision({ prestatairesExterieurs: ["qtsa-principal", "qtsa-secours"], journalAbrege: "j1" });
    interne.releverActions({ actions: r.actions, file: r.file, maintenant });
    const texte = interne.metriques();
    expect(texte).to.include("noortrace_anchoring_queue_entries{kind=\"ots_periode\",state=\"en_attente\"} 1");
    expect(texte).to.include("noortrace_anchoring_deadlines_total{state=\"satisfaite\"} 12");
    expect(texte).to.include("noortrace_anchoring_window_s{journal=\"j1\"} 54");
    expect(texte).to.include("noortrace_anchoring_d_jeton_s_count{kind=\"jeton_point\",provider=\"tsa-interne\"} 3");
    expect(texte).to.include("noortrace_anchor_pending{anchor=\"rfc3161\"} 0");
    const sansExterieur = new Supervision();
    sansExterieur.releverActions({ actions: r.actions, file: r.file, maintenant });
    expect(sansExterieur.metriques()).to.not.include("noortrace_anchoring_window_s{");
  });

  it("consigner écrit par le journal injecté au format de CT-2 EX-9.5 et refuse jeton, pièce, secret et valeurs longues (AN-43)", function () {
    const lignes = [];
    const journal = { consigner: (niveau, composant, evenement, data) => lignes.push({ niveau, composant, evenement, data }) };
    const s = new Supervision({ journal, horloge: { murale: () => 1793714460000 } });
    const l = s.consigner("info", "checkpoint_countersigned", { tree_size: 2, provider: "tsa-interne", d_jeton_s: 125 });
    expect(l.ts).to.equal("2026-11-03T14:01:00.000Z");
    expect(lignes).to.deep.equal([{ niveau: "info", composant: "ancrage", evenement: "checkpoint_countersigned", data: { tree_size: 2, provider: "tsa-interne", d_jeton_s: 125 } }]);
    for (const champs of [{ token: "x" }, { secret: "x" }, { password: "x" }, { jeton: "x" }, { Authorization: "x" }, { piece: "x" }, { note: "-----BEGIN CERTIFICATE-----" }, { blob: "a".repeat(513) }, { octets: new Uint8Array(2) }]) {
      expect(() => s.consigner("info", "x", champs), JSON.stringify(Object.keys(champs))).to.throw(TypeError);
    }
    expect(() => s.consigner("fatal", "x", {})).to.throw(RangeError);
    expect(() => s.consigner("info", "Mauvais Nom", {})).to.throw(RangeError);
    const t = trace("heure-nominale-reference");
    const r = scenario(t.config, t.inputs);
    s.consignerActions(r.actions);
    expect(lignes.filter((x) => x.evenement === "alerte_point_manquant")).to.have.lengthOf(2);
    expect(lignes.some((x) => JSON.stringify(x).includes("0x9c4cd8444c868abd"))).to.equal(false);
  });
});

describe("ancrage, planificateur : conduites hors traces (EX-8.3 à EX-8.11, EX-9.4, EX-5.12)", function () {
  it("entrées hostiles : forme hors schéma, première entrée autre que demarrage, horloge qui recule, projection non conforme, type inconnu", function () {
    const c = configReference();
    expect(() => creerPlanificateur({ ...c, queue: {} }, { nonces: noncesVecteurs() })).to.throw(ErreurPlanificateur);
    const p = creerPlanificateur(c, { nonces: noncesVecteurs() });
    expect(() => p.traiter(e("2026-11-03T13:40:00.000Z", "tic"))).to.throw(ErreurPlanificateur, /démarrage/);
    expect(() => p.traiter({ t: "2026-11-03T13:40:00Z", type: "demarrage", data: {} })).to.throw(ErreurPlanificateur, /conforme/);
    expect(() => p.traiter(e("2026-11-03T13:40:00.000Z", "point_produit", { ...K1, tree_size: -1 }))).to.throw(ErreurPlanificateur);
    expect(() => p.traiter(e("2026-11-03T13:40:00.000Z", "demarrage", { extra: 1 }))).to.not.throw();
    expect(() => p.traiter(e("2026-11-03T13:39:59.999Z", "tic"))).to.throw(ErreurPlanificateur, /antérieure/);
    expect(() => p.traiter(e("2026-11-03T13:41:00.000Z", "demarrage"))).to.throw(ErreurPlanificateur, /déjà/);
    expect(() => p.traiter(e("2026-11-03T13:41:00.000Z", "reponse_rfc3161", { request_id: "x" }))).to.throw(ErreurPlanificateur);
    expect(() => creerPlanificateur(c, { fileInitiale: [{ version: 0 }] })).to.throw(ErreurPlanificateur);
    expect(() => creerPlanificateur(c, {}).traiter(e("2026-11-03T13:40:00.000Z", "demarrage"))).to.not.throw();
  });

  it("sans source de nonces, un envoi RFC 3161 est refusé ; avec `aleatoire`, les nonces sont tirés sur 8 octets (tirage nul rejoué) et les gigues bornées", function () {
    const c = configReference();
    const p = creerPlanificateur(c, {});
    p.traiter(e("2026-11-03T13:40:00.000Z", "demarrage"));
    expect(() => p.traiter(e("2026-11-03T14:00:00.250Z", "periode_close", CLOTURE))).to.throw(ErreurPlanificateur, /nonces/);
    let appels = 0;
    const aleatoire = (n) => {
      appels += 1;
      return appels === 1 ? new Uint8Array(n) : Uint8Array.from({ length: n }, (_, i) => (i * 37 + appels) & 0xff);
    };
    const nonces = noncesAleatoires(aleatoire);
    const n1 = nonces.rfc3161();
    expect(typeof n1).to.equal("bigint");
    expect(n1 > 0n && n1 < 1n << 64n).to.equal(true);
    expect(nonces.ots()).to.have.lengthOf(16);
    for (let i = 0; i < 20; i++) expect(nonces.gigue(250)).to.be.within(0, 250);
    expect(nonces.gigue(0)).to.equal(0);
    expect(() => noncesAleatoires(null)).to.throw(TypeError);
    expect(() => noncesAleatoires(() => new Uint8Array(3)).rfc3161()).to.throw(TypeError);
    const p2 = creerPlanificateur(c, { aleatoire });
    p2.traiter(e("2026-11-03T13:40:00.000Z", "demarrage"));
    const actions = p2.traiter(e("2026-11-03T14:00:00.250Z", "periode_close", CLOTURE));
    expect(actions.some((a) => a.action === "soumettre_ots" && /^0x[0-9a-f]{32}$/.test(a.detail.nonce))).to.equal(true);
  });

  it("EX-8.5 règle 2 : un point remis deux fois ne crée pas deux demandes (anchor_duplicate_ignored) ; une inclusion répétée est ignorée", function () {
    const c = configReference();
    const r = scenario(c, [
      e("2026-11-03T13:40:00.000Z", "demarrage"),
      e("2026-11-03T13:42:00.000Z", "point_produit", K1),
      e("2026-11-03T13:42:03.000Z", "inclusion_registre", INCLUSION(`ancre_registre_point:${K1.checkpoint_hash}`, 20001)),
      e("2026-11-03T13:42:04.000Z", "inclusion_registre", INCLUSION(`ancre_registre_point:${K1.checkpoint_hash}`, 20001)),
      e("2026-11-03T13:42:05.000Z", "point_produit", K1),
      e("2026-11-03T13:42:06.000Z", "inclusion_registre", INCLUSION("ancre_registre_point:0x" + "ab".repeat(32), 1)),
    ]);
    expect(r.file.filter((d) => d.subject.hash === K1.checkpoint_hash)).to.have.lengthOf(2);
    const doublons = actionsDe(r.actions, { action: "journaliser" }).filter((a) => a.detail.event === "anchor_duplicate_ignored");
    expect(doublons.map((a) => [a.t, a.request_id.split(":")[0], a.detail.state ?? a.detail.reason])).to.deep.equal([
      ["2026-11-03T13:42:04.000Z", "ancre_registre_point", "obtenue"],
      ["2026-11-03T13:42:05.000Z", "ancre_registre_point", "obtenue"],
      ["2026-11-03T13:42:05.000Z", "jeton_point", "envoyee"],
      ["2026-11-03T13:42:06.000Z", "ancre_registre_point", "demande_inconnue"],
    ]);
    expect(actionsDe(r.actions, { action: "journaliser" }).some((a) => a.detail.event === "checkpoint_not_anchored")).to.equal(false);
    expect(actionsDe(r.actions, { action: "envoyer_rfc3161" })).to.have.lengthOf(1);
  });

  it("EX-4.6 : registry.checkpoints tous ancre chaque point, preuves de vie comprises ; aucun n'ancre rien et le jeton part aussitôt", function () {
    const K0 = { ...K1, tree_size: 0, checkpoint_hash: "0x" + "c1".repeat(32), checkpoint_ts: "2026-11-03T13:41:00.000Z" };
    const tous = configReference();
    tous.registry.checkpoints = "tous";
    const r = scenario(tous, [e("2026-11-03T13:40:00.000Z", "demarrage"), e("2026-11-03T13:41:00.000Z", "point_produit", K0), e("2026-11-03T13:42:00.000Z", "point_produit", K1)]);
    // Seule l'ancre du point de vie part (puis repart faute de reçu après inclusion_alert_s) ; celle de K1 attend son tour (EX-9.4).
    expect(actionsDe(r.actions, { action: "envoyer_registre" }).map((a) => [a.t, a.request_id])).to.deep.equal([
      ["2026-11-03T13:41:00.000Z", `ancre_registre_point:${K0.checkpoint_hash}`],
      ["2026-11-03T13:42:00.000Z", `ancre_registre_point:${K0.checkpoint_hash}`],
    ]);
    expect(r.file.filter((d) => d.kind === "ancre_registre_point").map((d) => d.state)).to.deep.equal(["envoyee", "a_envoyer"]);
    expect(actionsDe(r.actions, { action: "programmer" }).some((a) => a.detail.reason === "attente_nonce")).to.equal(true);
    const aucun = configReference();
    aucun.registry.checkpoints = "aucun";
    const r2 = scenario(aucun, [e("2026-11-03T13:40:00.000Z", "demarrage"), e("2026-11-03T13:42:00.000Z", "point_produit", K1)]);
    expect(actionsDe(r2.actions, { action: "envoyer_registre" })).to.deep.equal([]);
    expect(actionsDe(r2.actions, { action: "journaliser" }).find((a) => a.detail.event === "checkpoint_not_anchored").detail.reason).to.equal("registre_aucun");
    expect(actionsDe(r2.actions, { action: "envoyer_rfc3161" })[0].t).to.equal("2026-11-03T13:42:00.000Z");
    expect(r2.file.find((d) => d.kind === "jeton_point").state).to.equal("envoyee");
  });

  it("provider_role aucun (hors production) : les échéances sont closes sans_objet, aucun jeton de point, la clôture reste servie", function () {
    const c = configReference();
    c.rfc3161.checkpoints.provider_role = "aucun";
    c.opentimestamps.checkpoint = "mi_periode";
    const r = scenario(c, [e("2026-11-03T13:40:00.000Z", "demarrage"), e("2026-11-03T13:42:00.000Z", "point_produit", K1), e("2026-11-03T14:00:00.250Z", "periode_close", CLOTURE)]);
    expect(r.file.some((d) => d.kind === "jeton_point")).to.equal(false);
    expect(actionsDe(r.actions, { action: "echeance" }).filter((a) => a.detail.state === "sans_objet").map((a) => a.detail.k)).to.deep.equal([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(r.file.some((d) => d.kind === "ots_point")).to.equal(true);
    expect(r.file.some((d) => d.kind === "jeton_periode")).to.equal(true);
  });

  it("registre absent (hors production) : jeton_periode part aussitôt, sans attente de l'inclusion", function () {
    const c = configReference();
    const r = scenario(c, [e("2026-11-03T13:59:00.000Z", "demarrage"), e("2026-11-03T14:00:00.250Z", "periode_close", CLOTURE)], { planificateur: { sansRegistre: true } });
    const envoi = actionsDe(r.actions, { action: "envoyer_rfc3161", request: "jeton_periode" })[0];
    expect(envoi.t).to.equal("2026-11-03T14:00:00.250Z");
    expect(r.file.find((d) => d.kind === "jeton_periode").state).to.equal("envoyee");
  });

  it("EX-8.8 : un jeton_point du principal est relevé par le secours après checkpoints.fallback_after_s, les deux séries en parallèle, l'autre arrêtée à la promotion", function () {
    const c = configReference();
    c.rfc3161.checkpoints.provider_role = "principal";
    const id = `jeton_point:${K1.checkpoint_hash}`;
    const n = (k) => nonceVecteur({ journal: "journal-principal", sujet: "point", empreinte: K1.checkpoint_hash, n: k });
    const r = scenario(c, [
      e("2026-11-03T13:40:00.000Z", "demarrage"),
      e("2026-11-03T13:42:00.000Z", "point_produit", K1),
      e("2026-11-03T13:42:03.000Z", "inclusion_registre", INCLUSION(`ancre_registre_point:${K1.checkpoint_hash}`, 20001)),
      e("2026-11-03T13:42:13.000Z", "reponse_rfc3161", ERREUR(id, 1, { transport: "delai" })),
      e("2026-11-03T13:44:10.000Z", "tic"),
      e("2026-11-03T13:44:33.000Z", "reponse_rfc3161", GRANTED(id, 3, nonceHex(n(3)), "2026-11-03T13:44:32Z", "k1 secours")),
      e("2026-11-03T13:44:40.000Z", "reponse_rfc3161", GRANTED(id, 2, nonceHex(n(2)), "2026-11-03T13:44:39Z", "k1 principal tardif")),
    ]);
    const releve = actionsDe(r.actions, { action: "releve" })[0];
    expect(releve.t).to.equal("2026-11-03T13:44:03.000Z");
    expect(releve.detail.provider).to.equal("qtsa-secours");
    const envois = actionsDe(r.actions, { action: "envoyer_rfc3161" }).map((a) => [a.detail.attempt, a.detail.provider]);
    expect(envois).to.deep.equal([[1, "qtsa-principal"], [2, "qtsa-principal"], [3, "qtsa-secours"]]);
    const jeton = r.file.find((d) => d.id === id);
    expect(jeton.state).to.equal("obtenue");
    expect(jeton.result.provider).to.equal("qtsa-secours");
    expect(jeton.attempts[1].outcome).to.equal("en_cours");
    const tardif = actionsDe(r.actions, { action: "journaliser" }).find((a) => a.detail.event === "anchor_response_rejected" && a.detail.error_code === "demande_close");
    expect(tardif.detail.kept).to.equal(true);
    expect(r.actions.filter((a) => a.action === "stocker" && a.request_id === id)).to.have.lengthOf(2);
  });

  it("EX-8.8 : deux échecs permanents (principal puis secours) refusent le jeton_point (prestataires_epuises majeure) et rendent ses échéances", function () {
    const c = configReference();
    c.rfc3161.checkpoints.provider_role = "principal";
    const id = `jeton_point:${K1.checkpoint_hash}`;
    const r = scenario(c, [
      e("2026-11-03T13:40:00.000Z", "demarrage"),
      e("2026-11-03T13:42:00.000Z", "point_produit", K1),
      e("2026-11-03T13:42:03.000Z", "inclusion_registre", INCLUSION(`ancre_registre_point:${K1.checkpoint_hash}`, 20001)),
      e("2026-11-03T13:42:04.000Z", "reponse_rfc3161", ERREUR(id, 1, { http_status: 401 })),
      e("2026-11-03T13:42:05.000Z", "reponse_rfc3161", ERREUR(id, 2, { pki_status: 2, failure_info: "badAlg" })),
      e("2026-11-03T13:53:00.000Z", "point_produit", K2),
    ]);
    const rejets = actionsDe(r.actions, { action: "rejeter_reponse" }).map((a) => [a.detail.error_code, a.detail.class]);
    expect(rejets).to.deep.equal([["http_401", "permanente"], ["echec_badAlg", "permanente"]]);
    expect(r.file.find((d) => d.id === id).state).to.equal("refusee");
    expect(actionsDe(r.actions, { action: "alerter" }).some((a) => a.detail.code === "prestataires_epuises" && a.detail.severity === "majeure")).to.equal(true);
    expect(r.file.find((d) => d.id === `jeton_point:${K2.checkpoint_hash}`).deadlines).to.deep.equal([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  });

  it("EX-5.12 : statuts PKI 3 et timeNotAvailable transitoires, 4 et 5 permanents avec alerte revoque, nonce et empreinte différents, T-6 en échec, 429 avec Retry-After, 404, 408 répété", function () {
    const c = configReference();
    const id = `jeton_point:${K1.checkpoint_hash}`;
    const ancre = `ancre_registre_point:${K1.checkpoint_hash}`;
    const nonce = (k) => nonceHex(nonceVecteur({ journal: "journal-principal", sujet: "point", empreinte: K1.checkpoint_hash, n: k }));
    const r = scenario(c, [
      e("2026-11-03T13:40:00.000Z", "demarrage"),
      e("2026-11-03T13:42:00.000Z", "point_produit", K1),
      e("2026-11-03T13:42:03.000Z", "inclusion_registre", INCLUSION(ancre, 20001)),
      e("2026-11-03T13:42:04.000Z", "reponse_rfc3161", ERREUR(id, 1, { pki_status: 3 })),
      e("2026-11-03T13:42:10.000Z", "reponse_rfc3161", ERREUR(id, 2, { pki_status: 2, failure_info: "timeNotAvailable" })),
      e("2026-11-03T13:42:21.000Z", "reponse_rfc3161", ERREUR(id, 3, { http_status: 429, retry_after_s: 7 })),
      e("2026-11-03T13:42:29.000Z", "reponse_rfc3161", ERREUR(id, 4, { http_status: 408 })),
      e("2026-11-03T13:42:30.000Z", "reponse_rfc3161", ERREUR(id, 5, { http_status: 408 })),
      e("2026-11-03T13:43:51.000Z", "reponse_rfc3161", { ...GRANTED(id, 6, nonce(6), "2026-11-03T13:43:50Z", "k1"), checks_passed: ["T-1", "T-2", "T-3", "T-4", "T-5", "T-7", "T-8", "T-9"] }),
    ]);
    const rejets = actionsDe(r.actions, { action: "rejeter_reponse" }).map((a) => [a.detail.error_code, a.detail.class]);
    expect(rejets).to.deep.equal([["statut_3", "transitoire"], ["echec_timeNotAvailable", "transitoire"], ["http_429", "transitoire"], ["http_408", "transitoire"], ["http_408", "transitoire"], ["verification_T-6", "permanente"]]);
    const prog = actionsDe(r.actions, { action: "programmer", request: "jeton_point" }).map((a) => [a.detail.reason, a.detail.next_at]);
    expect(prog.slice(1)).to.deep.equal([["backoff", "2026-11-03T13:42:09.000Z"], ["backoff", "2026-11-03T13:42:20.000Z"], ["retry_after", "2026-11-03T13:42:28.000Z"], ["immediat", "2026-11-03T13:42:29.000Z"], ["backoff", "2026-11-03T13:43:50.000Z"]]);
    expect(r.file.find((d) => d.id === id).state).to.equal("refusee");
    expect(r.actions.filter((a) => a.action === "stocker" && a.request_id === id)).to.have.lengthOf(1);

    const r2 = scenario(c, [
      e("2026-11-03T13:40:00.000Z", "demarrage"),
      e("2026-11-03T13:42:00.000Z", "point_produit", K1),
      e("2026-11-03T13:42:03.000Z", "inclusion_registre", INCLUSION(ancre, 20001)),
      e("2026-11-03T13:42:04.000Z", "reponse_rfc3161", ERREUR(id, 1, { pki_status: 5 })),
    ]);
    expect(actionsDe(r2.actions, { action: "alerter" }).map((a) => a.detail.code)).to.include("revoque");
    expect(actionsDe(r2.actions, { action: "rejeter_reponse" })[0].detail).to.deep.equal({ error_code: "statut_5", class: "permanente" });
    // Un statut PKI hors de l'énumération du schéma n'entre pas dans le planificateur (EX-8.16, entrées conformes seulement).
    expect(() => scenario(c, [e("2026-11-03T13:40:00.000Z", "demarrage"), e("2026-11-03T13:42:00.000Z", "point_produit", K1), e("2026-11-03T13:42:03.000Z", "inclusion_registre", INCLUSION(ancre, 20001)), e("2026-11-03T13:42:04.000Z", "reponse_rfc3161", ERREUR(id, 1, { pki_status: 7 }))])).to.throw(ErreurPlanificateur, /pki_status/);
    for (const [champs, code] of [
      [{ nonce_in_response: "0x" + "00".repeat(7) + "01" }, "nonce_different"],
      [{ nonce_in_response: null }, "nonce_absent"],
      [{ imprint_matches: false }, "empreinte_differente"],
      [{ policy_check: "politique_differente" }, "politique_differente"],
      [{ pki_status: 2, failure_info: null }, "statut_2"],
      [{ pki_status: 2, failure_info: "autre" }, "statut_2"],
      [{ http_status: 404 }, "http_404"],
      [{ http_status: 500, retry_after_s: null }, "http_500"],
    ]) {
      const r3 = scenario(c, [
        e("2026-11-03T13:40:00.000Z", "demarrage"),
        e("2026-11-03T13:42:00.000Z", "point_produit", K1),
        e("2026-11-03T13:42:03.000Z", "inclusion_registre", INCLUSION(ancre, 20001)),
        e("2026-11-03T13:42:04.000Z", "reponse_rfc3161", { ...GRANTED(id, 1, nonce(1), "2026-11-03T13:42:04Z", "k1"), ...champs }),
      ]);
      expect(actionsDe(r3.actions, { action: "rejeter_reponse" })[0].detail.error_code, code).to.equal(code);
    }
  });

  it("EX-8.11 : trop peu de calendriers → a_reprendre avec le même engagement ; au-delà de give_up_after_s l'alerte ots_give_up et la cadence quotidienne", function () {
    const c = configReference();
    c.opentimestamps.upgrade = { first_after_s: 60, interval_s: 60, give_up_after_s: 3600 };
    const id = `ots_periode:${CLOTURE.period_hash}`;
    const entrees = [
      e("2026-11-03T13:59:00.000Z", "demarrage"),
      e("2026-11-03T14:00:00.250Z", "periode_close", CLOTURE),
      e("2026-11-03T14:00:01.000Z", "reponse_ots", { request_id: id, calendars_answered: 1, attestation: "aucune", proof_sha256: null, proof_size: null }),
      e("2026-11-03T14:00:07.000Z", "reponse_ots", { request_id: id, calendars_answered: 2, attestation: "en_attente", proof_sha256: SHA("preuve p1"), proof_size: 233 }),
    ];
    let t = N.decoderHorodatage("2026-11-03T14:01:07.000Z");
    for (let i = 0; i < 61; i++) {
      entrees.push(e(N.ecrireHorodatage(t), "reponse_ots", { request_id: id, calendars_answered: 1, attestation: "en_attente", proof_sha256: null, proof_size: null }));
      t += 60000;
    }
    entrees.push(e(N.ecrireHorodatage(t + 86400000), "reponse_ots", { request_id: id, calendars_answered: 1, attestation: "complete", proof_sha256: SHA("preuve complete"), proof_size: 316 }));
    const r = scenario(c, entrees);
    const soumissions = actionsDe(r.actions, { action: "soumettre_ots" });
    expect(soumissions).to.have.lengthOf(2);
    expect(soumissions[0].detail.nonce).to.equal(soumissions[1].detail.nonce);
    expect(soumissions[1].t).to.equal("2026-11-03T14:00:06.000Z");
    const alertes = actionsDe(r.actions, { action: "alerter" }).filter((a) => a.detail.code === "ots_give_up");
    expect(alertes).to.have.lengthOf(1);
    expect(alertes[0].detail.severity).to.equal("majeure");
    const programmes = actionsDe(r.actions, { action: "programmer", request: "ots_periode" }).filter((a) => a.detail.reason === "mise_a_niveau");
    const dernier = programmes[programmes.length - 1];
    expect(N.decoderHorodatage(dernier.detail.next_at) - N.decoderHorodatage(dernier.t)).to.equal(86400000);
    expect(r.file.find((d) => d.id === id).state).to.equal("complete");
    expect(actionsDe(r.actions, { action: "mettre_a_niveau_ots" }).length).to.be.greaterThan(60);
  });

  it("EX-9.4, EX-8.10 : une ancre à reprendre dont la reprise tombe pendant l'envoi d'une autre ancre de la même clé part au reçu de celle-ci (elle n'attend pas indéfiniment)", function () {
    const c = configReference();
    c.registry.checkpoints = "tous";
    const periode = `ancre_registre_periode:${CLOTURE.period_hash}`;
    // Premier point de l'heure suivante, produit pendant la reprise de l'ancre de la période.
    const K5 = { org_id: ORG, journal_id: JOURNAL, period_start: PERIODE + 3600, tree_size: 1, checkpoint_hash: "0x" + "5a".repeat(32), checkpoint_ts: "2026-11-03T14:00:02.000Z" };
    const point = `ancre_registre_point:${K5.checkpoint_hash}`;
    const r = scenario(c, [
      e("2026-11-03T13:40:00.000Z", "demarrage"),
      e("2026-11-03T14:00:00.250Z", "periode_close", CLOTURE),
      e("2026-11-03T14:00:01.000Z", "echec_registre", { request_id: periode, code: "noeud_injoignable" }),
      e("2026-11-03T14:00:02.000Z", "point_produit", K5),
      // Reprise de l'ancre de la période due à 14:00:06 : l'ancre du point est en vol, elle attend son reçu (attente_nonce).
      e("2026-11-03T14:00:07.000Z", "tic"),
      e("2026-11-03T14:00:08.000Z", "inclusion_registre", INCLUSION(point, 20002)),
      e("2026-11-03T14:00:09.000Z", "tic"),
    ]);
    expect(actionsDe(r.actions, { action: "envoyer_registre" }).map((a) => [a.t, a.request_id])).to.deep.equal([
      ["2026-11-03T14:00:00.250Z", periode],
      ["2026-11-03T14:00:02.000Z", point],
      ["2026-11-03T14:00:08.000Z", periode],
    ]);
    expect(actionsDe(r.actions, { action: "programmer", request: periode }).some((a) => a.t === "2026-11-03T14:00:06.000Z" && a.detail.reason === "attente_nonce")).to.equal(true);
    expect(r.file.find((d) => d.id === periode).state).to.equal("envoyee");
  });

  it("EX-8.10 : un échec transitoire du registre reprogramme l'ancre ; un refus définitif refuse l'ancre d'un point mais jamais celle d'une période", function () {
    const c = configReference();
    const ancre = `ancre_registre_point:${K1.checkpoint_hash}`;
    const r = scenario(c, [
      e("2026-11-03T13:40:00.000Z", "demarrage"),
      e("2026-11-03T13:42:00.000Z", "point_produit", K1),
      e("2026-11-03T13:42:01.000Z", "echec_registre", { request_id: ancre, code: "noeud_injoignable" }),
      e("2026-11-03T13:42:10.000Z", "tic"),
      e("2026-11-03T13:42:11.000Z", "echec_registre", { request_id: ancre, code: "refus_emetteur_inconnu" }),
      e("2026-11-03T14:00:00.250Z", "periode_close", CLOTURE),
      e("2026-11-03T14:00:01.000Z", "echec_registre", { request_id: `ancre_registre_periode:${CLOTURE.period_hash}`, code: "refus_fonds_insuffisants" }),
    ]);
    const a = r.file.find((d) => d.id === ancre);
    expect(a.state).to.equal("refusee");
    expect(a.attempts.map((x) => [x.outcome, x.error_code])).to.deep.equal([["echec_transitoire", "noeud_injoignable"], ["echec_permanente", "refus_emetteur_inconnu"]]);
    expect(actionsDe(r.actions, { action: "envoyer_registre", request: ancre })).to.have.lengthOf(2);
    expect(actionsDe(r.actions, { action: "envoyer_rfc3161", request: "jeton_point" })[0].t).to.equal("2026-11-03T13:42:05.000Z");
    const periode = r.file.find((d) => d.kind === "ancre_registre_periode");
    expect(periode.state).to.equal("a_reprendre");
    expect(periode.due_at).to.equal("2026-11-03T14:05:01.000Z");
  });

  it("EX-8.5 règle 4 : à max_pending, un nouveau point n'est pas ancré mais la clôture crée ses trois demandes ; TAILLE_CAPTURE_REPRESENTEE peut être remplacée par capture_size", function () {
    const c = configReference();
    c.queue.max_pending = 100;
    const t = trace("file-pleine");
    const r = scenario(c, [e("2026-11-03T13:40:00.000Z", "demarrage"), e("2026-11-03T13:42:00.000Z", "point_produit", K1), e("2026-11-03T14:00:00.250Z", "periode_close", CLOTURE)], { fileInitiale: t.queue_before });
    expect(actionsDe(r.actions, { action: "journaliser" }).filter((a) => a.detail.event === "anchor_queue_full")).to.have.lengthOf(1);
    expect(r.file).to.have.lengthOf(103);
    const r2 = scenario(c, [
      e("2026-11-03T13:40:00.000Z", "demarrage"),
      e("2026-11-03T13:42:00.000Z", "point_produit", K1),
      e("2026-11-03T13:42:03.000Z", "inclusion_registre", { ...INCLUSION(`ancre_registre_point:${K1.checkpoint_hash}`, 20001), capture_size: 123761 }),
    ]);
    expect(actionsDe(r2.actions, { action: "stocker" })[0].detail.size).to.equal(123761);
    expect(TAILLE_CAPTURE_REPRESENTEE).to.equal(4096);
  });

  it("docType de la période et du point sont ceux de constantes.json (CT-4 §6.4, CT-1 annexe B)", function () {
    const constantes = lire("ct-5", "constantes.json");
    expect(DOC_TYPE_PERIODE_PLANIFICATEUR).to.equal(constantes.doc_types.period);
    expect(N.DOC_TYPE_POINT).to.equal(constantes.doc_types.checkpoint);
  });

  it("tic() lit l'horloge injectée ; echeances(periodStart) rend l'état des échéances ; file() rend des copies", function () {
    const c = configReference();
    let t = N.decoderHorodatage("2026-11-03T13:40:00.000Z");
    const p = creerPlanificateur(c, { nonces: noncesVecteurs(), maintenant: () => t });
    p.traiter(e("2026-11-03T13:40:00.000Z", "demarrage"));
    p.traiter(e("2026-11-03T13:42:00.000Z", "point_produit", K1));
    p.traiter(e("2026-11-03T13:42:03.000Z", "inclusion_registre", INCLUSION(`ancre_registre_point:${K1.checkpoint_hash}`, 20001)));
    t = N.decoderHorodatage("2026-11-03T13:45:00.000Z");
    const actions = p.tic();
    expect(actions).to.deep.equal([{ t: "2026-11-03T13:44:00.000Z", action: "journaliser", request_id: null, detail: { event: "point_manquant", last_checkpoint_ts: K1.checkpoint_ts, gap_s: 120 } }, { t: "2026-11-03T13:44:00.000Z", action: "alerter", request_id: null, detail: { code: "point_manquant", severity: "majeure" } }, { t: "2026-11-03T13:45:00.000Z", action: "echeance", request_id: null, detail: { k: 9, state: "ouverte" } }]);
    const ech = p.echeances(PERIODE, ORG, JOURNAL);
    expect(ech.map((x) => x.state)).to.deep.equal([...Array(8).fill("ouverte"), "ouverte", "a_venir", "a_venir"]);
    expect(ech[0].request_id).to.equal(`jeton_point:${K1.checkpoint_hash}`);
    const f = p.file();
    f[0].state = "x";
    expect(p.file()[0].state).to.not.equal("x");
    expect(() => creerPlanificateur(c, { nonces: noncesVecteurs() }).tic()).to.throw(ErreurPlanificateur);
  });
});

describe("ancrage, planificateur : point_manquant depuis le checkpoint_ts déclaré (EX-4.1, 8.9, révision 0.4) et alertes du jeton d'un point (AN-2)", function () {
  const CLOTURE_POINT = { ...K2, tree_size: 5, checkpoint_hash: SHA("point de cloture"), checkpoint_ts: "2026-11-03T14:00:00.250Z" };
  const manquants = (actions) => actions.filter((a) => a.action === "journaliser" && a.detail.event === "point_manquant").map((a) => [a.t, a.detail.last_checkpoint_ts, a.detail.gap_s]);
  const alertes = (actions, code) => actions.filter((a) => a.action === "alerter" && a.detail.code === code);

  it("un point relu longtemps après sa production (saut d'horloge) lève l'alerte due à checkpoint_ts + 2 × c_K dès la reprise, datée de l'instant où elle était due ; le point de clôture n'arme aucune minuterie", function () {
    const c = configReference();
    const r = scenario(c, [
      e("2026-11-03T13:40:00.000Z", "demarrage"),
      e("2026-11-03T13:42:00.000Z", "point_produit", K1),
      e("2026-11-03T13:43:00.000Z", "tic"),
      e("2026-11-03T15:30:00.000Z", "point_produit", K2), // produit à 13:53, admis à 15:30
      e("2026-11-03T15:30:01.000Z", "tic"),
      e("2026-11-03T15:30:10.000Z", "point_produit", CLOTURE_POINT), // checkpoint_ts ≥ period_end : aucune minuterie
      e("2026-11-03T15:40:00.000Z", "tic"),
      e("2026-11-03T15:40:00.000Z", "periode_close", CLOTURE),
      e("2026-11-03T15:50:00.000Z", "tic"),
    ]);
    // Deux alertes seulement : celle due à 13:44 (K1 + 2 × c_K), celle due à 13:55 (K2 + 2 × c_K) ; aucune pour le point de clôture (14:02) ni après.
    expect(manquants(r.actions)).to.deep.equal([["2026-11-03T13:44:00.000Z", K1.checkpoint_ts, 120], ["2026-11-03T13:55:00.000Z", K2.checkpoint_ts, 120]]);
    expect(alertes(r.actions, "point_manquant").map((a) => a.t)).to.deep.equal(["2026-11-03T13:44:00.000Z", "2026-11-03T13:55:00.000Z"]);
    // Ordre : l'alerte due à 13:44 précède l'admission de K2 (15:30) ; celle due à 13:55 suit l'admission de K2 et précède le tic de 15:30:01.
    const t = r.actions.map((a) => (a.action === "journaliser" && a.detail.event === "point_manquant" ? `manquant@${a.t}` : a.action === "ecrire_file" && a.request_id === `jeton_point:${K2.checkpoint_hash}` ? "k2" : null)).filter(Boolean);
    expect(t.indexOf("manquant@2026-11-03T13:44:00.000Z")).to.be.below(t.indexOf("k2"));
    expect(t.indexOf("manquant@2026-11-03T13:55:00.000Z")).to.be.above(t.indexOf("k2"));
    // Même point relu par la reconstruction (file perdue) : le délai court depuis checkpoint_ts, non depuis le démarrage.
    const relu = scenario(c, [
      e("2026-11-03T13:56:00.000Z", "demarrage"),
      e("2026-11-03T13:56:00.000Z", "stockage_relu", { periods: [], checkpoints: [K2] }),
      e("2026-11-03T13:56:02.000Z", "tic"),
      e("2026-11-03T13:58:30.000Z", "tic"),
    ]);
    expect(manquants(relu.actions)).to.deep.equal([["2026-11-03T13:55:00.000Z", K2.checkpoint_ts, 120]]);
    // Échec de la règle ancienne : aucune alerte à 13:58 (démarrage + 2 × c_K).
    expect(alertes(relu.actions, "point_manquant").map((a) => a.t)).to.deep.equal(["2026-11-03T13:55:00.000Z"]);
  });

  it("aucune alerte tant que les points se suivent à c_K ; aucune pour une période close ; une seule par silence (réarmée au point suivant)", function () {
    const c = configReference();
    const K1b = { ...K1, tree_size: 3, checkpoint_hash: SHA("k1b"), checkpoint_ts: "2026-11-03T13:43:00.000Z" };
    const suivis = scenario(c, [
      e("2026-11-03T13:40:00.000Z", "demarrage"),
      e("2026-11-03T13:42:00.000Z", "point_produit", K1),
      e("2026-11-03T13:43:00.000Z", "point_produit", K1b),
      e("2026-11-03T13:44:30.000Z", "tic"),
    ]);
    expect(manquants(suivis.actions)).to.deep.equal([]);
    const silence = scenario(c, [
      e("2026-11-03T13:40:00.000Z", "demarrage"),
      e("2026-11-03T13:42:00.000Z", "point_produit", K1),
      e("2026-11-03T13:50:00.000Z", "tic"),
      e("2026-11-03T13:53:00.000Z", "point_produit", K2),
      e("2026-11-03T13:56:00.000Z", "tic"),
      e("2026-11-03T14:00:00.250Z", "point_produit", CLOTURE_POINT),
      e("2026-11-03T14:00:00.250Z", "periode_close", CLOTURE),
      e("2026-11-03T14:30:00.000Z", "tic"),
    ]);
    expect(manquants(silence.actions)).to.deep.equal([["2026-11-03T13:44:00.000Z", K1.checkpoint_ts, 120], ["2026-11-03T13:55:00.000Z", K2.checkpoint_ts, 120]]);
  });

  it("jeton d'un point : contresignature_tardive (mineure) quand genTime + précision − checkpoint_ts > c_T ; jeton_anterieur_au_point (majeure) quand genTime + précision < checkpoint_ts − clock_tolerance_s ; rien sinon", function () {
    const c = configReference();
    c.rfc3161.freshness.clock_tolerance_s = 600; // la tolérance d'horloge ne masque pas la règle sur c_T (300 s)
    const id = `jeton_point:${K1.checkpoint_hash}`;
    const jouer = (genTime) => {
      const p = creerPlanificateur(c, { gigues: [], nonces: noncesVecteurs(), fileInitiale: [] });
      const actions = [];
      for (const i of [
        e("2026-11-03T13:40:00.000Z", "demarrage"),
        e("2026-11-03T13:42:00.000Z", "point_produit", K1),
        e("2026-11-03T13:42:03.000Z", "inclusion_registre", INCLUSION(`ancre_registre_point:${K1.checkpoint_hash}`, 20001)),
      ]) actions.push(...p.traiter(i));
      const envoi = actionsDe(actions, { action: "envoyer_rfc3161", request: id })[0];
      actions.push(...p.traiter(e("2026-11-03T13:42:05.000Z", "reponse_rfc3161", GRANTED(id, 1, envoi.detail.nonce, genTime, "k1"))));
      return { actions, file: p.file() };
    };
    // 13:48:00 + 1 s − 13:42:00 = 361 s > c_T = 300 s : tardive ; l'alerte suit la ligne checkpoint_countersigned.
    const tardif = jouer("2026-11-03T13:48:00Z");
    expect(alertes(tardif.actions, "contresignature_tardive")).to.deep.equal([{ t: "2026-11-03T13:42:05.000Z", action: "alerter", request_id: id, detail: { code: "contresignature_tardive", severity: "mineure" } }]);
    expect(alertes(tardif.actions, "jeton_anterieur_au_point")).to.deep.equal([]);
    const i = tardif.actions.findIndex((a) => a.action === "journaliser" && a.detail.event === "checkpoint_countersigned");
    expect(tardif.actions[i + 1].detail.code).to.equal("contresignature_tardive");
    expect(tardif.file.find((d) => d.id === id).state).to.equal("obtenue");
    // 13:46:59 + 1 s − 13:42:00 = 300 s : à la borne, aucune alerte.
    const limite = jouer("2026-11-03T13:46:59Z");
    expect(alertes(limite.actions, "contresignature_tardive")).to.deep.equal([]);
    expect(alertes(limite.actions, "jeton_anterieur_au_point")).to.deep.equal([]);
    // 13:31:50 + 1 s < 13:42:00 − 600 s : jeton antérieur au point (majeure) ; l'horloge suspecte (EX-5.11, écart à l'envoi > 600 s) est signalée en plus.
    const anterieur = jouer("2026-11-03T13:31:50Z");
    expect(alertes(anterieur.actions, "jeton_anterieur_au_point")).to.deep.equal([{ t: "2026-11-03T13:42:05.000Z", action: "alerter", request_id: id, detail: { code: "jeton_anterieur_au_point", severity: "majeure" } }]);
    expect(alertes(anterieur.actions, "horloge_suspecte")).to.have.lengthOf(1);
    expect(alertes(anterieur.actions, "contresignature_tardive")).to.deep.equal([]);
    // 13:32:00 + 1 s = checkpoint_ts − clock_tolerance_s + 1 s : à la borne, aucune alerte d'antériorité.
    const borne = jouer("2026-11-03T13:32:00Z");
    expect(alertes(borne.actions, "jeton_anterieur_au_point")).to.deep.equal([]);
  });
});
