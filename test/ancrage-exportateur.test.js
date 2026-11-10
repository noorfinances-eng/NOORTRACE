// Exportateur du composant d'ancrage (lot F2 ; CT-5 §10.1, EX-10.1 à EX-10.5,
// AN-50 à AN-53 ; CT-1 §11.2 ; CT-6 §5.4, §13.4). Vecteurs rejoués : les
// dossiers de spec/vecteurs/ct-6/dossiers qui portent points-de-controle.json
// (point couvrant d'EX-10.2 retrouvé depuis la série de CT-1 et les ancres que
// chaque vecteur embarque ; partie reconstruite octet pour octet), les
// dossiers de CT-1 qui portent la partie, les parties du registre de
// periode-1-point (EX-10.4, AN-52), le dossier complet reconstruit depuis un
// dépôt d'ancres d'EX-5.14 (AN-50, dossier.json identique au vecteur) et
// vérifié par les deux vérificateurs de CT-6 (K-1 à K-9 ; AN-51), le réexport
// (AN-53) et des entrées hostiles (CT-6 §15.1).

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import v8 from "node:v8";
import vm from "node:vm";
import * as N from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";
import { DepotAncres } from "@noortrace/ancrage/rfc3161";
import { DepotOts } from "@noortrace/ancrage/ots";
import {
  choisirPointCouvrant, construirePartiePointsDeControle, piecesPeriode, piecesObjet, partiesRegistre, exporterDossier, reexportsDus, etatAncresPeriode,
  controlerAncresDossier, depotsJournal, referenceRegistre, jetonPromuDuPoint, RANGS, RAISONS, BORNES_EXPORTATEUR, octetsJsonDossier,
} from "@noortrace/ancrage/exportateur";
import { RACINE, CT1, CT6, lireJson, repertoireTemporaire, enAttente } from "./fixtures/ancrage-composant/outils.mjs";
import { binaireGo } from "./fixtures/enregistreur-ancrage/outils.mjs";

const octets = (p) => new Uint8Array(fs.readFileSync(p));
const DOSSIERS_CT6 = path.join(CT6, "dossiers");
const SERIE_P1 = lireJson(path.join(CT1, "points-de-controle", "periode-1.json"));
const ORG = SERIE_P1[0].org_id;
const JOURNAL = SERIE_P1[0].journal_id;
const PERIODE = SERIE_P1[0].period_start;
const EVENEMENTS = lireJson(path.join(CT1, "journal-valide", "evenements.json"));
const MANIFESTE_P1 = lireJson(path.join(CT1, "manifestes", "periode-1.json"));
const HASHES_P1 = EVENEMENTS.filter((e) => e.seq >= MANIFESTE_P1.first_seq && e.seq <= MANIFESTE_P1.last_seq).map((e) => e.hash);
const CAPTURE = path.join(CT6, "registre", "capture");
const ATTENDU_REGISTRE = lireJson(path.join(CT6, "registre", "attendu.json"));
const CONSTANTES_CT4 = lireJson(path.join(RACINE, "spec", "vecteurs", "ct-4", "constantes.json"));
const JEUX_DEV = { sets: [{ from_height: 1, to_height: null, validators: lireJson(path.join(RACINE, "test", "fixtures", "certificat-commit", "validators.json")).validators, source: "validators.json du réseau de développement, clés publiques seulement" }] };
const SOURCE_REGISTRE = lireJson(path.join(CT6, "registre", "periode-1-point", "registre.json")).source;

const dossiersAvecPartie = (racine) => fs.readdirSync(racine).filter((n) => fs.existsSync(path.join(racine, n, "points-de-controle.json"))).sort();

/** Index de capture du bloc 18928 (ancre du point de 09:32, EX-A.15) reconstruit depuis les fichiers bruts de la capture unique, écrit dans `dir`. */
function capturesPeriode1Point(dir) {
  fs.mkdirSync(dir, { recursive: true });
  for (const n of fs.readdirSync(CAPTURE)) if (/^(bloc|recu|certificat)-/.test(n)) fs.copyFileSync(path.join(CAPTURE, n), path.join(dir, n));
  const dir1 = path.join(RACINE, "spec", "vecteurs", "ct-4", "capture", "periode-1");
  for (const n of fs.readdirSync(dir1)) if (n.startsWith("capture-")) fs.copyFileSync(path.join(dir1, n), path.join(dir, n));
  const sha = (n) => N.sha256Hex(octets(path.join(dir, n)));
  const point = ATTENDU_REGISTRE.checkpoint_anchor.transaction;
  const bloc = lireJson(path.join(CAPTURE, "bloc-18928.json")).result;
  const index = {
    version: 0, role: "ancre", evm_chain_id: 2124, bft_chain_id: "noortrace-2124-dev", contract: CONSTANTES_CT4.contracts.attestation_registry,
    transaction_hash: point.hash, block_number: 18928, block_hash: bloc.hash, transaction_index: 0, log_index: 0,
    files: { block: { name: "bloc-18928.json", sha256: sha("bloc-18928.json") }, receipts: [{ name: `recu-${point.hash}.json`, sha256: sha(`recu-${point.hash}.json`) }], certificate: { name: "certificat-18928.json", sha256: sha("certificat-18928.json") } },
    node: { rpc: "http://127.0.0.1:8645", validator_id: "v1" }, validator_set_hash: ATTENDU_REGISTRE.capture.valset_hash, captured_at: "2026-10-26T01:25:00.000Z", attempts: 1,
    checks: ["CP-1", "CP-2", "CP-3", "CP-4", "CP-5", "CP-6"].map((id) => ({ id, status: "reussi", detail: "" })), sending: null,
  };
  expect(R.verifierIndexCapture(index).valide).to.equal(true);
  fs.writeFileSync(path.join(dir, "capture-18928-0-ancre.json"), R.serialiserIndex(index));
  return index;
}

/** Enregistrement d'acquisition minimal d'EX-5.13 (forme des vecteurs de reprise), promu, pour un jeton écrit dans le dépôt. */
function enregistrementAcquisition({ objet, imprint, providerId, attemptId, fichier, jeton, qualified = null, promoted = true, revoked, t10 = "reussi" }) {
  const nom = objet === "manifeste" ? "manifeste" : `point-${imprint.slice(2)}`;
  const e = {
    version: 0, object: objet, object_name: nom, imprint, period_start: PERIODE, provider_id: providerId, provider_role: providerId === "tsa-interne" ? "interne" : "principal", attempt_id: attemptId, attempt: 1,
    request_id: `${objet === "manifeste" ? "jeton_periode" : "jeton_point"}:${imprint}`, nonce: "0x74a6f4979421411e", sent_at: "2026-11-05T09:32:01.000Z", received_at: "2026-11-05T09:32:02.000Z",
    outcome: "obtenue", error_code: null, http_status: 200, pki_status: 0, failure_info: null, gen_time: "2026-11-05T09:32:02Z", accuracy_s: 1, upper_bound: "2026-11-05T09:32:03.000Z",
    token_sha256: N.sha256Hex(jeton), token_size: jeton.length, checks: { "T-1": "reussi", "T-2": "reussi", "T-3": "reussi", "T-4": "reussi", "T-5": "reussi", "T-6": "reussi", "T-7": "reussi", "T-8": "reussi", "T-9": "reussi", "T-10": t10 },
    qualified, promoted, files: { request: `${fichier}.tsq`, response: `${fichier}.tsr`, token: `${fichier}.der`, crls: [] },
  };
  if (revoked !== undefined) e.revoked = revoked;
  return e;
}

/** Dépôt d'ancres d'EX-5.14 peuplé des pièces du dossier `valide-point-de-controle-complet` : jetons promus, preuves, en-têtes. */
function depotVecteurs(racine, { pointEnAttente = false, sansPoint = false } = {}) {
  const depot = DepotAncres.ouvrir({ racine, orgId: ORG, journalId: JOURNAL });
  const depotOts = DepotOts.ouvrir({ racine, orgId: ORG, journalId: JOURNAL });
  const periodHash = N.hacherManifeste(MANIFESTE_P1);
  const point = SERIE_P1.find((p) => p.checkpoint_ts === "2026-11-05T09:32:00.000Z");
  const hash = N.hacherPoint(point);
  const jetonPeriode = octets(path.join(CT6, "rfc3161", "jetons", "periode-1.der"));
  const jetonPoint = octets(path.join(CT6, "rfc3161", "jetons", "point-periode-1.der"));
  // Une première tentative en échec puis la tentative promue : le fichier est en ajout seul, le dernier état fait foi.
  const baseM = depot.nomPiece({ objet: "manifeste", imprint: periodHash, providerId: "qtsa-principal", attemptId: `jeton_periode:${periodHash.slice(2, 18)}:1` });
  depot.ecrirePiece(PERIODE, "rfc3161", `${baseM}.tsq`, N.utf8("requete"));
  depot.ecrirePiece(PERIODE, "rfc3161", `${baseM}.tsr`, N.utf8("reponse"));
  depot.ecrirePiece(PERIODE, "rfc3161", `${baseM}.der`, jetonPeriode);
  depot.ajouterAcquisition(PERIODE, enregistrementAcquisition({ objet: "manifeste", imprint: periodHash, providerId: "qtsa-principal", attemptId: `jeton_periode:${periodHash.slice(2, 18)}:1`, fichier: `rfc3161/${baseM}`, jeton: jetonPeriode, qualified: { framework: "eidas" } }));
  if (!sansPoint) {
    const baseK = depot.nomPiece({ objet: "point", imprint: hash, providerId: "tsa-interne", attemptId: `jeton_point:${hash.slice(2, 18)}:1` });
    depot.ecrirePiece(PERIODE, "rfc3161", `${baseK}.tsq`, N.utf8("requete"));
    depot.ecrirePiece(PERIODE, "rfc3161", `${baseK}.tsr`, N.utf8("reponse"));
    depot.ecrirePiece(PERIODE, "rfc3161", `${baseK}.der`, jetonPoint);
    depot.ajouterAcquisition(PERIODE, enregistrementAcquisition({ objet: "point", imprint: hash, providerId: "tsa-interne", attemptId: `jeton_point:${hash.slice(2, 18)}:1`, fichier: `rfc3161/${baseK}`, jeton: jetonPoint, t10: "non_execute" }));
    // Ligne de T-10 différée (dernier état de la même tentative).
    depot.ajouterAcquisition(PERIODE, enregistrementAcquisition({ objet: "point", imprint: hash, providerId: "tsa-interne", attemptId: `jeton_point:${hash.slice(2, 18)}:1`, fichier: `rfc3161/${baseK}`, jeton: jetonPoint, revoked: false }));
  }
  depotOts.ecrire({ periodStart: PERIODE, objet: "manifeste", octets: octets(path.join(CT6, "ots", "preuves", "periode-1.ots")) });
  depotOts.ecrire({ periodStart: PERIODE, objet: `point-${hash.slice(2)}`, octets: octets(path.join(CT6, "ots", "preuves", "point-periode-1-en-attente.ots")) });
  if (!pointEnAttente) depotOts.ecrire({ periodStart: PERIODE, objet: `point-${hash.slice(2)}`, octets: octets(path.join(CT6, "ots", "preuves", "point-periode-1.ots")) });
  depotOts.ecrireEntetes({ periodStart: PERIODE, document: lireJson(path.join(CT6, "ots", "entetes", "chaine-points.json")) });
  return { depot, depotOts, point, hash, periodHash };
}

/** Sept parties de CT-1 d'un dossier des vecteurs, telles quelles. */
function partiesBase(dossier) {
  const m = new Map();
  for (const nom of ["evenement.json", "voisins.json", "chemin.json", "manifeste.json", "manifeste.sig", "cles.json", "approbations.json"]) {
    const p = path.join(dossier, nom);
    if (fs.existsSync(p)) m.set(nom, octets(p));
  }
  return m;
}

const verificateurJs = (repertoire, ancres, entetes) => {
  const r = spawnSync(process.execPath, [path.join(RACINE, "scripts", "verify", "dossier.mjs"), repertoire, "--json", ...(ancres ? ["--ancres", ancres] : []), ...(entetes ? ["--entetes-bitcoin", entetes] : [])], { cwd: RACINE, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return { code: r.status, rapport: r.stdout ? JSON.parse(r.stdout) : null };
};
const verificateurGo = (bin, repertoire, ancres, entetes) => {
  const r = spawnSync(bin, [repertoire, "--json", ...(ancres ? ["--ancres", ancres] : []), ...(entetes ? ["--entetes-bitcoin", entetes] : [])], { cwd: RACINE, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return { code: r.status, rapport: r.stdout ? JSON.parse(r.stdout) : null };
};
const statuts = (rapport, prefixe) => Object.fromEntries(rapport.checks.filter((c) => c.id.startsWith(prefixe)).map((c) => [c.id, c.status]));

describe("ancrage, exportateur (lot F2) : choix du point couvrant d'EX-10.2 sur les dossiers des vecteurs (AN-51)", function () {
  it("la série de CT-1 (période 1) est la série de tous les dossiers CT-6 porteurs de la partie : chaque point embarqué en est membre", function () {
    const hashes = new Set(SERIE_P1.map((p) => N.hacherPoint(p)));
    for (const nom of dossiersAvecPartie(DOSSIERS_CT6)) {
      const p = lireJson(path.join(DOSSIERS_CT6, nom, "points-de-controle.json"));
      if (!p || !p.checkpoint) continue; // invalide-k1-partie-inexploitable : littéral null
      if (/^invalide-k[1-6]/.test(nom)) continue; // points altérés à dessein
      expect(hashes.has(N.hacherPoint(p.checkpoint)), nom).to.equal(true);
    }
  });

  it("EX-10.2 : pour chaque dossier CT-6 valide porteur de la partie, le point retrouvé depuis la série et les ancres qu'il embarque est celui du vecteur (jeton promu > preuve complète > ancre capturée > sans ancre ; plus petit tree_size ; premier de la série)", function () {
    let cas = 0;
    for (const nom of dossiersAvecPartie(DOSSIERS_CT6)) {
      if (!nom.startsWith("valide-")) continue;
      const dossier = path.join(DOSSIERS_CT6, nom);
      const partie = lireJson(path.join(dossier, "points-de-controle.json"));
      const leafIndex = lireJson(path.join(dossier, "chemin.json")).leaf_index;
      const attendu = N.hacherPoint(partie.checkpoint);
      const a = partie.anchors;
      const r = choisirPointCouvrant({
        serie: SERIE_P1,
        leafIndex,
        acquisitions: (h) => (h === attendu && a.rfc3161 ? { outcome: "obtenue", promoted: true } : null),
        preuves: (h) => (h === attendu && a.ots ? N.decoderBase64Canonique(a.ots.proof) : null),
        captures: (h) => (h === attendu && a.registry ? a.registry : null),
      });
      expect(r, nom).to.not.equal(null);
      expect(r.checkpointHash, nom).to.equal(attendu);
      expect(r.point.tree_size, nom).to.be.greaterThan(leafIndex);
      const rangAttendu = a.rfc3161 ? RANGS.jeton : a.ots && N.decoderBase64Canonique(a.ots.proof) && !nom.includes("en-attente") ? RANGS.preuve : a.registry ? RANGS.registre : RANGS.aucune;
      expect(r.rang, nom).to.equal(rangAttendu);
      cas += 1;
    }
    expect(cas).to.be.at.least(9);
  });

  it("EX-10.2, exemple normatif : seq 7 (leaf_index 6) avec un jeton sur le point de 09:35 et une ancre au registre sur celui de 09:32 → 09:35 (valide-point-de-controle-point-contresigne) ; jeton sur le point de clôture → 10:00:00.300 (point-de-cloture) ; sans ancre → 09:32, plus petit tree_size puis premier", function () {
    const h = (ts) => N.hacherPoint(SERIE_P1.find((p) => p.checkpoint_ts === ts));
    const contresigne = choisirPointCouvrant({ serie: SERIE_P1, leafIndex: 6, acquisitions: (x) => (x === h("2026-11-05T09:35:00.000Z") ? { promoted: true } : null), captures: [h("2026-11-05T09:32:00.000Z")] });
    expect(contresigne.point.checkpoint_ts).to.equal("2026-11-05T09:35:00.000Z");
    expect(contresigne.rang).to.equal(RANGS.jeton);
    expect(N.hacherPoint(lireJson(path.join(DOSSIERS_CT6, "valide-point-de-controle-point-contresigne", "points-de-controle.json")).checkpoint)).to.equal(contresigne.checkpointHash);
    const cloture = choisirPointCouvrant({ serie: SERIE_P1, leafIndex: 6, acquisitions: (x) => (x === h("2026-11-05T10:00:00.300Z") ? { promoted: true } : null) });
    expect(cloture.point.tree_size).to.equal(9);
    expect(N.hacherPoint(lireJson(path.join(DOSSIERS_CT6, "valide-point-de-controle-point-de-cloture", "points-de-controle.json")).checkpoint)).to.equal(cloture.checkpointHash);
    const sans = choisirPointCouvrant({ serie: SERIE_P1, leafIndex: 6 });
    expect(sans.point.checkpoint_ts).to.equal("2026-11-05T09:32:00.000Z");
    expect(sans.rang).to.equal(RANGS.aucune);
    // Une preuve complète bat une ancre au registre ; une preuve en attente ne compte pas.
    const complete = octets(path.join(CT6, "ots", "preuves", "point-periode-1.ots"));
    const enAttente_ = octets(path.join(CT6, "ots", "preuves", "point-periode-1-en-attente.ots"));
    expect(choisirPointCouvrant({ serie: SERIE_P1, leafIndex: 6, preuves: (x) => (x === h("2026-11-05T09:35:00.000Z") ? complete : null), captures: [h("2026-11-05T09:32:00.000Z")] }).point.checkpoint_ts).to.equal("2026-11-05T09:35:00.000Z");
    expect(choisirPointCouvrant({ serie: SERIE_P1, leafIndex: 6, preuves: (x) => (x === h("2026-11-05T09:35:00.000Z") ? enAttente_ : null), captures: [h("2026-11-05T09:32:00.000Z")] }).point.checkpoint_ts).to.equal("2026-11-05T09:32:00.000Z");
    // À défaut de tout point après i : null (partie absente, « aucun point de contrôle »).
    expect(choisirPointCouvrant({ serie: SERIE_P1, leafIndex: 9 })).to.equal(null);
    expect(choisirPointCouvrant({ serie: [], leafIndex: 0 })).to.equal(null);
    // Une ligne d'acquisition révoquée ou non promue ne donne pas le rang 1.
    const acq = (extra) => [{ object: "point", object_name: `point-${h("2026-11-05T09:35:00.000Z").slice(2)}`, imprint: h("2026-11-05T09:35:00.000Z"), outcome: "obtenue", promoted: true, attempt_id: "a", files: { token: "x.der" }, ...extra }];
    expect(choisirPointCouvrant({ serie: SERIE_P1, leafIndex: 6, acquisitions: acq({}) }).point.checkpoint_ts).to.equal("2026-11-05T09:35:00.000Z");
    expect(choisirPointCouvrant({ serie: SERIE_P1, leafIndex: 6, acquisitions: acq({ revoked: true }) }).point.checkpoint_ts).to.equal("2026-11-05T09:32:00.000Z");
    expect(choisirPointCouvrant({ serie: SERIE_P1, leafIndex: 6, acquisitions: acq({ promoted: false }) }).point.checkpoint_ts).to.equal("2026-11-05T09:32:00.000Z");
  });

  it("dossiers CT-1 porteurs de la partie : le point embarqué couvre l'événement ; sans ancre, le choix donne le plus petit tree_size (valide-seq-7-point-de-controle) ; le point de clôture n'est choisi que s'il porte une ancre (valide-seq-7-point-de-cloture)", function () {
    for (const nom of dossiersAvecPartie(path.join(CT1, "dossiers"))) {
      if (!nom.startsWith("valide-")) continue;
      const dossier = path.join(CT1, "dossiers", nom);
      const partie = lireJson(path.join(dossier, "points-de-controle.json"));
      const leafIndex = lireJson(path.join(dossier, "chemin.json")).leaf_index;
      expect(partie.checkpoint.tree_size, nom).to.be.greaterThan(leafIndex);
      const sans = choisirPointCouvrant({ serie: SERIE_P1, leafIndex });
      if (nom === "valide-seq-7-point-de-cloture") {
        expect(sans.checkpointHash).to.not.equal(N.hacherPoint(partie.checkpoint));
        expect(choisirPointCouvrant({ serie: SERIE_P1, leafIndex, captures: [N.hacherPoint(partie.checkpoint)] }).checkpointHash).to.equal(N.hacherPoint(partie.checkpoint));
      } else expect(sans.checkpointHash, nom).to.equal(N.hacherPoint(partie.checkpoint));
    }
  });

  it("entrées hostiles : série sans tableau, point sans tree_size, checkpoint_ts inexistant, leafIndex négatif ou non entier, source d'ancres d'un type inconnu", function () {
    expect(() => choisirPointCouvrant({ serie: null, leafIndex: 0 })).to.throw(TypeError);
    expect(() => choisirPointCouvrant({ serie: [{ ...SERIE_P1[0], tree_size: "8" }], leafIndex: 0 })).to.throw(TypeError, /tree_size/);
    expect(() => choisirPointCouvrant({ serie: [{ ...SERIE_P1[0], checkpoint_ts: "2026-02-30T00:00:00.000Z" }], leafIndex: 0 })).to.throw(TypeError, /checkpoint_ts/);
    expect(() => choisirPointCouvrant({ serie: SERIE_P1, leafIndex: -1 })).to.throw(TypeError, /leafIndex/);
    expect(() => choisirPointCouvrant({ serie: SERIE_P1, leafIndex: 1.5 })).to.throw(TypeError, /leafIndex/);
    expect(() => choisirPointCouvrant({ serie: SERIE_P1, leafIndex: 0, acquisitions: 42 })).to.throw(TypeError, /source d'ancres/);
  });
});

describe("ancrage, exportateur : partie points-de-controle.json d'EX-10.3 (AN-50, AN-52)", function () {
  const point0932 = SERIE_P1.find((p) => p.checkpoint_ts === "2026-11-05T09:32:00.000Z");
  const jetonPoint = octets(path.join(CT6, "rfc3161", "jetons", "point-periode-1.der"));
  const preuvePoint = octets(path.join(CT6, "ots", "preuves", "point-periode-1.ots"));
  let dirCaptures;
  let indexPoint;
  before(function () {
    dirCaptures = repertoireTemporaire("noortrace-ancrage-f2-captures-");
    indexPoint = capturesPeriode1Point(dirCaptures);
  });
  after(function () {
    if (dirCaptures) fs.rmSync(dirCaptures, { recursive: true, force: true });
  });

  it("valide-point-de-controle-complet : point de 09:32, checkpoint_hash recalculé, preuve de cohérence 8 → 9, jeton et preuve en base64 canonique, référence registry depuis l'index de capture du bloc 18928 : octets identiques au vecteur", function () {
    const attendu = octets(path.join(DOSSIERS_CT6, "valide-point-de-controle-complet", "points-de-controle.json"));
    const r = construirePartiePointsDeControle({ point: point0932, hashes: HASHES_P1, jeton: jetonPoint, preuve: preuvePoint, capture: indexPoint });
    expect(Buffer.compare(Buffer.from(r.octets), attendu)).to.equal(0);
    expect(r.partie.consistency).to.include({ first_size: 8, second_size: 9 });
    expect(r.partie.anchors.registry).to.deep.equal(lireJson(path.join(DOSSIERS_CT6, "valide-point-de-controle-complet", "points-de-controle.json")).anchors.registry);
    // AN-50 : les ancres embarquées se décodent (base64 canonique) en les octets exacts des pièces.
    expect(Buffer.compare(Buffer.from(N.decoderBase64Canonique(r.partie.anchors.rfc3161.token)), jetonPoint)).to.equal(0);
    expect(Buffer.compare(Buffer.from(N.decoderBase64Canonique(r.partie.anchors.ots.proof)), preuvePoint)).to.equal(0);
  });

  it("valide-point-de-controle-jeton-seul, sans-ancre, ots-en-attente, point-contresigne, point-de-cloture : parties reconstruites octet pour octet depuis les pièces que chaque vecteur embarque", function () {
    for (const nom of ["valide-point-de-controle-jeton-seul", "valide-point-de-controle-sans-ancre", "valide-point-de-controle-ots-en-attente", "valide-point-de-controle-point-contresigne", "valide-point-de-controle-point-de-cloture", "valide-point-de-controle-reference-declarative"]) {
      const attendu = octets(path.join(DOSSIERS_CT6, nom, "points-de-controle.json"));
      const partie = JSON.parse(Buffer.from(attendu).toString("utf8"));
      const point = SERIE_P1.find((p) => N.hacherPoint(p) === N.hacherPoint(partie.checkpoint));
      const r = construirePartiePointsDeControle({
        point, hashes: HASHES_P1,
        jeton: partie.anchors.rfc3161 ? N.decoderBase64Canonique(partie.anchors.rfc3161.token) : null,
        preuve: partie.anchors.ots ? N.decoderBase64Canonique(partie.anchors.ots.proof) : null,
        capture: partie.anchors.registry ? indexPoint : null,
      });
      expect(Buffer.compare(Buffer.from(r.octets), attendu), nom).to.equal(0);
    }
  });

  it("referenceRegistre : champs de l'index de capture, fingerprint recalculée, doc_type du point (AN-52) ; index mal formé refusé", function () {
    const ref = referenceRegistre({ index: indexPoint, orgId: ORG, journalId: JOURNAL, checkpointHash: N.hacherPoint(point0932) });
    expect(ref).to.deep.equal({ chain_id: 2124, contract: CONSTANTES_CT4.contracts.attestation_registry, fingerprint: N.empreinteAncre(ORG, JOURNAL, N.hacherPoint(point0932)), doc_type: R.DOC_TYPE_POINT_DE_CONTROLE, block_number: 18928, block_hash: indexPoint.block_hash, transaction_hash: indexPoint.transaction_hash, log_index: 0 });
    expect(() => referenceRegistre({ index: { ...indexPoint, block_number: "0x49f0" }, orgId: ORG, journalId: JOURNAL, checkpointHash: N.hacherPoint(point0932) })).to.throw(TypeError, /block_number/);
    expect(() => referenceRegistre({ index: { ...indexPoint, contract: "0xZZ" }, orgId: ORG, journalId: JOURNAL, checkpointHash: N.hacherPoint(point0932) })).to.throw(TypeError, /contract/);
    expect(() => referenceRegistre({ index: null, orgId: ORG, journalId: JOURNAL, checkpointHash: N.hacherPoint(point0932) })).to.throw(TypeError);
  });

  it("refus : tree_size 0 ou supérieur au nombre de feuilles (K-1), hashes mal formés, jeton vide ou au-delà de 64 Kio, preuve illisible ou d'une autre empreinte (K-9), point sans identifiants", function () {
    const p0 = SERIE_P1[0];
    expect(() => construirePartiePointsDeControle({ point: p0, hashes: HASHES_P1 })).to.throw(RangeError, /tree_size/);
    expect(() => construirePartiePointsDeControle({ point: point0932, hashes: HASHES_P1.slice(0, 7) })).to.throw(RangeError, /tree_size/);
    expect(() => construirePartiePointsDeControle({ point: point0932, hashes: [...HASHES_P1.slice(0, 8), "0xZZ"] })).to.throw(TypeError, /hashes/);
    expect(() => construirePartiePointsDeControle({ point: point0932, hashes: HASHES_P1, jeton: new Uint8Array(0) })).to.throw(RangeError, /jeton/);
    expect(() => construirePartiePointsDeControle({ point: point0932, hashes: HASHES_P1, jeton: new Uint8Array(BORNES_EXPORTATEUR.jeton + 1) })).to.throw(RangeError, /jeton/);
    expect(() => construirePartiePointsDeControle({ point: point0932, hashes: HASHES_P1, preuve: N.utf8("pas une preuve") })).to.throw();
    expect(() => construirePartiePointsDeControle({ point: point0932, hashes: HASHES_P1, preuve: octets(path.join(CT6, "ots", "preuves", "periode-1.ots")) })).to.throw(RangeError, /empreinte/);
    expect(() => construirePartiePointsDeControle({ point: { ...point0932, org_id: "0x12" }, hashes: HASHES_P1 })).to.throw(TypeError, /org_id/);
  });

  it("EX-10.4 (AN-52) : parties du registre avec l'entrée ancre_point_de_controle depuis les captures de la période 1 et du bloc 18928 : registre.json, certificat-commit.json et validateurs.json identiques à periode-1-point ; sans capture du point, aucune entrée ; clôture absente : capture_incomplete", function () {
    const ref = path.join(CT6, "registre", "periode-1-point");
    const periodHash = N.hacherManifeste(MANIFESTE_P1);
    const fingerprint = N.empreinteAncre(ORG, JOURNAL, periodHash);
    const cles = lireJson(path.join(CT1, "cles", "cles.json"));
    const inscriptions = cles.keys.map((k) => ({ clePublique: k.public_key }));
    const r = partiesRegistre({ repertoireCaptures: dirCaptures, periodHash, fingerprint, inscriptions, empreintePoint: N.empreinteAncre(ORG, JOURNAL, N.hacherPoint(point0932)), jeux: JEUX_DEV, source: SOURCE_REGISTRE });
    for (const [nom, fichier] of [["registre", "registre.json"], ["certificatCommit", "certificat-commit.json"], ["validateurs", "validateurs.json"]]) {
      expect(Buffer.compare(Buffer.from(r.octets[nom]), octets(path.join(ref, fichier))), fichier).to.equal(0);
    }
    expect(r.inscriptionsAbsentes).to.deep.equal([]);
    // Une clé sans inscription capturée est simplement omise (AV-R-1 au vérificateur), jamais une erreur.
    const r2 = partiesRegistre({ repertoireCaptures: dirCaptures, periodHash, fingerprint, inscriptions: [{ clePublique: "0x" + "ab".repeat(32) }], jeux: JEUX_DEV, source: SOURCE_REGISTRE });
    expect(r2.inscriptionsAbsentes).to.deep.equal(["0x" + "ab".repeat(32)]);
    expect(r2.registre.entries.map((e) => e.role)).to.deep.equal(["ancre", "cloture"]);
    expect(() => partiesRegistre({ repertoireCaptures: dirCaptures, periodHash: "0x" + "11".repeat(32), fingerprint, jeux: JEUX_DEV, source: SOURCE_REGISTRE })).to.throw(/capture_incomplete/);
    expect(() => partiesRegistre({ repertoireCaptures: dirCaptures, periodHash, fingerprint, empreintePoint: "0x" + "22".repeat(32), jeux: JEUX_DEV, source: SOURCE_REGISTRE })).to.throw(/capture_incomplete : ancre du point/);
  });
});

describe("ancrage, exportateur : dossier complet depuis un dépôt d'ancres d'EX-5.14 (EX-10.1, AN-50, AN-51, AN-53)", function () {
  this.timeout(120000);
  let dir;
  let stockage;
  let captures;
  let d;
  before(function () {
    dir = repertoireTemporaire("noortrace-ancrage-f2-export-");
    stockage = path.join(dir, "stockage");
    captures = path.join(dir, "captures");
    d = depotVecteurs(stockage);
    capturesPeriode1Point(captures);
  });
  after(function () {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("EX-10.1 : piecesPeriode rend le .der du jeton promu du manifeste (dernier état d'acquisitions.ndjson, SHA-256 confronté), la dernière version de preuve.ots et entetes-bitcoin.json, octet pour octet", function () {
    const depots = depotsJournal({ racineStockage: stockage, orgId: ORG, journalId: JOURNAL });
    const p = piecesPeriode({ depots, periodStart: PERIODE });
    expect(p.defauts).to.deep.equal([]);
    expect(Buffer.compare(Buffer.from(p.jeton.octets), octets(path.join(CT6, "rfc3161", "jetons", "periode-1.der")))).to.equal(0);
    expect(p.jeton.enregistrement.provider_id).to.equal("qtsa-principal");
    expect(p.preuve.version).to.equal(1);
    expect(Buffer.compare(Buffer.from(p.preuve.octets), octets(path.join(CT6, "ots", "preuves", "periode-1.ots")))).to.equal(0);
    expect(p.entetes).to.not.equal(null);
    const k = piecesObjet({ depots, periodStart: PERIODE, objet: "point", checkpointHash: d.hash });
    expect(k.preuve.version).to.equal(2);
    expect(k.preuve.etat).to.equal("complete");
    expect(k.jeton.enregistrement.checks["T-10"]).to.equal("reussi");
    expect(jetonPromuDuPoint(depots.ancres.dernieresAcquisitions(PERIODE).enregistrements, d.hash).attempt_id).to.equal(k.jeton.enregistrement.attempt_id);
    // Jeton promu dont le fichier a été altéré : défaut consigné, aucune pièce remise (AN-50).
    const autre = path.join(dir, "altere");
    depotVecteurs(autre);
    const rep = path.join(autre, ORG.slice(2), JOURNAL.slice(2), "ancres", `periode-${PERIODE}`, "rfc3161");
    const der = fs.readdirSync(rep).find((n) => n.startsWith("manifeste") && n.endsWith(".der"));
    fs.appendFileSync(path.join(rep, der), Buffer.from([0]));
    const pa = piecesPeriode({ depots: depotsJournal({ racineStockage: autre, orgId: ORG, journalId: JOURNAL }), periodStart: PERIODE });
    expect(pa.jeton).to.equal(null);
    expect(pa.defauts.map((x) => x.raison)).to.include("SHA-256 différent de token_sha256 (AN-50)");
  });

  it("exporterDossier : treize parties, dossier.json identique à valide-point-de-controle-complet (même generated_at), entetes-bitcoin.json à côté hors des parties ; controlerAncresDossier conforme", function () {
    const ref = path.join(DOSSIERS_CT6, "valide-point-de-controle-complet");
    const destination = path.join(dir, "dossier-complet");
    const cles = lireJson(path.join(ref, "cles.json"));
    const r = exporterDossier({
      event: { seq: 7, hash: lireJson(path.join(ref, "evenement.json")).hash },
      org_id: ORG, journal_id: JOURNAL,
      partiesBase: partiesBase(ref), leafIndex: 6, hashes: HASHES_P1, manifeste: MANIFESTE_P1, periodHash: d.periodHash, serie: SERIE_P1, racineStockage: stockage,
      registre: { repertoireCaptures: captures, jeux: JEUX_DEV, source: SOURCE_REGISTRE, inscriptions: cles.keys.map((k) => ({ clePublique: k.public_key })) },
      destination, generated_at: N.decoderHorodatage(lireJson(path.join(ref, "dossier.json")).generated_at),
    });
    expect(r.defauts).to.deep.equal([]);
    expect(r.point).to.include({ rang: RANGS.jeton, tree_size: 8 });
    for (const nom of fs.readdirSync(ref)) {
      if (nom === "attendu.json") continue;
      expect(Buffer.compare(fs.readFileSync(path.join(destination, nom)), fs.readFileSync(path.join(ref, nom))), nom).to.equal(0);
    }
    expect(fs.existsSync(path.join(destination, "entetes-bitcoin.json"))).to.equal(true);
    expect(r.dossier.parts.map((p) => p.name)).to.not.include("entetes_bitcoin");
    expect(r.resume.periode.ots.etat).to.equal("complete");
    expect(controlerAncresDossier({ repertoireDossier: destination, racineStockage: stockage, orgId: ORG, journalId: JOURNAL, periodStart: PERIODE })).to.deep.equal({ conforme: true, ecarts: [] });
    // Le vecteur dont le base64 n'est pas canonique est relevé (K-7).
    const c = controlerAncresDossier({ repertoireDossier: path.join(DOSSIERS_CT6, "invalide-k7-base64-non-canonique"), racineStockage: stockage, orgId: ORG, journalId: JOURNAL, periodStart: PERIODE });
    expect(c.conforme).to.equal(false);
    expect(c.ecarts.map((e) => e.piece)).to.include("rfc3161.token");
  });

  it("AN-51 : le dossier produit passe K-1 à K-9 et les huit contrôles du vérificateur JavaScript de référence (boîte noire) avec le fichier d'ancres de test, même code et même énoncé que le vecteur", function () {
    const destination = path.join(dir, "dossier-complet");
    const attendu = lireJson(path.join(DOSSIERS_CT6, "valide-point-de-controle-complet", "attendu.json"));
    const js = verificateurJs(destination, path.join(CT6, "ancres", "ancres-test.json"), path.join(destination, "entetes-bitcoin.json"));
    expect(js.code).to.equal(attendu.exit_code);
    expect(js.rapport.verdict).to.equal("valide");
    expect(statuts(js.rapport, "K-")).to.deep.equal(Object.fromEntries(["K-1", "K-2", "K-3", "K-4", "K-5", "K-6", "K-7", "K-8", "K-9"].map((k) => [k, "reussi"])));
    expect(Object.fromEntries(js.rapport.controls.map((c) => [c.number, c.status]))).to.deep.equal(attendu.control_statuses);
    expect(js.rapport.statement.fr).to.equal(attendu.statement.fr);
  });

  it("AN-51 : même verdict, mêmes statuts K- et même énoncé par le binaire Go de CT-6 (boîte noire)", function () {
    const bin = binaireGo();
    if (!bin) return enAttente(this, "vérificateur Go de CT-6 (NOORTRACE_VERIFIER_BIN, NOORTRACE_GO_BIN ou verificateur/dist/noortrace-verifier-linux-amd64)");
    const destination = path.join(dir, "dossier-complet");
    const ancres = path.join(CT6, "ancres", "ancres-test.json");
    const entetes = path.join(destination, "entetes-bitcoin.json");
    const js = verificateurJs(destination, ancres, entetes);
    const go = verificateurGo(bin, destination, ancres, entetes);
    expect(go.code).to.equal(0);
    expect(go.rapport.verdict).to.equal("valide");
    expect(statuts(go.rapport, "K-")).to.deep.equal(statuts(js.rapport, "K-"));
    expect(go.rapport.statement.fr).to.equal(js.rapport.statement.fr);
    expect(go.rapport.statement.en).to.equal(js.rapport.statement.en);
  });

  it("dossier sans registre et avec une preuve de point en attente : parties réservées absentes avec leur raison, K-9 non exécutée (partie absente) ; sans jeton de point, le point couvrant est celui de la preuve (rang 2) ou de l'ancre", function () {
    const racine = path.join(dir, "stockage-attente");
    const x = depotVecteurs(racine, { pointEnAttente: true });
    const ref = path.join(DOSSIERS_CT6, "valide-point-de-controle-complet");
    const destination = path.join(dir, "dossier-attente");
    const r = exporterDossier({
      event: { seq: 7, hash: lireJson(path.join(ref, "evenement.json")).hash }, org_id: ORG, journal_id: JOURNAL,
      partiesBase: partiesBase(ref), leafIndex: 6, hashes: HASHES_P1, manifeste: MANIFESTE_P1, periodHash: x.periodHash, serie: SERIE_P1, racineStockage: racine,
      registre: null, destination, generated_at: N.decoderHorodatage("2026-11-06T09:00:00.000Z"),
    });
    const parts = Object.fromEntries(r.dossier.parts.map((p) => [p.name, p]));
    expect(parts.registre.reason_if_absent).to.equal(RAISONS.registreAbsent);
    expect(parts.points_de_controle.present).to.equal(true);
    expect(r.resume.point.ancres.ots.etat).to.equal("en_attente");
    const js = verificateurJs(destination, path.join(CT6, "ancres", "ancres-test.json"), path.join(destination, "entetes-bitcoin.json"));
    expect(js.code).to.equal(0);
    expect(statuts(js.rapport, "K-")["K-9"]).to.equal("non_execute");
    expect(js.rapport.checks.find((c) => c.id === "K-9").reason).to.equal("partie_absente");
    expect(js.rapport.checks.find((c) => c.id === "K-8").reason).to.equal("partie_absente");
    // Sans jeton de point : le point de 09:32 est retenu au rang de sa preuve complète (dépôt complet) ; en attente : sans ancre.
    const sansJeton = path.join(dir, "stockage-sans-jeton");
    depotVecteurs(sansJeton);
    const r2 = exporterDossier({
      event: { seq: 7, hash: lireJson(path.join(ref, "evenement.json")).hash }, org_id: ORG, journal_id: JOURNAL,
      partiesBase: partiesBase(ref), leafIndex: 6, hashes: HASHES_P1, manifeste: MANIFESTE_P1, periodHash: x.periodHash, serie: SERIE_P1, racineStockage: sansJeton,
      registre: null, destination: path.join(dir, "dossier-sans-jeton"), generated_at: N.decoderHorodatage("2026-11-06T09:00:00.000Z"), ecrire: false,
    });
    expect(r2.point.rang).to.equal(RANGS.jeton);
    const vide = path.join(dir, "stockage-vide");
    depotVecteurs(vide, { sansPoint: true, pointEnAttente: true });
    const r3 = exporterDossier({
      event: { seq: 7, hash: lireJson(path.join(ref, "evenement.json")).hash }, org_id: ORG, journal_id: JOURNAL,
      partiesBase: partiesBase(ref), leafIndex: 6, hashes: HASHES_P1, manifeste: MANIFESTE_P1, periodHash: x.periodHash, serie: SERIE_P1, racineStockage: vide,
      registre: null, destination: path.join(dir, "dossier-vide"), generated_at: N.decoderHorodatage("2026-11-06T09:00:00.000Z"), ecrire: false,
    });
    expect(r3.point.rang).to.equal(RANGS.aucune);
    expect(r3.point.ancres).to.deep.equal({ rfc3161: null, ots: { sha256: N.sha256Hex(octets(path.join(CT6, "ots", "preuves", "point-periode-1-en-attente.ots"))), etat: "en_attente", version: 1 }, registre: null });
    // Sans point après i : partie déclarée absente « aucun point de contrôle ».
    const r4 = exporterDossier({
      event: { seq: 7, hash: lireJson(path.join(ref, "evenement.json")).hash }, org_id: ORG, journal_id: JOURNAL,
      partiesBase: partiesBase(ref), leafIndex: 6, hashes: HASHES_P1, manifeste: MANIFESTE_P1, periodHash: x.periodHash, serie: SERIE_P1.slice(0, 20), racineStockage: vide,
      registre: null, destination: path.join(dir, "dossier-sans-point"), generated_at: N.decoderHorodatage("2026-11-06T09:00:00.000Z"), ecrire: false,
    });
    expect(r4.point).to.equal(null);
    expect(r4.dossier.parts.find((p) => p.name === "points_de_controle")).to.include({ present: false, reason_if_absent: RAISONS.pointAbsent });
  });

  it("EX-10.5 (AN-53) : reexportsDus rend les dossiers qu'une ancre arrivée depuis rend à réexporter (en_attente → complete, jeton promu plus tard, ancre capturée après coup, clôture relayée, en-têtes écrits) ; rien sans changement ; le dossier antérieur n'est jamais modifié", function () {
    const racineAttente = path.join(dir, "stockage-attente");
    const ref = path.join(DOSSIERS_CT6, "valide-point-de-controle-complet");
    const serieEtat = (racine, rep = null) => etatAncresPeriode({ racineStockage: racine, orgId: ORG, journalId: JOURNAL, periodStart: PERIODE, serie: SERIE_P1, repertoireCaptures: rep, periodHash: d.periodHash });
    const resume = exporterDossier({
      event: { seq: 7, hash: lireJson(path.join(ref, "evenement.json")).hash }, org_id: ORG, journal_id: JOURNAL,
      partiesBase: partiesBase(ref), leafIndex: 6, hashes: HASHES_P1, manifeste: MANIFESTE_P1, periodHash: d.periodHash, serie: SERIE_P1, racineStockage: racineAttente,
      registre: null, destination: path.join(dir, "d-attente"), generated_at: N.decoderHorodatage("2026-11-06T09:00:00.000Z"),
    }).resume;
    const avant = fs.readFileSync(path.join(dir, "d-attente", "dossier.json"));
    // Même état : rien.
    expect(reexportsDus({ dossiersProduits: [resume], etatAncres: new Map([[PERIODE, serieEtat(racineAttente)]]) })).to.deep.equal([]);
    // La preuve du point passe complete (version 2 écrite) : réexport dû.
    DepotOts.ouvrir({ racine: racineAttente, orgId: ORG, journalId: JOURNAL }).ecrire({ periodStart: PERIODE, objet: `point-${d.hash.slice(2)}`, octets: octets(path.join(CT6, "ots", "preuves", "point-periode-1.ots")) });
    const dus = reexportsDus({ dossiersProduits: [resume], etatAncres: (P) => (P === PERIODE ? serieEtat(racineAttente) : null) });
    expect(dus).to.have.lengthOf(1);
    expect(dus[0]).to.include({ seq: 7, period_start: PERIODE, destination: path.join(dir, "d-attente") });
    expect(dus[0].raisons).to.deep.equal(["ots_point"]);
    // Clôture capturée après coup et entrée registre : réexport dû, raisons cumulées.
    const etat2 = serieEtat(racineAttente, captures);
    const dus2 = reexportsDus({ dossiersProduits: [resume], etatAncres: { [PERIODE]: etat2 } });
    expect(dus2[0].raisons).to.include.members(["ots_point", "registre_periode", "registre_point"]);
    // Jeton obtenu plus tard sur un autre point (relève promue) : point couvrant meilleur.
    const sansJeton = { ...resume, point: { ...resume.point, rang: RANGS.preuve, ancres: { ...resume.point.ancres, rfc3161: null } } };
    expect(reexportsDus({ dossiersProduits: [sansJeton], etatAncres: { [PERIODE]: serieEtat(racineAttente) } })[0].raisons).to.include("jeton_point");
    // Le dossier remis n'a pas changé ; un nouveau dossier a un generated_at postérieur, fixé par l'appelant.
    expect(Buffer.compare(fs.readFileSync(path.join(dir, "d-attente", "dossier.json")), avant)).to.equal(0);
    const nouveau = exporterDossier({
      event: { seq: 7, hash: lireJson(path.join(ref, "evenement.json")).hash }, org_id: ORG, journal_id: JOURNAL,
      partiesBase: partiesBase(ref), leafIndex: 6, hashes: HASHES_P1, manifeste: MANIFESTE_P1, periodHash: d.periodHash, serie: SERIE_P1, racineStockage: racineAttente,
      registre: null, destination: path.join(dir, "d-attente-2"), generated_at: N.decoderHorodatage("2026-11-06T10:00:00.000Z"),
    }).resume;
    expect(N.decoderHorodatage(nouveau.generated_at)).to.be.greaterThan(N.decoderHorodatage(resume.generated_at));
    expect(nouveau.point.ancres.ots.etat).to.equal("complete");
    expect(reexportsDus({ dossiersProduits: [nouveau], etatAncres: { [PERIODE]: serieEtat(racineAttente) } })).to.deep.equal([]);
    // Entrées hostiles : liste absente, états non objets, période inconnue.
    expect(() => reexportsDus({ dossiersProduits: null, etatAncres: {} })).to.throw(TypeError);
    expect(reexportsDus({ dossiersProduits: [resume, null, { seq: 1 }], etatAncres: {} })).to.deep.equal([]);
  });

  it("mémoire (épreuves de l'étape 5, collecte c_T = 60 s) : les résumés gardés pour EX-10.5 et l'index des nonces ne retiennent pas le texte d'acquisitions.ndjson ; avant la correction, chaque résumé gardait le fichier entier (2 799 exports, tas épuisé)", function () {
    const racine = path.join(dir, "stockage-memoire");
    const dm = depotVecteurs(racine);
    // acquisitions.ndjson grossi d'environ 3 Mo par des tentatives non promues (l'enregistrement promu reste le dernier état de sa tentative).
    const jeton = octets(path.join(CT6, "rfc3161", "jetons", "periode-1.der"));
    const remplissage = "r".repeat(900);
    for (let k = 0; k < 3000; k++) {
      const e = enregistrementAcquisition({ objet: "manifeste", imprint: dm.periodHash, providerId: "tsa-interne", attemptId: `jeton_periode:${dm.periodHash.slice(2, 18)}:${k + 10}`, fichier: `rfc3161/remplissage-${k}`, jeton, promoted: false });
      e.error_code = `${remplissage}${k}`;
      e.nonce = `0x${(k + 1).toString(16).padStart(16, "0")}`;
      dm.depot.ajouterAcquisition(PERIODE, e);
    }
    const taille = fs.statSync(path.join(dm.depot.repertoire(PERIODE), "acquisitions.ndjson")).size;
    expect(taille).to.be.greaterThan(3000000);
    const ref = path.join(DOSSIERS_CT6, "valide-point-de-controle-complet");
    const base = {
      event: { seq: 7, hash: lireJson(path.join(ref, "evenement.json")).hash }, org_id: ORG, journal_id: JOURNAL, partiesBase: partiesBase(ref), leafIndex: 6, hashes: HASHES_P1,
      manifeste: MANIFESTE_P1, periodHash: dm.periodHash, serie: SERIE_P1, racineStockage: racine, registre: null, destination: path.join(dir, "x"), generated_at: 1, ecrire: false,
    };
    v8.setFlagsFromString("--expose-gc");
    const gc = vm.runInNewContext("gc");
    gc();
    const avant = process.memoryUsage().heapUsed;
    const resumes = [];
    for (let k = 0; k < 40; k++) resumes.push(exporterDossier(base).resume);
    const lecteur = DepotAncres.ouvrir({ racine, orgId: ORG, journalId: JOURNAL });
    expect(lecteur.nonceConnu("0x0000000000000001")).to.equal(true);
    gc();
    const retenu = process.memoryUsage().heapUsed - avant;
    expect(resumes[39].periode.rfc3161).to.equal(N.sha256Hex(jeton));
    // Quarante résumés et un index de 3 001 nonces : quelques centaines de Kio ; avec la retenue, 41 copies du fichier (plus de 120 Mo).
    expect(retenu, `${retenu} octets retenus`).to.be.lessThan(16 * 1024 * 1024);
    void lecteur;
  });

  it("entrées hostiles d'exporterDossier : event, identifiants, partiesBase, manifeste, generated_at refusés ; octetsJsonDossier est la mise en forme de CT-1 §11.1", function () {
    const ref = path.join(DOSSIERS_CT6, "valide-point-de-controle-complet");
    const base = { event: { seq: 7, hash: lireJson(path.join(ref, "evenement.json")).hash }, org_id: ORG, journal_id: JOURNAL, partiesBase: partiesBase(ref), leafIndex: 6, hashes: HASHES_P1, manifeste: MANIFESTE_P1, periodHash: d.periodHash, serie: SERIE_P1, racineStockage: stockage, registre: null, destination: path.join(dir, "x"), generated_at: 1, ecrire: false };
    expect(() => exporterDossier({ ...base, event: { seq: "7", hash: base.event.hash } })).to.throw(TypeError, /event/);
    expect(() => exporterDossier({ ...base, org_id: "0x00" })).to.throw(TypeError, /org_id/);
    expect(() => exporterDossier({ ...base, partiesBase: {} })).to.throw(TypeError, /partiesBase/);
    expect(() => exporterDossier({ ...base, manifeste: null })).to.throw(TypeError, /manifeste/);
    expect(() => exporterDossier({ ...base, generated_at: "2026-11-06T09:00:00.000Z" })).to.throw(TypeError, /generated_at/);
    expect(Buffer.from(octetsJsonDossier({ a: 1 })).toString("utf8")).to.equal('{\n  "a": 1\n}\n');
  });
});
