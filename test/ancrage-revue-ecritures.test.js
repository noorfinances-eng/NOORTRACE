// Revue de sécurité interne de l'étape 8 : écritures du composant
// d'ancrage. Une pièce, une ligne de file ou une réponse capturée n'existe
// sous son nom que complète et vérifiée (CT-5 EX-5.14, EX-8.5 règles 1 et 3 ;
// CT-4 EX-9.3) : (fragment de ligne dans la file), 
// (fsync du répertoire), (lignes écartées au compactage consignées),
// (dépôt : écriture courte, fragment d'acquisitions.ndjson), EX-5.10
// (rejeu de l'étape 9 : enregistrement `obtenue` promu que l'exportateur
// remet), CT-5 EX-6.5 (dernière version .ots lisible), CT-4 EX-9.3 (capture : un
// fichier présent faux ou tronqué est mis de côté et redemandé).

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import * as N from "@noortrace/noyau";
import { FileDurable, lireFiles } from "@noortrace/ancrage/planificateur";
import { DepotAncres, ErreurDepot, ErreurTransport } from "@noortrace/ancrage/rfc3161";
import { DepotOts, Noeud, OP, attestationEnAttente, ecrireOts } from "@noortrace/ancrage/ots";
import * as R from "@noortrace/ancrage/registre";
import { piecesPeriode, depotsJournal } from "@noortrace/ancrage/exportateur";
import { NoeudFactice, validateursEssai } from "./fixtures/ancrage-registre/noeud-factice.mjs";
import { ORG, JOURNAL, attenteCalme, monterComposant, remisePoint, remiseCloture, repertoireTemporaire, enAttente } from "./fixtures/ancrage-composant/outils.mjs";

const RACINE = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const lireJson = (p) => JSON.parse(fs.readFileSync(path.join(RACINE, p), "utf8"));
const REPRISE = path.join(RACINE, "spec", "vecteurs", "ct-5", "reprise");
const demandes = (nom) => fs.readFileSync(path.join(REPRISE, nom), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));

/** Fait échouer `fs.writeSync` une fois, après `partiel` octets écrits (disque plein en cours d'écriture). */
function pannePartielle(partiel) {
  const vrai = fs.writeSync;
  let faite = false;
  fs.writeSync = function (fd, donnees, ...reste) {
    if (faite) return vrai.call(fs, fd, donnees, ...reste);
    faite = true;
    const octets = typeof donnees === "string" ? Buffer.from(donnees, "utf8") : Buffer.from(donnees.buffer, donnees.byteOffset, donnees.byteLength);
    const [offset = 0, longueur = octets.length - offset] = typeof reste[0] === "number" ? reste : [0, octets.length];
    const n = Math.min(partiel, longueur);
    if (n > 0) vrai.call(fs, fd, octets, offset, n);
    const err = new Error("ENOSPC: no space left on device, write");
    err.code = "ENOSPC";
    throw err;
  };
  return () => {
    fs.writeSync = vrai;
  };
}

/** `fs.writeSync` rend une écriture courte une fois (quota ou limite de taille atteints en cours d'écriture). */
function ecritureCourte(partiel) {
  const vrai = fs.writeSync;
  let faite = false;
  fs.writeSync = function (fd, donnees, ...reste) {
    if (faite) return vrai.call(fs, fd, donnees, ...reste);
    faite = true;
    const octets = typeof donnees === "string" ? Buffer.from(donnees, "utf8") : Buffer.from(donnees.buffer, donnees.byteOffset, donnees.byteLength);
    const [offset = 0, longueur = octets.length - offset] = typeof reste[0] === "number" ? reste : [0, octets.length];
    return vrai.call(fs, fd, octets, offset, Math.min(partiel, longueur));
  };
  return () => {
    fs.writeSync = vrai;
  };
}

describe("ancrage, revue de sécurité de l'étape 8 : file durable (EX-8.5 règles 1, 3 et 5)", function () {
  let dir;
  beforeEach(function () {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "ancrage-revue-file-"));
  });
  afterEach(function () {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("CT-5 EX-8.5 : un fragment de ligne laissé en fin de fichier est retiré à l'ouverture ; la ligne écrite ensuite est relue", function () {
    const d = demandes("redemarrage-reprise.avant.ndjson");
    const rep = path.join(dir, "file");
    const f1 = FileDurable.ouvrir({ repertoire: rep, epoque: 1 });
    f1.ecrire(d[0]);
    f1.fermer();
    // Coupure pendant l'ajout d'une ligne : 200 octets sans fin de ligne.
    fs.appendFileSync(f1.chemin, N.jcs({ ...d[0], state: "envoyee" }).slice(0, 200));
    const f2 = FileDurable.ouvrir({ repertoire: rep, epoque: 1 });
    expect(f2.reparation, "le fragment est retiré à l'ouverture (EX-8.5, règle 3 : la ligne tronquée est ignorée, jamais relue)").to.deep.equal({ octets_retires: 200 });
    const acquittee = { ...d[0], state: "a_reprendre", due_at: d[0].created_at };
    f2.ecrire(acquittee);
    f2.fermer();
    const relue = lireFiles(rep);
    expect(relue.tronquees).to.deep.equal([]);
    expect(relue.parId.get(d[0].id)).to.deep.equal(acquittee);
  });

  it("CT-5 EX-8.5 : une écriture interrompue en cours de ligne (ENOSPC) ne laisse aucun fragment ; la ligne suivante acquittée est relue", function () {
    const d = demandes("redemarrage-reprise.avant.ndjson");
    const rep = path.join(dir, "file");
    const f = FileDurable.ouvrir({ repertoire: rep, epoque: 1 });
    f.ecrire(d[0]);
    const retablir = pannePartielle(40);
    try {
      expect(() => f.ecrire({ ...d[0], state: "envoyee" })).to.throw(/ENOSPC/);
    } finally {
      retablir();
    }
    expect(fs.readFileSync(f.chemin, "utf8")).to.equal(N.jcs(d[0]) + "\n");
    const acquittee = { ...d[0], state: "a_reprendre", due_at: d[0].created_at };
    f.ecrire(acquittee);
    f.fermer();
    const relue = lireFiles(rep);
    expect(relue.tronquees).to.deep.equal([]);
    expect(relue.parId.get(d[0].id)).to.deep.equal(acquittee);
  });

  it("CT-5 EX-8.5 : la création du fichier d'une époque synchronise son répertoire (fsync), pas seulement la création du répertoire", function () {
    const rep = path.join(dir, "file");
    fs.mkdirSync(rep, { recursive: true });
    const vraiOpen = fs.openSync;
    const vraiFsync = fs.fsyncSync;
    const ouverts = new Map();
    const synchronises = [];
    fs.openSync = function (chemin, ...reste) {
      const fd = vraiOpen.call(fs, chemin, ...reste);
      ouverts.set(fd, String(chemin));
      return fd;
    };
    fs.fsyncSync = function (fd) {
      synchronises.push(ouverts.get(fd) ?? null);
      return vraiFsync.call(fs, fd);
    };
    try {
      const f = FileDurable.ouvrir({ repertoire: rep, epoque: 3 });
      f.fermer();
    } finally {
      fs.openSync = vraiOpen;
      fs.fsyncSync = vraiFsync;
    }
    expect(synchronises.map((p) => path.resolve(p))).to.include(path.resolve(rep));
  });

  it("CT-5 EX-8.5 : le compactage consigne chaque ligne illisible écartée (anchor_queue_truncated_line) et leur nombre dans anchor_queue_compacted", function () {
    const d = demandes("redemarrage-reprise.avant.ndjson");
    const rep = path.join(dir, "file");
    const lignes = [];
    const journal = (niveau, evenement, champs) => lignes.push({ niveau, evenement, champs });
    const f = FileDurable.ouvrir({ repertoire: rep, epoque: 1, journal, fdatasync: false });
    f.ecrire(d[0]);
    fs.appendFileSync(f.chemin, "{\"corrompue\": true}\n");
    f.ecrire({ ...d[0], state: "a_reprendre", due_at: d[0].created_at });
    const r = f.compacter({ declencheur: "cloture" });
    f.fermer();
    expect(r.fait).to.equal(true);
    expect(r.dropped_lines).to.equal(1);
    const compacte = lignes.find((l) => l.evenement === "anchor_queue_compacted");
    expect(compacte.champs.dropped_lines).to.equal(1);
    const ecartee = lignes.filter((l) => l.evenement === "anchor_queue_truncated_line");
    expect(ecartee).to.have.lengthOf(1);
    expect(ecartee[0].niveau).to.equal("error");
    expect(ecartee[0].champs).to.include({ line: 2, reason: "demande_non_conforme" });
  });
});

describe("ancrage, revue de sécurité de l'étape 8 : dépôt des pièces RFC 3161 (EX-5.14, AN-14 ; CT-5 EX-5.10)", function () {
  let dir;
  let depot;
  const P = 1793862000;
  beforeEach(function () {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "ancrage-revue-depot-"));
    depot = DepotAncres.ouvrir({ racine: dir, orgId: ORG, journalId: JOURNAL });
  });
  afterEach(function () {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("CT-5 EX-5.14 : une pièce n'existe sous son nom qu'entière : une écriture courte est poursuivie jusqu'au dernier octet ; une écriture en échec ne laisse aucun fichier sous le nom", function () {
    const octets = new Uint8Array(2228).fill(0x41);
    let retablir = ecritureCourte(2048);
    try {
      depot.ecrirePiece(P, "rfc3161", "manifeste-a-1.der", octets);
    } finally {
      retablir();
    }
    const rep = path.join(depot.repertoire(P), "rfc3161");
    expect(fs.statSync(path.join(rep, "manifeste-a-1.der")).size).to.equal(2228);
    retablir = pannePartielle(100);
    try {
      expect(() => depot.ecrirePiece(P, "rfc3161", "manifeste-a-2.der", octets)).to.throw(ErreurDepot);
    } finally {
      retablir();
    }
    expect(fs.existsSync(path.join(rep, "manifeste-a-2.der")), "aucun fichier partiel sous le nom définitif").to.equal(false);
    expect(fs.readdirSync(rep).filter((n) => n.includes("manifeste-a-2")), "aucun résidu temporaire").to.deep.equal([]);
    // Après l'échec, la même pièce s'écrit (le nom n'est pas pris par un fragment).
    depot.ecrirePiece(P, "rfc3161", "manifeste-a-2.der", octets);
    expect(fs.statSync(path.join(rep, "manifeste-a-2.der")).size).to.equal(2228);
  });

  it("CT-5 EX-5.14 : acquisitions.ndjson : une ligne courte est écrite en entier, un fragment laissé par une coupure ne rend jamais l'acquisition suivante illisible", function () {
    const e1 = { attempt_id: "a:1", attempt: 1, object: "manifeste", object_name: "manifeste", imprint: "0x" + "11".repeat(32), outcome: "obtenue", promoted: true, revoked: false, nonce: "0x0000000000000001", upper_bound: "2026-11-05T08:00:01.000Z", files: { token: "rfc3161/manifeste-a-1.der" }, remplissage: "x".repeat(2300) };
    let retablir = ecritureCourte(2048);
    try {
      depot.ajouterAcquisition(P, e1);
    } finally {
      retablir();
    }
    let lu = depot.lireAcquisitions(P);
    expect(lu.tronquee).to.equal(false);
    expect(lu.enregistrements.map((e) => e.attempt_id)).to.deep.equal(["a:1"]);
    // Coupure pendant un ajout : fragment de 300 octets sans fin de ligne, puis une acquisition complète.
    const chemin = path.join(depot.repertoire(P), "acquisitions.ndjson");
    fs.appendFileSync(chemin, N.jcs({ ...e1, attempt_id: "a:2" }).slice(0, 300));
    const e3 = { ...e1, attempt_id: "a:3", attempt: 3 };
    depot.ajouterAcquisition(P, e3);
    lu = depot.lireAcquisitions(P);
    expect(lu.illisibles).to.deep.equal([]);
    expect(lu.tronquee).to.equal(false);
    expect(lu.enregistrements.map((e) => e.attempt_id)).to.deep.equal(["a:1", "a:3"]);
    expect(depot.promu("manifeste", P).attempt_id).to.equal("a:3");
    // Une écriture en échec au milieu d'une ligne ne laisse pas de fragment non plus.
    retablir = pannePartielle(50);
    try {
      expect(() => depot.ajouterAcquisition(P, { ...e1, attempt_id: "a:4", attempt: 4 })).to.throw(ErreurDepot);
    } finally {
      retablir();
    }
    expect(depot.lireAcquisitions(P).enregistrements.map((e) => e.attempt_id)).to.deep.equal(["a:1", "a:3"]);
    expect(fs.readFileSync(chemin, "utf8").endsWith("\n")).to.equal(true);
  });

  it("CT-5 EX-5.10 : dejaPromu et promu n'acceptent promoted qu'avec outcome obtenue (EX-5.8)", function () {
    const base = { attempt: 1, object: "manifeste", object_name: "manifeste", imprint: "0x" + "22".repeat(32), revoked: false, nonce: "0x0000000000000002", upper_bound: "2026-11-05T08:00:01.000Z", files: { token: "rfc3161/manifeste-b-1.der" } };
    depot.ajouterAcquisition(P, { ...base, attempt_id: "b:1", outcome: "echec_transitoire", error_code: "ecriture", promoted: true });
    expect(depot.dejaPromu("manifeste", base.imprint, P)).to.equal(false);
    expect(depot.promu("manifeste", P)).to.equal(null);
    depot.ajouterAcquisition(P, { ...base, attempt_id: "b:2", attempt: 2, outcome: "obtenue", error_code: null, promoted: true });
    expect(depot.dejaPromu("manifeste", base.imprint, P)).to.equal(true);
    expect(depot.promu("manifeste", P).attempt_id).to.equal("b:2");
  });
});

describe("ancrage, revue de sécurité de l'étape 8 : composant, écriture de l'étape 9 en échec puis rejouée (EX-5.10 étape 9, EX-5.8)", function () {
  this.timeout(600000);
  const PERIODE = 1793862000;
  const TOUTES = Object.fromEntries(Array.from({ length: 59 }, (_, i) => [i + 1, 1]));

  for (const mode of ["acquisitions", "piece"]) {
    it(`échec passager de ${mode === "acquisitions" ? "l'enregistrement d'acquisition" : "la pièce .der"} du jeton de clôture : au rejeu, acquisitions.ndjson porte un enregistrement obtenue promu et l'exportateur remet le jeton`, async function () {
      const dir = repertoireTemporaire("ancrage-revue-ecritures-");
      const m = await monterComposant({ dir, periodStart: PERIODE, evenements: TOUTES, ErreurTransport });
      if (m.condition) return enAttente(this, m.condition);
      const composant = m.creer();
      const calme = attenteCalme(composant);
      await composant.demarrer();
      for (const point of m.serie.points.slice(0, -1)) {
        await m.horloge.aller(N.decoderHorodatage(point.checkpoint_ts), calme);
        m.remis.push(point);
        expect((await composant.remettrePoint(remisePoint(point))).admis).to.equal(true);
        await calme();
      }
      let pannes = 0;
      const vraiAjouter = DepotAncres.prototype.ajouterAcquisition;
      const vraiEcrire = DepotAncres.prototype.ecrirePiece;
      const panne = () => {
        pannes += 1;
        const err = new Error("ENOSPC: no space left on device, write");
        err.code = "ENOSPC";
        throw new ErreurDepot(`écriture impossible : ${err.message}`, err);
      };
      if (mode === "acquisitions") {
        DepotAncres.prototype.ajouterAcquisition = function (periodStart, e) {
          if (e.object === "manifeste" && pannes === 0) panne();
          return vraiAjouter.call(this, periodStart, e);
        };
      } else {
        DepotAncres.prototype.ecrirePiece = function (periodStart, sous, nom, octets) {
          if (sous === "rfc3161" && /^manifeste.*\.der$/.test(nom) && pannes === 0) panne();
          return vraiEcrire.call(this, periodStart, sous, nom, octets);
        };
      }
      try {
        const cloture = m.serie.points.at(-1);
        await m.horloge.aller(N.decoderHorodatage(cloture.checkpoint_ts), calme);
        m.remis.push(cloture);
        await composant.remettrePoint(remisePoint(cloture));
        expect((await composant.remettreCloture(remiseCloture(m.serie))).admis).to.equal(true);
        await calme();
        expect(pannes).to.equal(1);
        expect(m.journal.de("anchor_piece_write_failed").length).to.be.at.least(1);
        // Le disque revient : le tic suivant rejoue l'écriture.
        await m.horloge.avancer(3000, calme);
        await m.horloge.avancer(20000, calme);
      } finally {
        DepotAncres.prototype.ajouterAcquisition = vraiAjouter;
        DepotAncres.prototype.ecrirePiece = vraiEcrire;
      }
      const jeton = composant.demandes().find((d) => d.kind === "jeton_periode");
      expect(jeton.state).to.equal("obtenue");
      expect(composant.etat().ecritures_en_attente).to.equal(0);
      const depots = depotsJournal({ racineStockage: m.contexte.racineStockage, orgId: ORG, journalId: JOURNAL });
      const lues = depots.ancres.dernieresAcquisitions(PERIODE).enregistrements.filter((e) => e.object === "manifeste");
      expect(lues.map((e) => [e.outcome, e.error_code, e.promoted])).to.deep.equal([["obtenue", null, true]]);
      const pieces = piecesPeriode({ depots, periodStart: PERIODE });
      expect(pieces.defauts).to.deep.equal([]);
      expect(pieces.jeton, "l'exportateur remet le jeton promu").to.not.equal(null);
      expect(pieces.jeton.sha256).to.equal(jeton.result.sha256);
      await composant.arreter({ attendre: false });
      await m.fermer();
      fs.rmSync(dir, { recursive: true, force: true });
    });
  }
});

describe("ancrage, revue de sécurité de l'étape 8 : dépôt des preuves OpenTimestamps (EX-6.5)", function () {
  let dir;
  beforeEach(function () {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "ancrage-revue-ots-depot-"));
  });
  afterEach(function () {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function preuve(uri) {
    const n = new Noeud();
    n.operation(OP.SHA256, null).ajouterAttestation(attestationEnAttente(uri));
    return ecrireOts({ empreinte: new Uint8Array(32).fill(7), arbre: n });
  }

  it("la dernière version est la plus haute que le lecteur lit ; une version tronquée (coupure) est signalée, non rendue ; l'écriture passe par un nom provisoire", function () {
    const depot = DepotOts.ouvrir({ racine: dir, orgId: ORG, journalId: JOURNAL });
    const P = 1793710800;
    const v1 = depot.ecrire({ periodStart: P, objet: "manifeste", octets: preuve("https://a.calendrier.example") });
    const v2 = depot.ecrire({ periodStart: P, objet: "manifeste", octets: preuve("https://b.calendrier.example") });
    fs.writeFileSync(v2.chemin, fs.readFileSync(v2.chemin).subarray(0, 40));
    const d = depot.derniere({ periodStart: P, objet: "manifeste" });
    expect(d.version).to.equal(1);
    expect(d.octets).to.deep.equal(preuve("https://a.calendrier.example"));
    expect(d.illisibles).to.deep.equal([{ version: 2, nom: path.basename(v2.chemin), raison: "tronque" }]);
    expect(v1.version).to.equal(1);
    // Une écriture interrompue ne laisse pas de fichier sous le nom de version.
    const retablir = pannePartielle(10);
    try {
      expect(() => depot.ecrire({ periodStart: P, objet: "manifeste", octets: preuve("https://c.calendrier.example") })).to.throw(/ENOSPC/);
    } finally {
      retablir();
    }
    expect(depot.versions({ periodStart: P, objet: "manifeste" }).map((v) => v.version)).to.deep.equal([1, 2]);
    expect(fs.readdirSync(path.join(depot.repertoirePeriode(P), "ots")).filter((n) => !/^manifeste-\d+\.ots$/.test(n))).to.deep.equal([]);
  });
});

describe("ancrage, revue de sécurité de l'étape 8 : capture d'une transaction du registre (CT-4 EX-9.3)", function () {
  this.timeout(60000);
  const CONSTANTES = lireJson("spec/vecteurs/ct-4/constantes.json");
  const POINTS = ["http://127.0.0.1:8645", "http://127.0.0.1:8646", "http://127.0.0.1:8647", "http://127.0.0.1:8648"];
  const CONTRATS = { attestation_registry: CONSTANTES.contracts.attestation_registry, period_registry: CONSTANTES.contracts.period_registry, recorder_registry: CONSTANTES.contracts.recorder_registry };
  const ORG4 = CONSTANTES.organisation.org_id;
  const JOURNAL_REF = "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b";
  const K2 = "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff";
  const CLE = new R.SignataireChaineFichier(N.sha256(N.utf8("noortrace/ancrage/test/cle-chaine-01")));
  const ED25519_01 = CONSTANTES.recorders[0].public_key;
  const REPERTOIRES = [];
  after(function () {
    for (const r of REPERTOIRES) fs.rmSync(r, { recursive: true, force: true });
  });

  /** Contexte : nœud factice derrière un transport qui peut altérer une réponse (`mentir({ url, requete, honnete })`). */
  function contexte({ mentir = null } = {}) {
    const noeud = new NoeudFactice({ validateurs: validateursEssai(CONSTANTES), points: POINTS, contrats: CONTRATS });
    const honnete = noeud.transport();
    const etat = { ment: true };
    const transport = async ({ url, octets, delaiMs, tailleMax }) => {
      const requete = JSON.parse(Buffer.from(octets).toString("utf8"));
      const reponse = JSON.parse(Buffer.from((await honnete({ url, octets, delaiMs, tailleMax })).octets).toString("utf8"));
      const finale = etat.ment && mentir ? mentir({ url, requete, honnete: reponse }) ?? reponse : reponse;
      return { status: 200, octets: new TextEncoder().encode(JSON.stringify(finale)) };
    };
    const rpc = new R.ClientRpc({ points: POINTS, transport, identifiants: Object.fromEntries(POINTS.map((p, k) => [p, `v${k + 1}`])) });
    const repertoire = fs.mkdtempSync(path.join(os.tmpdir(), "ancrage-revue-capture-"));
    REPERTOIRES.push(repertoire);
    let monotone = 0;
    const horloge = { murale: () => Date.UTC(2026, 10, 9, 12, 0, 0) + monotone, monotone: () => monotone };
    const attendre = async (ms) => { monotone += ms; };
    const jeux = { validators: validateursEssai(CONSTANTES).validators, source: "jeu d'essai de CT-4 annexe A.2" };
    const instance = { evmChainId: 2124, bftChainId: "noortrace-2124-dev", contrats: CONTRATS, fees: { gas_limit: 3000000, gas_limit_max: 16777216 }, jeux };
    const nouvelEnvoyeur = () => new R.Envoyeur({ rpc, repertoireEnvois: repertoire, instance, horloge, attendre, delais: { recuMs: 60000, sondageMs: 500 }, journal: () => {} });
    noeud.approvisionner(CLE.adresse(), 4719000000n);
    noeud.inscrire({ orgId: ORG4, chainKey: CLE.adresse(), ed25519PubKey: ED25519_01, journalId: JOURNAL_REF });
    const ancre = (envoyeur) => envoyeur.ancrer({ orgId: ORG4, journalId: JOURNAL_REF, objet: K2, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE });
    return { noeud, rpc, repertoire, etat, nouvelEnvoyeur, ancre };
  }

  it("a) un point rend une fois un en-tête altéré : capture_incomplete, aucun fichier sous bloc-<h>.json ; la reprise avec des points honnêtes capture sans intervention", async function () {
    const c = contexte({ mentir: ({ requete, honnete }) => (requete.method === "eth_getBlockByNumber" && honnete.result ? { ...honnete, result: { ...honnete.result, stateRoot: "0x" + "66".repeat(32) } } : null) });
    const r1 = await c.ancre(c.nouvelEnvoyeur());
    expect(r1.type).to.equal("echec_registre");
    expect(r1.data.code).to.equal("capture_incomplete");
    expect(fs.existsSync(path.join(c.repertoire, "bloc-1001.json")), "une réponse qui ne passe pas CP-2 n'est jamais écrite sous son nom définitif").to.equal(false);
    c.etat.ment = false;
    const r2 = await c.ancre(c.nouvelEnvoyeur());
    expect(r2.type, JSON.stringify(r2)).to.equal("inclusion_registre");
    expect(fs.existsSync(path.join(c.repertoire, "capture-1001-0-ancre.json"))).to.equal(true);
  });

  it("b) un certificat lisible aux precommits altérés, servi une fois : certificat_invalide sans fichier ; puis capture à la reprise", async function () {
    const c = contexte({
      mentir: ({ requete, honnete }) => {
        if (requete.method !== "noor_getCommitCertificate" || !honnete.result) return null;
        const copie = JSON.parse(JSON.stringify(honnete.result));
        for (const p of copie.precommits.slice(0, 2)) p.line = p.line.replace(/"sig":"(.)/, (m, g) => `"sig":"${g === "A" ? "B" : "A"}`);
        return { ...honnete, result: copie };
      },
    });
    const r1 = await c.ancre(c.nouvelEnvoyeur());
    expect(r1.data.code).to.equal("certificat_invalide");
    expect(fs.existsSync(path.join(c.repertoire, "certificat-1001.json"))).to.equal(false);
    c.etat.ment = false;
    const r2 = await c.ancre(c.nouvelEnvoyeur());
    expect(r2.type, JSON.stringify(r2)).to.equal("inclusion_registre");
  });

  it("c) un fichier bloc-<h>.json vide laissé par une coupure est mis de côté (.rejete-<sha256>) et la réponse redemandée : capture à la première reprise", async function () {
    const c = contexte();
    fs.writeFileSync(path.join(c.repertoire, "bloc-1001.json"), "");
    const r = await c.ancre(c.nouvelEnvoyeur());
    expect(r.type, JSON.stringify(r)).to.equal("inclusion_registre");
    const noms = fs.readdirSync(c.repertoire);
    expect(noms.some((n) => /^bloc-1001\.json\.rejete-[0-9a-f]{64}$/.test(n)), `fichier mis de côté : ${noms.join(", ")}`).to.equal(true);
    expect(JSON.parse(fs.readFileSync(path.join(c.repertoire, "bloc-1001.json"), "utf8")).result.number).to.equal("0x3e9");
  });

  it("d) un fichier bloc-<h>.json présent, lisible et faux (stateRoot altéré) est mis de côté et redemandé", async function () {
    const c = contexte();
    // Première capture honnête, puis altération du fichier sur le disque et seconde capture d'une autre transaction du même bloc : impossible avec un bloc par
    // transaction ; on simule le fichier présent faux avant la première capture.
    const e = c.nouvelEnvoyeur();
    const r1 = await c.ancre(e);
    expect(r1.type).to.equal("inclusion_registre");
    const chemin = path.join(c.repertoire, "bloc-1001.json");
    const vrai = JSON.parse(fs.readFileSync(chemin, "utf8"));
    for (const n of fs.readdirSync(c.repertoire)) if (/^(capture|recu|certificat)-/.test(n)) fs.rmSync(path.join(c.repertoire, n));
    fs.writeFileSync(chemin, JSON.stringify({ ...vrai, result: { ...vrai.result, stateRoot: "0x" + "77".repeat(32) } }));
    const hash = fs.readdirSync(c.repertoire).find((n) => n.startsWith("envoi-")).slice(6, -5);
    const r2 = await c.nouvelEnvoyeur().renvoyer(hash);
    expect(r2.type, JSON.stringify(r2)).to.equal("inclusion_registre");
    expect(fs.readdirSync(c.repertoire).some((n) => /^bloc-1001\.json\.rejete-/.test(n))).to.equal(true);
    expect(JSON.parse(fs.readFileSync(chemin, "utf8")).result.stateRoot).to.equal(vrai.result.stateRoot);
  });
});
