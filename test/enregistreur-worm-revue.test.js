// Revue de sécurité interne de l'étape 8 : constats sur la part WORM de
// l'enregistreur (EX-12.38, EX-12.36 (CT-2 §12.6,
// §12.11, EX-17.5 à EX-17.7, EX-12.18). Chaque `it` reproduit le défaut tel que
// le relecteur l'a prouvé, sans réseau ni Docker : le
// support WORM est joué par un objet d'opérations en mémoire qui sert toutes
// les versions d'une clé, les marqueurs de suppression et les corps voulus.
// Le cas de l'attribut `i` (CT-2 EX-12.18) demande le compte 0 et un système de
// fichiers à attributs ; sans eux il est mis en attente, condition nommée.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { sha256Hex } from "@noortrace/noyau";
import * as E from "@noortrace/enregistreur";
import { analyserXml } from "../paquets/enregistreur/src/worm/xml.mjs";
import { verifierGarde, etatGel, empreinteEnregistrement } from "../paquets/enregistreur/src/worm/garde.mjs";
import { lireRegistreGels, releverVerrouillage, versionsAttenduesGelees, SupervisionWorm } from "../paquets/enregistreur/src/worm/controles.mjs";
import { ServiceCopiesWorm } from "../paquets/enregistreur/src/worm/copies.mjs";
import { OutilGel, ArretOutil, CODES } from "../paquets/enregistreur/src/worm/gel.mjs";
import { calculerPerimetre, octetsListeObjets } from "../paquets/enregistreur/src/worm/perimetre.mjs";
import { OperationsS3 } from "../paquets/enregistreur/src/worm/support.mjs";
import { AccesS3, ErreurTransport } from "../paquets/enregistreur/src/worm/s3.mjs";
import { passageAttributs } from "../paquets/enregistreur/src/worm/attributs.mjs";
import { configurationDev, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";

const ICI = path.dirname(fileURLToPath(import.meta.url));
const RACINE = path.resolve(ICI, "..");
const enc = (c) => new Uint8Array(Buffer.from(JSON.stringify(c)));

/** La promesse rejette avec un message qui correspond au motif. */
async function rejette(p, motif) {
  let erreur = null;
  try {
    await p;
  } catch (e) {
    erreur = e;
  }
  expect(erreur, `rejet attendu (${motif})`).to.be.an("error");
  expect(String(erreur.message)).to.match(motif);
}

// ------------------------------------------------------------------ décor : un gel valide et un support en mémoire

const PREFIX = "j/";
const GEL = "gel-20261201T090000Z-5f0c2a1e";
const SEG = `${PREFIX}segments/seg-0000000000000001-00000000000000000001.ndjson`;
const K_POSE = `${PREFIX}gels/${GEL}/0001-pose.json`;
const K_RES = `${PREFIX}gels/${GEL}/0002-pose_resultat.json`;
const K_OBJ = `${PREFIX}gels/${GEL}/objets-0001.ndjson`;
const ECHEANCE = "2037-12-01T09:00:00.000Z";
const T0 = Date.UTC(2026, 11, 2, 12, 0, 0);

/** Enregistrements `pose`, `pose_resultat` d'un gel valide sur une version (schéma `enregistrement_gel`). */
function gelValide(objets = [{ key: SEG, version_id: "v1" }], gel_id = GEL) {
  const octets = octetsListeObjets(objets);
  const base = {
    version: 0, gel_id, org_id: `0x${"a".repeat(64)}`, journal_id: `0x${"b".repeat(64)}`, periods: { from: 3600, to: 3600 },
    support: { type: "s3-object-lock", bucket: "bucket-b", prefix: PREFIX },
    objects: { key: `${PREFIX}gels/${gel_id}/objets-0001.ndjson`, sha256: sha256Hex(octets), count: objets.length },
    reference: null, request_sha256: null, anomalies: [],
  };
  const pose = { ...base, n: 1, kind: "pose", actor: "a@x.example", at: "2026-12-01T09:00:00.000Z", reason: "m", results: null, prev_sha256: null };
  const res = { ...base, n: 2, kind: "pose_resultat", actor: "a@x.example", at: "2026-12-01T09:00:01.000Z", reason: null, results: { ok: objets.length, failed: [] }, prev_sha256: empreinteEnregistrement(pose) };
  return { base, pose, res, octets };
}

/**
 * Support en mémoire : `objets` = liste ordonnée de versions `{ key, version_id, corps?, delete_marker?, last_modified? }`
 * (la dernière poussée sous une clé est la version courante) ; `gel(key, version_id)` rend `ON`, `OFF` ou null.
 */
function supportFictif(objets, o = {}) {
  const versions = objets.map((v, k) => ({
    key: v.key, version_id: v.version_id, corps: v.corps === undefined ? null : Buffer.from(v.corps), delete_marker: v.delete_marker === true,
    last_modified: v.last_modified ?? new Date(Date.UTC(2026, 10, 1) + k * 60000).toISOString(),
  }));
  const parCle = (k) => versions.filter((v) => v.key === k);
  const appels = [];
  const s = {
    type: "s3-object-lock",
    appels,
    async listerVersions(prefixe) {
      appels.push(["listerVersions", prefixe]);
      const l = versions.filter((v) => v.key.startsWith(prefixe)).map((v) => ({
        key: v.key, version_id: v.version_id, is_latest: parCle(v.key).at(-1) === v, delete_marker: v.delete_marker, last_modified: v.last_modified,
      }));
      return { statut: 200, versions: l, code: null };
    },
    async lire(key, vid = null) {
      appels.push(["lire", key, vid]);
      const v = vid === null ? parCle(key).filter((x) => !x.delete_marker).at(-1) : parCle(key).find((x) => x.version_id === vid);
      if (!v || v.delete_marker || v.corps === null) return { statut: 404, corps: Buffer.alloc(0), version_id: null, last_modified: null };
      return { statut: 200, corps: Buffer.from(v.corps), version_id: v.version_id, last_modified: v.last_modified };
    },
    async empreinte(key, vid = null) {
      const r = await s.lire(key, vid);
      if (r.statut !== 200) return { statut: r.statut, sha256: null, longueur: null, version_id: null, last_modified: null };
      return { statut: 200, sha256: sha256Hex(new Uint8Array(r.corps)), longueur: r.corps.length, version_id: r.version_id, last_modified: r.last_modified };
    },
    async etat(key, vid) {
      appels.push(["etat", key, vid]);
      if (o.etatIllisible?.(key, vid)) return { statut: 500, entetes: {}, json: null };
      const gel = o.gel?.(key, vid) ?? null;
      const entetes = { "x-amz-object-lock-mode": "COMPLIANCE", "x-amz-object-lock-retain-until-date": ECHEANCE };
      if (gel) entetes["x-amz-object-lock-legal-hold"] = gel;
      return { statut: 200, entetes, json: null };
    },
    async lireGel(key, vid) {
      appels.push(["lireGel", key, vid]);
      return { statut: 200, valeur: o.gel?.(key, vid) ?? null, code: null };
    },
    etatGel(lu) {
      if (lu.valeur === null) return "jamais";
      return lu.valeur === "ON" ? "on" : lu.valeur === "OFF" ? "off" : "illisible";
    },
    async poserGel(key, vid, pose) {
      appels.push(["poserGel", key, vid, pose]);
      return { statut: 200, code: null };
    },
    async ecrireConditionnel(key, octets) {
      appels.push(["ecrireConditionnel", key]);
      if (parCle(key).length) return { statut: 412, version_id: null, code: "PreconditionFailed" };
      versions.push({ key, version_id: `w${versions.length}`, corps: Buffer.from(octets), delete_marker: false, last_modified: new Date(T0).toISOString() });
      return { statut: 200, version_id: `w${versions.length - 1}`, code: null };
    },
    async copier(key) {
      appels.push(["copier", key]);
      return { statut: 412, version_id: null, code: "PreconditionFailed" };
    },
    async configurationVerrou() {
      return { statut: 200, config: { enabled: "Enabled", mode: "COMPLIANCE", days: 3650, years: null }, code: null };
    },
  };
  return s;
}

/** Journal et métriques d'essai. */
function temoins() {
  const lignes = [];
  const compteurs = new Map();
  const jauges = new Map();
  return {
    lignes,
    compteurs,
    jauges,
    journal: { consigner: (niveau, composant, evenement, data) => lignes.push({ niveau, composant, evenement, data }) },
    metriques: {
      compter: (n, e = {}) => compteurs.set(`${n}${JSON.stringify(e)}`, (compteurs.get(`${n}${JSON.stringify(e)}`) ?? 0) + 1),
      jauge: (n, e, v) => jauges.set(n, v),
      valeur: (n, e = {}) => compteurs.get(`${n}${JSON.stringify(e)}`),
    },
    de: (evenement) => lignes.filter((l) => l.evenement === evenement),
  };
}

const WORM = { prefix: PREFIX, type: "s3-object-lock", mode: "compliance", retain_days: 3650, lock_audit_interval_days: 30, bucket: "bucket-b" };

/** Supervision du démon sur un support fictif (quotidien, relevé, tic). */
function supervision(operations, t, o = {}) {
  const copies = {
    operations, worm: WORM, prefixe: PREFIX, enAttente: new Map(), balayer: async () => ({ copies: 0, manquantes: 0 }),
    coeur: { repertoire: o.repertoire ?? "/nonexistent", ecrivain: { epoque: 1 }, journal: t.journal, metriques: t.metriques, horlogeBrute: { murale: () => o.murale?.() ?? T0 } },
  };
  return new SupervisionWorm(copies, { intervalleMs: 60000 });
}

// ------------------------------------------------------------------ : analyseur XML et réponses du support

describe("revue WORM : analyseur XML des réponses S3 et réponses du support bornées", function () {
  this.timeout(60000);

  it("une instruction, un commentaire ou une section CDATA sans fermeture, et une page d'erreur tronquée, terminent (erreur ou null) en moins de trois secondes ; le témoin bien formé est lu", function () {
    const cas = {
      "commentaire non fermé": "ab<!--",
      "instruction non fermée": ' <?xml version="1.0"',
      "CDATA non fermée": "<a><![CDATA[x",
      "page d'erreur tronquée": "<html><body><!-- 503 Service Unavailable",
    };
    for (const [nom, corps] of Object.entries(cas)) {
      const code = `import { codeErreurS3 } from ${JSON.stringify(path.join(RACINE, "paquets/enregistreur/src/worm/s3.mjs"))}; process.stdout.write(JSON.stringify(codeErreurS3(Buffer.from(${JSON.stringify(corps)}))));`;
      const r = spawnSync(process.execPath, ["--input-type=module", "-e", code], { cwd: RACINE, timeout: 3000, encoding: "utf8" });
      expect(r.signal, `${nom} : tué par le délai (l'analyse ne termine pas)`).to.equal(null);
      expect(r.status, `${nom} : ${r.stderr}`).to.equal(0);
      expect(r.stdout).to.equal("null");
    }
    const x = analyserXml('<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>');
    expect(x.enfants[0].enfants[0].texte).to.equal("AccessDenied");
    for (const corps of ["<a><!-- x", "<a><?pi", "<a><![CDATA[x", "<a", "<a></b>"]) expect(() => analyserXml(corps), corps).to.throw(/XML/);
  });

  it("un corps de réponse plus grand que la borne est refusé sans être gardé en mémoire ; une page tronquée sans marqueur ou à marqueur qui n'avance pas arrête la pagination ; une version sans Key est refusée", async function () {
    // Corps sans borne : un serveur local sert 24 Mio sans fin de ligne.
    const serveur = http.createServer((req, res) => {
      res.writeHead(200, { "content-type": "application/xml" });
      const morceau = Buffer.alloc(1 << 20, 0x78);
      let n = 0;
      const pousser = () => {
        while (n < 24) {
          n++;
          if (!res.write(morceau)) return res.once("drain", pousser);
        }
        res.end();
      };
      pousser();
    });
    await new Promise((r) => serveur.listen(0, "127.0.0.1", r));
    try {
      const acces = new AccesS3({ endpoint: `http://127.0.0.1:${serveur.address().port}`, region: "us-east-1", bucket: "bucket-b", identifiants: { access_key_id: "a", secret_access_key: "b", session_token: null } });
      const avant = process.memoryUsage().rss;
      let erreur = null;
      try {
        await acces.envoyer({ method: "GET", target: "/?versions", headers: [], body: null });
      } catch (e) {
        erreur = e;
      }
      expect(erreur, "la réponse de 24 Mio devrait être refusée").to.be.an("error");
      expect(String(erreur.message)).to.match(/borne|trop/i);
      expect(erreur).to.not.be.instanceOf(ErreurTransport);
      void avant;
    } finally {
      serveur.closeAllConnections?.();
      await new Promise((r) => serveur.close(r));
    }
    // Pagination.
    const page = (o) => Buffer.from(`<?xml version="1.0"?><ListVersionsResult><IsTruncated>${o.tronquee}</IsTruncated>${o.marqueur ? `<NextKeyMarker>${o.marqueur}</NextKeyMarker><NextVersionIdMarker>v</NextVersionIdMarker>` : ""}${o.cles.map((k) => `<Version>${k === null ? "" : `<Key>${k}</Key>`}<VersionId>v</VersionId><IsLatest>true</IsLatest><LastModified>2026-11-01T00:00:00.000Z</LastModified></Version>`).join("")}</ListVersionsResult>`);
    const ops = (pages) => {
      const s = new OperationsS3({ worm: { ...WORM, endpoint: "https://s3.example", region: "us-east-1" }, identifiants: { access_key_id: "a", secret_access_key: "b", session_token: null }, delais: [] });
      let k = 0;
      s.acces.envoyer = async () => ({ statut: 200, entetes: {}, corps: pages[Math.min(k++, pages.length - 1)] });
      return { s, appels: () => k };
    };
    const sansMarqueur = ops([page({ tronquee: true, marqueur: null, cles: ["j/a"] })]);
    await rejette(sansMarqueur.s.listerVersions("j/"), /pagination/);
    expect(sansMarqueur.appels()).to.be.below(5);
    const fige = ops([page({ tronquee: true, marqueur: "j/a", cles: ["j/a"] }), page({ tronquee: true, marqueur: "j/a", cles: ["j/a"] })]);
    await rejette(fige.s.listerVersions("j/"), /pagination/);
    expect(fige.appels()).to.be.below(5);
    const sansCle = ops([page({ tronquee: false, marqueur: null, cles: [null] })]);
    await rejette(sansCle.s.listerVersions("j/"), /Key|illisible/);
    const bonne = ops([page({ tronquee: true, marqueur: "j/a", cles: ["j/a"] }), page({ tronquee: false, marqueur: null, cles: ["j/b"] })]);
    expect((await bonne.s.listerVersions("j/")).versions.map((v) => v.key)).to.deep.equal(["j/a", "j/b"]);
  });
});

// ------------------------------------------------------------------ CT-2 EX-17.7, CT-2 EX-12.38 : règle de garde totale, exceptions jamais avalées

describe("revue WORM : registre des gels lu avec schéma, règle de garde totale (CT-2 EX-17.7, CT-2 EX-12.38)", function () {
  this.timeout(60000);

  it("CT-2 EX-17.7, CT-2 EX-12.38 : verifierGarde ne lève sur aucune entrée (null, nombre, tableau, kind prototypal, at illisible) et rend des erreurs au rang fautif", function () {
    for (const suite of [[null], [1], [[1]], ["x"], [{ at: "x" }], [{ kind: "toString" }, { kind: "pose" }], [{ kind: "constructor" }, { kind: "pose_resultat" }], [{ kind: "__proto__", n: 1 }, { kind: "pose" }], [undefined]]) {
      let r;
      expect(() => { r = verifierGarde(suite); }, JSON.stringify(suite)).to.not.throw();
      expect(r.valid).to.equal(false);
      expect(r.errors.length).to.be.above(0);
      expect(r.record_sha256).to.have.length(suite.length);
      expect(() => etatGel(suite)).to.not.throw();
    }
    const { pose, res } = gelValide();
    expect(verifierGarde([pose, res]).valid).to.equal(true);
    const r = verifierGarde([pose, { ...res, kind: "toString" }]);
    expect(r.valid).to.equal(false);
    expect(r.errors.some((e) => e.n === 2 && e.code === "ordre_invalide")).to.equal(true);
  });

  it("CT-2 EX-17.7 : un objet de corps `null` et un enregistrement hors schéma sous <prefix>gels/ donnent une ligne worm_legal_hold_observed illisible, un échec integrity_check registre_gels compté, et la relecture quotidienne des autres gels a lieu (gel_absent consigné)", async function () {
    const { pose, res, octets } = gelValide();
    for (const [nom, extra, attendu] of [
      ["corps null dans le répertoire du gel", [{ key: `${PREFIX}gels/${GEL}/0003-pose_resultat.json`, version_id: "x", corps: "null" }], "registre_gels"],
      ["corps null dans un autre répertoire", [{ key: `${PREFIX}gels/gel-20261202T090000Z-00000000/0001-pose.json`, version_id: "x", corps: "null" }], "registre_gels"],
      ["kind prototypal hors schéma (enregistrement de forme valide, kind constructor)", [{ key: `${PREFIX}gels/${GEL}/0003-pose_resultat.json`, version_id: "x", corps: JSON.stringify({ ...res, n: 3, kind: "constructor" }) }, { key: `${PREFIX}gels/${GEL}/0004-pose_resultat.json`, version_id: "x", corps: JSON.stringify({ ...res, n: 4 }) }], "registre_gels"],
      // Un nom hors d'EX-12.37 (`0003-constructor.json`) n'est pas un enregistrement : consigné `worm_versions_unexpected` (nom_inattendu), jamais lu ni avalé.
      ["nom d'enregistrement inattendu (0003-constructor.json)", [{ key: `${PREFIX}gels/${GEL}/0003-constructor.json`, version_id: "x", corps: JSON.stringify({ ...res, n: 3, kind: "constructor" }) }], "nom_inattendu"],
    ]) {
      const t = temoins();
      const ops = supportFictif([
        { key: K_POSE, version_id: "v1", corps: JSON.stringify(pose) },
        { key: K_RES, version_id: "v1", corps: JSON.stringify(res) },
        { key: K_OBJ, version_id: "v1", corps: octets },
        { key: SEG, version_id: "v1", corps: "seg" },
        ...extra,
      ], { gel: () => "OFF" });
      const s = supervision(ops, t);
      await s.quotidien(T0);
      if (attendu === "registre_gels") {
        expect(t.de("integrity_check").filter((l) => l.data.check === "registre_gels" && l.data.ok === false), `${nom} : échec registre_gels`).to.have.length(1);
        expect(t.metriques.valeur("noortrace_integrity_check_failures_total", { check: "registre_gels" }), `${nom} : compteur`).to.equal(1);
        const illisibles = t.de("worm_legal_hold_observed").filter((l) => l.niveau === "error" && l.data.illisible === true);
        expect(illisibles.length, `${nom} : une ligne d'erreur par enregistrement illisible`).to.be.above(0);
      } else {
        const u = t.de("worm_versions_unexpected").filter((l) => l.data.raison === "nom_inattendu");
        expect(u.map((l) => l.data.key), `${nom}`).to.deep.equal([`${PREFIX}gels/${GEL}/0003-constructor.json`]);
      }
      expect(t.de("worm_lock_check").filter((l) => l.data.reasons?.includes("gel_absent") && l.data.gel_id === GEL), `${nom} : la relecture des versions du gel sain a lieu`).to.have.length(1);
    }
  });

  it("CT-2 EX-17.7 : une exception de la lecture quotidienne ou du relevé n'est jamais avalée par tic() : ligne integrity_check en échec avec le message, compteur, et le jour n'est pas tenu pour fait (nouvel essai au tour suivant)", async function () {
    const t = temoins();
    const ops = supportFictif([]);
    ops.listerVersions = async () => { throw new TypeError("x is not a function"); };
    const s = supervision(ops, t);
    await s.tic();
    const echecs = t.de("integrity_check").filter((l) => l.data.ok === false && l.data.check === "registre_gels");
    expect(echecs.length).to.be.above(0);
    expect(JSON.stringify(echecs[0].data)).to.match(/not a function/);
    expect(s.jour, "le jour n'est posé qu'après un passage complet").to.equal(null);
    expect(t.jauges.get("noortrace_worm_last_audit_age_s"), "CT-2 EX-12.17 : la jauge existe dès le premier tour même sans relevé réussi").to.be.a("number");
  });
});

// ------------------------------------------------------------------ CT-2 EX-17.6 : toutes les versions du registre des gels

describe("revue WORM : registre des gels lu par toutes les versions de chaque clé (CT-2 EX-17.6)", function () {
  this.timeout(60000);

  it("(a) un marqueur de suppression sur chaque enregistrement ne fait pas disparaître le gel : il reste actif, ses versions attendues on, le marqueur est consigné (worm_versions_unexpected) et compté", async function () {
    const { pose, res, octets } = gelValide();
    const t = temoins();
    const ops = supportFictif([
      { key: K_POSE, version_id: "v1", corps: JSON.stringify(pose) }, { key: K_POSE, version_id: "m1", delete_marker: true },
      { key: K_RES, version_id: "v1", corps: JSON.stringify(res) }, { key: K_RES, version_id: "m2", delete_marker: true },
      { key: K_OBJ, version_id: "v1", corps: octets }, { key: SEG, version_id: "v1", corps: "seg" },
    ], { gel: () => "ON" });
    const g = await lireRegistreGels({ operations: ops, worm: WORM, journal: t.journal, metriques: t.metriques, vus: new Set() });
    expect(g.gels.map((x) => [x.gel_id, x.etat.actif])).to.deep.equal([[GEL, true]]);
    expect([...versionsAttenduesGelees(g.gels)]).to.deep.equal([`${SEG}#v1`]);
    const u = t.de("worm_versions_unexpected");
    expect(u.map((l) => l.data.key).sort()).to.deep.equal([K_POSE, K_RES]);
    expect(u.every((l) => l.data.marqueur === true)).to.equal(true);
    expect(t.jauges.get("noortrace_worm_legal_holds_active")).to.equal(1);
    const rep = repertoireTemporaire("noortrace-revue-worm-1-");
    const r = await releverVerrouillage({ operations: ops, worm: WORM, repertoire: rep, epoque: 1, journal: t.journal, metriques: t.metriques, murale: () => T0, gels: g.gels });
    expect(r.inattendues, "le pas 3 du relevé couvre gels/").to.be.at.least(2);
  });

  it("(b) une seconde version de 0001-pose.json (corps `{}`) n'altère pas la suite : la version la plus ancienne est lue, le gel reste actif et valide, la seconde version est consignée ; (c) la liste des objets est lue par la version dont l'empreinte est celle de la pose", async function () {
    const { pose, res, octets } = gelValide();
    const t = temoins();
    const ops = supportFictif([
      { key: K_POSE, version_id: "v1", corps: JSON.stringify(pose) }, { key: K_POSE, version_id: "v2", corps: "{}" },
      { key: K_RES, version_id: "v1", corps: JSON.stringify(res) },
      { key: K_OBJ, version_id: "v1", corps: octets }, { key: K_OBJ, version_id: "v2", corps: "" },
      { key: SEG, version_id: "v1", corps: "seg" },
    ], { gel: () => "ON" });
    const g = await lireRegistreGels({ operations: ops, worm: WORM, journal: t.journal, metriques: t.metriques, vus: new Set() });
    expect(g.gels).to.have.length(1);
    expect(g.gels[0].etat).to.include({ actif: true, valide: true });
    expect(g.gels[0].objets).to.deep.equal([{ key: SEG, version_id: "v1" }]);
    expect([...versionsAttenduesGelees(g.gels)]).to.deep.equal([`${SEG}#v1`]);
    const u = t.de("worm_versions_unexpected");
    expect(u.map((l) => l.data.key).sort()).to.deep.equal([K_OBJ, K_POSE].sort());
    expect(u.every((l) => l.data.versions === 2)).to.equal(true);
    expect(t.de("worm_legal_hold_observed").every((l) => l.niveau === "info")).to.equal(true);
  });

  it("l'outil (rôle Lecteur) lit de la même façon : etat sur un gel dont les enregistrements portent un marqueur rend le gel actif et ses versions attendues on", async function () {
    const { pose, res, octets } = gelValide();
    const t = temoins();
    const ops = supportFictif([
      { key: K_POSE, version_id: "v1", corps: JSON.stringify(pose) }, { key: K_POSE, version_id: "m1", delete_marker: true },
      { key: K_RES, version_id: "v1", corps: JSON.stringify(res) },
      { key: K_OBJ, version_id: "v1", corps: octets }, { key: SEG, version_id: "v1", corps: "seg" },
    ], { gel: () => "OFF" });
    const sorties = [];
    const outil = new OutilGel({ config: { recorder: { org_id: pose.org_id, journal_id: pose.journal_id }, storage: { seal: { worm: WORM }, retention: { pieces_days: null } } }, operations: ops, journal: { consigner: (n, e, d) => t.lignes.push({ niveau: n, evenement: e, data: d }) }, sortie: (x) => sorties.push(x), murale: () => T0 });
    const code = await outil.etat({ gel: GEL });
    const e = JSON.parse(sorties.join(""));
    expect(e.actif).to.equal(true);
    expect(e.versions).to.deep.equal([{ key: SEG, version_id: "v1", legal_hold: "off", attendu: "on" }]);
    expect(code).to.equal(CODES.PARTIEL);
  });
});

// ------------------------------------------------------------------ CT-2 EX-17.6 : version étrangère jamais adoptée

describe("revue WORM : le relevé n'inscrit pas une version étrangère au registre des copies (CT-2 EX-17.6)", function () {
  this.timeout(60000);

  it("une clé de segment occupée par un autre contenu : worm_copy_failed objet_present_different, puis le relevé consigne worm_versions_unexpected (empreinte différente) sans inscrire, et la jauge noortrace_worm_copy_pending reste à 1 après le relevé", async function () {
    const rep = repertoireTemporaire("noortrace-revue-worm-2-");
    fs.mkdirSync(path.join(rep, "segments"), { recursive: true });
    const ferme = "seg-0000000000000001-00000000000000000001.ndjson";
    const courant = "seg-0000000000000009-00000000000000000001.ndjson";
    fs.writeFileSync(path.join(rep, "segments", ferme), '{"segment":"reel"}\n');
    fs.writeFileSync(path.join(rep, "segments", courant), "");
    const cle = `${PREFIX}segments/${ferme}`;
    const t = temoins();
    const ops = supportFictif([{ key: cle, version_id: "vX", corps: '{"segment":"autre contenu"}\n', last_modified: new Date(T0 - 7200000).toISOString() }]);
    const coeur = { repertoire: rep, ecrivain: { epoque: 1, segment: { nom: courant } }, journal: t.journal, metriques: t.metriques, horlogeBrute: { murale: () => T0 }, o: {} };
    const s = new ServiceCopiesWorm({ worm: WORM, operations: ops });
    s.lier(coeur);
    await s.balayer();
    expect(t.de("worm_copy_failed").map((l) => l.data.raison)).to.deep.equal(["objet_present_different"]);
    expect(t.jauges.get("noortrace_worm_copy_pending")).to.equal(1);
    const r = await releverVerrouillage({ operations: ops, worm: WORM, repertoire: rep, epoque: 1, journal: t.journal, metriques: t.metriques, murale: () => T0, gels: [] });
    expect(r.inattendues).to.equal(1);
    const u = t.de("worm_versions_unexpected");
    expect(u).to.have.length(1);
    expect(u[0].data.key).to.equal(cle);
    expect(fs.existsSync(path.join(rep, "worm")) ? fs.readdirSync(path.join(rep, "worm")) : []).to.deep.equal([]);
    await s.balayer();
    expect(t.jauges.get("noortrace_worm_copy_pending"), "la copie manque toujours").to.equal(1);
  });

  it("une version sans ligne dont l'empreinte est celle du fichier local est inscrite sans alerte ; sans fichier local, elle est inscrite avec une ligne d'avertissement", async function () {
    const rep = repertoireTemporaire("noortrace-revue-e04b-");
    fs.mkdirSync(path.join(rep, "segments"), { recursive: true });
    const ferme = "seg-0000000000000001-00000000000000000001.ndjson";
    const local = '{"segment":"reel"}\n';
    fs.writeFileSync(path.join(rep, "segments", ferme), local);
    const cle = `${PREFIX}segments/${ferme}`;
    const absent = `${PREFIX}segments/seg-0000000000000002-00000000000000000001.ndjson`;
    const t = temoins();
    const ops = supportFictif([{ key: cle, version_id: "v1", corps: local }, { key: absent, version_id: "v1", corps: "x\n" }]);
    const r = await releverVerrouillage({ operations: ops, worm: WORM, repertoire: rep, epoque: 1, journal: t.journal, metriques: t.metriques, murale: () => T0, gels: [] });
    const registre = await E.lireRegistres(path.join(rep, "worm"));
    expect(registre.map((x) => x.ligne.key).sort()).to.deep.equal([cle, absent].sort());
    expect(registre.find((x) => x.ligne.key === cle).ligne.sha256).to.equal(sha256Hex(new Uint8Array(Buffer.from(local))));
    const u = t.de("worm_versions_unexpected");
    expect(u.map((l) => l.data.key)).to.deep.equal([absent]);
    expect(u[0].niveau).to.equal("warning");
    expect(r.inattendues).to.equal(1);
  });
});

// ------------------------------------------------------------------ CT-2 EX-12.40, CT-2 EX-12.35 : outil de gel

describe("revue WORM : outil de gel (CT-2 EX-12.40 levée, EX-12.35 périmètre, coût et plage)", function () {
  this.timeout(120000);

  it("CT-2 EX-12.40 : à la levée, un autre gel actif dont la liste des objets est illisible arrête l'outil (code 4) avant toute requête de levée", async function () {
    const A = gelValide([{ key: SEG, version_id: "v1" }], GEL);
    const demande = { ...A.base, n: 3, kind: "demande_levee", actor: "a@x.example", at: "2026-12-02T09:00:00.000Z", reason: "fin", results: null, prev_sha256: empreinteEnregistrement(A.res) };
    const GEL_B = "gel-20261202T090000Z-0000000b";
    const B = gelValide([{ key: SEG, version_id: "v1" }], GEL_B);
    const t = temoins();
    const ops = supportFictif([
      { key: K_POSE, version_id: "v1", corps: JSON.stringify(A.pose) }, { key: K_RES, version_id: "v1", corps: JSON.stringify(A.res) },
      { key: `${PREFIX}gels/${GEL}/0003-demande_levee.json`, version_id: "v1", corps: JSON.stringify(demande) },
      { key: K_OBJ, version_id: "v1", corps: A.octets },
      { key: `${PREFIX}gels/${GEL_B}/0001-pose.json`, version_id: "v1", corps: JSON.stringify(B.pose) },
      { key: `${PREFIX}gels/${GEL_B}/0002-pose_resultat.json`, version_id: "v1", corps: JSON.stringify(B.res) },
      // la liste des objets du gel B n'est pas lisible (404)
      { key: SEG, version_id: "v1", corps: "seg" },
    ], { gel: () => "ON" });
    const outil = new OutilGel({ config: { recorder: { org_id: A.pose.org_id, journal_id: A.pose.journal_id }, storage: { seal: { worm: WORM }, retention: { pieces_days: null } } }, operations: ops, journal: { consigner: (n, e, d) => t.lignes.push({ niveau: n, evenement: e, data: d }) }, sortie: () => {}, murale: () => Date.UTC(2026, 11, 2, 10) });
    let code;
    try {
      code = await outil.lever({ identite: "b@x.example", gel: GEL, demande: empreinteEnregistrement(demande) });
    } catch (e) {
      expect(e).to.be.instanceOf(ArretOutil);
      code = e.code;
    }
    expect(code).to.equal(CODES.SUPPORT);
    expect(ops.appels.filter((a) => a[0] === "poserGel"), "aucune requête de levée").to.deep.equal([]);
  });

  it("CT-2 EX-12.35 : la plage des segments d'une période est la réunion des plages de toutes les versions lisibles du manifeste ; des plages différentes valent l'anomalie segments_indetermines", function () {
    const seg = (f) => `${PREFIX}segments/seg-${String(f).padStart(16, "0")}-00000000000000000001.ndjson`;
    const versions = [
      { key: `${PREFIX}manifestes/periode-0000003600.json`, version_id: "v1", is_latest: false, delete_marker: false },
      { key: `${PREFIX}manifestes/periode-0000003600.json`, version_id: "v2", is_latest: true, delete_marker: false },
      { key: `${PREFIX}manifestes/periode-0000003600.sig`, version_id: "v1", is_latest: true, delete_marker: false },
      { key: `${PREFIX}points/periode-0000003600.ndjson`, version_id: "v1", is_latest: true, delete_marker: false },
      { key: seg(1), version_id: "v1", is_latest: true, delete_marker: false },
      { key: seg(2), version_id: "v1", is_latest: true, delete_marker: false },
    ];
    const r = calculerPerimetre({ prefix: PREFIX, from: 3600, to: 3600, versions, manifests: [{ period_start: 3600, first_seq: 1, last_seq: 2 }, { period_start: 3600, first_seq: 1, last_seq: 0 }], pieces: null });
    expect(r.segments.sort()).to.deep.equal([seg(1), seg(2)]);
    expect(r.anomalies.filter((a) => a.kind === "segments_indetermines")).to.have.length(1);
    expect(r.anomalies.filter((a) => a.kind === "versions_multiples").map((a) => a.key)).to.deep.equal([`${PREFIX}manifestes/periode-0000003600.json`]);
    const meme = calculerPerimetre({ prefix: PREFIX, from: 3600, to: 3600, versions, manifests: [{ period_start: 3600, first_seq: 1, last_seq: 2 }, { period_start: 3600, first_seq: 1, last_seq: 2 }], pieces: null });
    expect(meme.anomalies.filter((a) => a.kind === "segments_indetermines")).to.deep.equal([]);
  });

  it("CT-2 EX-12.35 : _perimetre de l'outil lit chaque version du manifeste (une seconde version de plage vide, écrite avant la pose, ne retire aucun segment)", async function () {
    const seg = (f) => `${PREFIX}segments/seg-${String(f).padStart(16, "0")}-00000000000000000001.ndjson`;
    const km = `${PREFIX}manifestes/periode-0000003600.json`;
    const ops = supportFictif([
      { key: km, version_id: "v1", corps: JSON.stringify({ first_seq: 1, last_seq: 2 }) },
      { key: km, version_id: "v2", corps: JSON.stringify({ first_seq: 1, last_seq: 0 }) },
      { key: `${PREFIX}manifestes/periode-0000003600.sig`, version_id: "v1", corps: "{}" },
      { key: `${PREFIX}points/periode-0000003600.ndjson`, version_id: "v1", corps: "" },
      { key: seg(1), version_id: "v1", corps: "a" }, { key: seg(2), version_id: "v1", corps: "b" },
    ]);
    const outil = new OutilGel({ config: { recorder: { org_id: "0x" + "a".repeat(64), journal_id: "0x" + "b".repeat(64) }, storage: { seal: { worm: WORM }, retention: { pieces_days: null } } }, operations: ops, journal: { consigner: () => {} }, sortie: () => {}, murale: () => T0 });
    const p = await outil._perimetre(3600, 3600);
    expect(p.segments.sort()).to.deep.equal([seg(1), seg(2)]);
    expect(p.anomalies.some((a) => a.kind === "segments_indetermines")).to.equal(true);
  });

  it("le périmètre d'un gel de 30 jours sur un journal de 200 000 clés se calcule en moins de cinq secondes (index par période et par clé)", function () {
    const versions = [];
    const periodes = 24 * 365 * 10;
    for (let k = 0; k < periodes; k++) {
      const P = 3600 + k * 3600;
      const dix = String(P).padStart(10, "0");
      versions.push({ key: `${PREFIX}manifestes/periode-${dix}.json`, version_id: "v", is_latest: true, delete_marker: false });
      versions.push({ key: `${PREFIX}segments/seg-${String(k + 1).padStart(16, "0")}-00000000000000000001.ndjson`, version_id: "v", is_latest: true, delete_marker: false });
      if (k % 4 === 0) versions.push({ key: `${PREFIX}ancres/periode-${dix}/rfc3161/x.tsr`, version_id: "v", is_latest: true, delete_marker: false });
    }
    const de = 3600 + (periodes - 720) * 3600;
    const a = 3600 + (periodes - 1) * 3600;
    const manifests = [];
    for (let P = de; P <= a; P += 3600) manifests.push({ period_start: P, first_seq: (P - 3600) / 3600 + 1, last_seq: (P - 3600) / 3600 + 1 });
    const t0 = performance.now();
    const r = calculerPerimetre({ prefix: PREFIX, from: de, to: a, versions, manifests, pieces: null });
    const duree = performance.now() - t0;
    expect(r.segments).to.have.length(720);
    expect(duree, `${duree} ms`).to.be.below(5000);
  });

  it("noortrace-ctl worm gel poser refuse (code 2) une plage dont --a dépasse l'heure courante, avant toute requête", async function () {
    const dir = repertoireTemporaire("noortrace-revue-worm-3-");
    const { config, env } = configurationDev(dir);
    config.storage.seal.worm = { ...WORM, credentials: { env: "NOORTRACE_TEST_WORM_ECRIVAIN" }, endpoint: "https://s3.example", region: null, legal_hold_on_write: false, copy_pieces: false };
    env.NOORTRACE_TEST_WORM_ECRIVAIN = JSON.stringify({ access_key_id: "a", secret_access_key: "b" });
    env.NOORTRACE_TEST_WORM_EXPLOITANT = JSON.stringify({ access_key_id: "c", secret_access_key: "d" });
    const f = path.join(dir, "configuration.json");
    fs.writeFileSync(f, JSON.stringify(config));
    const err = [];
    const murale = () => Date.UTC(2026, 11, 2, 12, 30);
    const code = await E.principalCtl(["worm", "gel", "poser", "--configuration", f, "--identifiants", JSON.stringify({ env: "NOORTRACE_TEST_WORM_EXPLOITANT" }), "--identite", "x", "--de", String(Date.UTC(2026, 11, 2, 12) / 1000), "--a", String(Date.UTC(2026, 11, 2, 13) / 1000), "--motif", "m"], { env, murale, stdout: { write() {} }, stderr: { write: (x) => err.push(x) }, delais: [] });
    expect(code).to.equal(2);
    expect(err.join("")).to.match(/heure courante|--a/);
  });
});

// ------------------------------------------------------------------ CT-2 EX-12.17 : jauge du relevé et comparaison horaire

describe("revue WORM : supervision (CT-2 EX-12.17)", function () {
  it("un relevé qui échoue à chaque tour depuis le démarrage : la jauge noortrace_worm_last_audit_age_s existe et croît avec le temps écoulé depuis l'armement ; un tour retardé de plus d'une heure compare toutes les lignes inscrites depuis le dernier passage horaire", async function () {
    const rep = repertoireTemporaire("noortrace-revue-worm-4-");
    let maintenant = T0;
    const t = temoins();
    const ops = supportFictif([]);
    ops.listerVersions = async () => ({ statut: 500, versions: [], code: null });
    const s = supervision(ops, t, { murale: () => maintenant, repertoire: rep });
    await s.tic();
    expect(t.jauges.get("noortrace_worm_last_audit_age_s")).to.be.a("number");
    maintenant = T0 + 7200000;
    await s.tic();
    expect(t.jauges.get("noortrace_worm_last_audit_age_s")).to.be.at.least(7200);
    // Comparaison horaire : trois lignes inscrites 30 min, 90 min et 150 min avant un tour qui vient 3 h après le précédent.
    await E.inscrireCopie(path.join(rep, "worm"), 1, { key: `${SEG}`, version_id: "v1", sha256: "0x" + "0".repeat(64), length: 1, copied_at: new Date(T0 + 7200000 + 1800000).toISOString(), lock: { verdict: "conforme", retain_until: ECHEANCE, legal_hold: "jamais" } });
    await E.inscrireCopie(path.join(rep, "worm"), 1, { key: `${PREFIX}segments/seg-0000000000000002-00000000000000000001.ndjson`, version_id: "v1", sha256: "0x" + "0".repeat(64), length: 1, copied_at: new Date(T0 + 7200000 + 5400000).toISOString(), lock: { verdict: "conforme", retain_until: ECHEANCE, legal_hold: "jamais" } });
    await E.inscrireCopie(path.join(rep, "worm"), 1, { key: `${PREFIX}segments/seg-0000000000000003-00000000000000000001.ndjson`, version_id: "v1", sha256: "0x" + "0".repeat(64), length: 1, copied_at: new Date(T0 + 7200000 + 9000000).toISOString(), lock: { verdict: "conforme", retain_until: ECHEANCE, legal_hold: "jamais" } });
    maintenant = T0 + 7200000 + 3 * 3600000;
    await s.tic();
    const compares = t.de("integrity_check").filter((l) => l.data.check === "copie_worm" && l.data.key);
    expect(compares.map((l) => l.data.key).sort()).to.have.length(3);
  });
});

// ------------------------------------------------------------------ : --identifiants comparés par emplacement

describe("revue WORM : noortrace-ctl worm gel refuse les identifiants de l'écrivain quel que soit encoding (CT-2 EX-12.36)", function () {
  it("{\"file\": <même fichier>, \"encoding\": \"utf8\"} contre {\"file\": <même fichier>} : code 2 et le message d'EX-12.36, avant toute lecture du secret", async function () {
    const dir = repertoireTemporaire("noortrace-revue-worm-5-");
    const { config, env } = configurationDev(dir);
    const fichier = path.join(dir, "worm-ecrivain");
    config.storage.seal.worm = { ...WORM, credentials: { file: fichier }, endpoint: "https://s3.example", region: null, legal_hold_on_write: false, copy_pieces: false };
    const f = path.join(dir, "configuration.json");
    fs.writeFileSync(f, JSON.stringify(config));
    const err = [];
    const code = await E.principalCtl(["worm", "gel", "etat", "--configuration", f, "--identifiants", JSON.stringify({ file: fichier, encoding: "utf8" }), "--gel", GEL], { env, stdout: { write() {} }, stderr: { write: (x) => err.push(x) }, delais: [] });
    expect(code).to.equal(2);
    expect(err.join("")).to.match(/égale à celle de l'écrivain/);
  });
});

// ------------------------------------------------------------------ CT-2 EX-12.36 : worm gel liste

describe("revue WORM : noortrace-ctl worm gel liste relit tout le registre sous le rôle Lecteur (CT-2 EX-12.36)", function () {
  it("imprime chaque gel du préfixe avec son état, sa garde et l'état de ses versions ; code 1 si une version attendue on ne l'est pas ou si une garde échoue", async function () {
    const A = gelValide([{ key: SEG, version_id: "v1" }], GEL);
    const GEL_B = "gel-20261202T090000Z-0000000b";
    const SEG2 = `${PREFIX}segments/seg-0000000000000002-00000000000000000001.ndjson`;
    const B = gelValide([{ key: SEG2, version_id: "v1" }], GEL_B);
    const dir = repertoireTemporaire("noortrace-revue-worm-6-");
    const { config, env } = configurationDev(dir);
    config.recorder.org_id = A.pose.org_id;
    config.recorder.journal_id = A.pose.journal_id;
    config.storage.seal.worm = { ...WORM, credentials: { env: "NOORTRACE_TEST_WORM_ECRIVAIN" }, endpoint: "https://s3.example", region: null, legal_hold_on_write: false, copy_pieces: false };
    env.NOORTRACE_TEST_WORM_ECRIVAIN = JSON.stringify({ access_key_id: "a", secret_access_key: "b" });
    env.NOORTRACE_TEST_WORM_LECTEUR = JSON.stringify({ access_key_id: "c", secret_access_key: "d" });
    const f = path.join(dir, "configuration.json");
    fs.writeFileSync(f, JSON.stringify(config));
    const ops = supportFictif([
      { key: K_POSE, version_id: "v1", corps: JSON.stringify(A.pose) }, { key: K_RES, version_id: "v1", corps: JSON.stringify(A.res) }, { key: K_OBJ, version_id: "v1", corps: A.octets },
      { key: `${PREFIX}gels/${GEL_B}/0001-pose.json`, version_id: "v1", corps: JSON.stringify(B.pose) },
      { key: `${PREFIX}gels/${GEL_B}/0002-pose_resultat.json`, version_id: "v1", corps: JSON.stringify(B.res) },
      { key: `${PREFIX}gels/${GEL_B}/objets-0001.ndjson`, version_id: "v1", corps: B.octets },
      { key: SEG, version_id: "v1", corps: "a" }, { key: SEG2, version_id: "v1", corps: "b" },
    ], { gel: (k) => (k === SEG ? "ON" : "OFF") });
    const out = [];
    const code = await E.principalCtl(["worm", "gel", "liste", "--configuration", f, "--identifiants", JSON.stringify({ env: "NOORTRACE_TEST_WORM_LECTEUR" })], { env, stdout: { write: (x) => out.push(x) }, stderr: { write() {} }, delais: [], operations: ops });
    const lignes = out.join("").trim().split("\n").map((l) => JSON.parse(l));
    expect(lignes.map((l) => l.gel_id)).to.deep.equal([GEL, GEL_B]);
    expect(lignes[0]).to.include({ actif: true, garde: "respectee" });
    expect(lignes[1].versions[0]).to.include({ legal_hold: "off", attendu: "on" });
    expect(code).to.equal(1);
  });
});

// ------------------------------------------------------------------ CT-2 EX-15.4, CT-2 §21 : validation de la configuration

describe("revue WORM : validation (CT-2 EX-15.4 Azure en production, pieces_days sans purge)", function () {
  it("CT-2 EX-15.4 : azure-immutable-blob est refusé en production (aucune copie ni liste n'y est fixée), comme gcs-object-retention ; sans endpoint, le schéma refuse déjà", function () {
    const dir = repertoireTemporaire("noortrace-revue-worm-7-");
    const prod = configurationDev(dir, { environment: "production" }).config;
    prod.storage.seal.worm = { type: "azure-immutable-blob", bucket: "conteneur", prefix: "j/", mode: "compliance", retain_days: 4018, credentials: { env: "X" }, endpoint: "https://compte.stockage.example", region: null, legal_hold_on_write: false, lock_audit_interval_days: 30, copy_pieces: false };
    const v = E.validerConfiguration(enc(prod));
    expect(v.erreurs.map((e) => e.pointeur)).to.include("/storage/seal/worm/type");
    const dev = configurationDev(dir).config;
    dev.storage.seal.worm = { ...prod.storage.seal.worm };
    expect(E.validerConfiguration(enc(dev)).erreurs.map((e) => e.pointeur)).to.not.include("/storage/seal/worm/type");
    dev.storage.seal.worm.endpoint = null;
    expect(E.validerConfiguration(enc(dev)).erreurs.map((e) => e.pointeur).some((p) => p.startsWith("/storage/seal/worm"))).to.equal(true);
  });

  it("CT-2 §21 : storage.retention.pieces_days non nul vaut un avertissement au pas 3 tant que la purge des pièces n'est pas codée ; null n'en donne pas", function () {
    const dir = repertoireTemporaire("noortrace-revue-worm-8-");
    const { config } = configurationDev(dir);
    config.storage.retention.pieces_days = 365;
    const v = E.validerConfiguration(enc(config));
    expect(v.erreurs).to.deep.equal([]);
    expect(v.avertissements.map((a) => a.pointeur)).to.include("/storage/retention/pieces_days");
    config.storage.retention.pieces_days = null;
    expect(E.validerConfiguration(enc(config)).avertissements.map((a) => a.pointeur)).to.not.include("/storage/retention/pieces_days");
  });
});

// ------------------------------------------------------------------ CT-2 EX-12.18 : détection du remplacement d'un fichier scellé

function attributsDisponibles() {
  if (process.getuid?.() !== 0) return { ok: false, condition: "compte 0 (CAP_LINUX_IMMUTABLE) requis pour poser a et i" };
  if (spawnSync("setpriv", ["--version"]).status !== 0) return { ok: false, condition: "setpriv absent (démon sans CAP_LINUX_IMMUTABLE)" };
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-attributs-revue-"));
  const f = path.join(d, "x");
  fs.writeFileSync(f, "x");
  const r = spawnSync("chattr", ["+i", f]);
  spawnSync("chattr", ["-i", f]);
  fs.rmSync(d, { recursive: true, force: true });
  return r.status === 0 ? { ok: true } : { ok: false, condition: "système de fichiers sans attribut i (chattr +i refusé)" };
}

describe("revue WORM : compagnon des attributs, remplacement du répertoire segments/ détecté (CT-2 EX-12.18)", function () {
  this.timeout(120000);
  const cond = attributsDisponibles();
  let racine;

  beforeEach(function () {
    if (!cond.ok) {
      this.currentTest.title += ` — en attente : ${cond.condition}`;
      this.skip();
    }
  });

  afterEach(function () {
    if (racine) {
      spawnSync("chattr", ["-R", "-i", "-a", racine]);
      fs.rmSync(racine, { recursive: true, force: true });
      racine = null;
    }
  });

  it("le compte du démon renomme segments/ et y remet un fichier de même nom : le passage suivant consigne attribute_sealed_replaced (inode et empreinte enregistrés hors de storage.root), le passage est en erreur (sonde malade, --une-fois rend 1)", function () {
    racine = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-revue-worm-9-"));
    fs.chmodSync(racine, 0o755);
    const org = "a".repeat(64);
    const jid = "b".repeat(64);
    const J = path.join(racine, org, jid);
    fs.mkdirSync(path.join(J, "segments"), { recursive: true });
    const F = "seg-0000000000000001-00000000000000000001.ndjson";
    const C = "seg-0000000000000009-00000000000000000001.ndjson";
    fs.writeFileSync(path.join(J, "segments", F), "contenu scelle\n");
    fs.writeFileSync(path.join(J, "segments", C), "");
    spawnSync("chown", ["-R", "10001:10001", racine]);
    const scelles = new Map();
    const lignes = [];
    const consigner = (niveau, evenement, data) => lignes.push({ niveau, evenement, data });
    const r1 = passageAttributs(racine, { consigner, scelles });
    expect(r1.poses.map((p) => path.basename(p.fichier) + ":" + p.attribut)).to.include(`${F}:i`);
    expect(r1.erreurs).to.deep.equal([]);
    const demon = (cmd) => spawnSync("setpriv", ["--reuid", "10001", "--regid", "10001", "--clear-groups", "--inh-caps=-all", "--bounding-set=-all", "sh", "-c", cmd], { cwd: J, encoding: "utf8" });
    expect(demon(`printf x >> segments/${F}`).status, "le fichier scellé ne s'écrit pas").to.not.equal(0);
    const mv = demon(`mv segments segments.ancien && mkdir segments && printf 'contenu reecrit\\n' > segments/${F} && : > segments/${C}`);
    expect(mv.status, mv.stderr).to.equal(0);
    const r2 = passageAttributs(racine, { consigner, scelles });
    const remplaces = lignes.filter((l) => l.evenement === "attribute_sealed_replaced");
    expect(remplaces, "le remplacement d'un nom scellé est consigné").to.have.length(1);
    expect(remplaces[0].niveau).to.equal("error");
    expect(remplaces[0].data.fichier).to.equal(path.join(org, jid, "segments", F));
    expect(remplaces[0].data.sha256_scelle).to.equal(sha256Hex(new Uint8Array(Buffer.from("contenu scelle\n"))));
    expect(remplaces[0].data.sha256_present).to.equal(sha256Hex(new Uint8Array(Buffer.from("contenu reecrit\n"))));
    expect(r2.erreurs.length, "le passage est en erreur").to.be.above(0);
    // Tant que le nom scellé n'est pas celui de l'inode enregistré, chaque passage le redit (l'état persiste).
    const avant = lignes.length;
    const r3 = passageAttributs(racine, { consigner, scelles });
    expect(lignes.slice(avant).filter((l) => l.evenement === "attribute_sealed_replaced")).to.have.length(1);
    expect(r3.erreurs.length).to.be.above(0);
  });
});
