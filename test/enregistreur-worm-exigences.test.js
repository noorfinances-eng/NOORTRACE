// Lot WORM : exigences de CT-2 §12.6 (EX-12.16 à EX-12.18, EX-12.29 à
// EX-12.33), §12.11 (EX-12.34 à EX-12.41), EX-17.5 à EX-17.7 et EX-18.9, en
// réussite et en échec, contre un vrai service S3 à Object Lock (LocalStack,
// image épinglée par condensé, lancée dans Docker) derrière un mandataire TLS
// (le schéma n'admet qu'une origine HTTPS). Entrées et situations hostiles :
// copie qui échoue, support injoignable, verrou absent ou plus court que la
// rétention, seconde version et marqueur de suppression posés par un autre
// rôle, gel posé avec les identifiants de l'écrivain, levée par la même
// personne que la demande, levée après sept jours, registre des gels écrit
// hors de l'outil, gel levé hors de l'outil.
// Sans Docker, chaque cas est mis en attente et son titre nomme la condition.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as N from "@noortrace/noyau";
import {
  Coeur, validerConfiguration, resoudreSecrets, supportWormDepuisConfiguration, principalCtl, lireRegistres, ServiceCopiesWorm,
  OperationsS3, OperationsAzure, OperationsGcs, ErreurNonFixe, OutilGel, CODES_SORTIE_GEL, controleWorm, RegistreSchemasConfiguration,
  requeteS3Copie, requeteS3Lire, cleObjetWorm, lireRegistreGels, releverVerrouillage, empreinteEnregistrement, octetsEnregistrement,
  identifiantsS3, SupervisionWorm, contentMd5, controlerConfigurationVerrou,
} from "@noortrace/enregistreur";
import { configurationDev, repertoireTemporaire, SPEC } from "./fixtures/enregistreur-coeur/outils.mjs";
import {
  IMAGES, dockerDisponible, demarrerS3, arreterTout, certificats, mandataireTls, creerBucketVerrouille, identifiantsRole, fichierSecret,
} from "./fixtures/enregistreur-worm/outils.mjs";
import { SimulateurAzureGcs } from "./fixtures/enregistreur-worm/simulateur-azure-gcs.mjs";

const SCHEMA_WORM = JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", "worm-v0.schema.json"), "utf8"));
const schemas = new RegistreSchemasConfiguration();
schemas.ajouter(SCHEMA_WORM);
const valideWorm = (def, o) => schemas.valider(`${SCHEMA_WORM.$id}#/$defs/${def}`, o);
const RAPIDE = [20, 20, 20];

/** Horloge réelle décalée (murale et monotone ensemble). */
const horloge = (decalage) => ({ murale: () => Date.now() + decalage, monotone: () => performance.now() + 1e7 + decalage });
/** Décalage qui place l'horloge dans l'heure suivante, de moins d'une heure (tolérance d'EX-12.33). */
const versHeureSuivante = () => 3600000 - (Date.now() % 3600000) + 2000;

describe("lot WORM : exigences sur un S3 réel à Object Lock (EX-12.16 à EX-12.41, EX-17.5 à EX-17.7, EX-18.9)", function () {
  this.timeout(600000);
  const docker = dockerDisponible([IMAGES.s3]);
  let dir;
  let s3;
  let tls;
  let prox;
  let n = 0;

  before(async function () {
    if (!docker.ok) return;
    dir = repertoireTemporaire("noortrace-worm-exigences-");
    s3 = await demarrerS3(`noortrace-test-worm-s3-${process.pid}`);
    tls = certificats(path.join(dir, "tls"));
    prox = await mandataireTls(tls, { port: s3.port });
  });

  after(async function () {
    await prox?.fermer();
    arreterTout();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  beforeEach(function () {
    if (!docker.ok) {
      this.currentTest.title += ` — en attente : ${docker.condition}`;
      this.skip();
    }
  });

  /** Un journal neuf sur un bucket neuf (rétention par défaut posée par l'exploitant). */
  async function journal(o = {}) {
    const d = path.join(dir, `j${++n}`);
    const bucket = `noortrace-worm-${process.pid}-${n}`;
    await creerBucketVerrouille(prox.origine, bucket, { ca: tls.caPem, jours: o.jours ?? 4018, mode: o.modeBucket ?? "COMPLIANCE", sansRegle: o.sansRegle });
    const { config, env } = configurationDev(d, { journal_id: N.octetsVersHex(N.keccak256(N.utf8(`journal-worm-${process.pid}-${n}`))) });
    config.storage.seal.worm = {
      type: "s3-object-lock", bucket, prefix: "journal-test/", mode: o.mode ?? "compliance", retain_days: 4018,
      credentials: { file: fichierSecret(path.join(d, "secrets", "worm-ecrivain"), identifiantsRole("ecrivain")) },
      endpoint: prox.origine, region: null, legal_hold_on_write: o.legal_hold_on_write ?? false, lock_audit_interval_days: 30, copy_pieces: o.copy_pieces ?? false,
    };
    if (o.pieces_days !== undefined) config.storage.retention.pieces_days = o.pieces_days;
    const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(config)), { reglesSupplementaires: [controleWorm] });
    expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
    const s = resoudreSecrets(v.config, { env });
    expect(s.erreurs).to.deep.equal([]);
    const fichier = path.join(d, "configuration.json");
    fs.writeFileSync(fichier, JSON.stringify(config));
    const ref = (role) => JSON.stringify({ file: fichierSecret(path.join(d, "secrets", role), identifiantsRole(role)) });
    return { d, bucket, config: v.config, brute: config, env, secrets: s.secrets, fichier, ref };
  }

  async function coeur(j, decalage = 0, o = {}) {
    const worm = o.worm ?? supportWormDepuisConfiguration(j.config, j.secrets, { tls: { ca: tls.caPem }, delais: RAPIDE });
    const c = await Coeur.demarrer({ config: j.config, secrets: j.secrets, worm, horloge: horloge(decalage) });
    return { c, worm };
  }

  /** Écrit l'événement de politique (heure courante), puis clôt la période dans l'heure suivante. */
  async function periodeClose(j, o = {}) {
    const a = await coeur(j);
    const P = Math.floor(a.c.horlogeBrute.murale() / 3600000) * 3600;
    await a.c.arreter();
    const b = await coeur(j, versHeureSuivante(), o);
    await b.c.tic();
    await b.worm.vider();
    return { ...b, P };
  }

  const admin = (j) => new OperationsS3({ worm: j.config.storage.seal.worm, identifiants: identifiantsS3(new TextEncoder().encode(identifiantsRole("administrateur"))), tls: { ca: tls.caPem }, delais: RAPIDE });
  const sortie = () => {
    const lignes = [];
    return { lignes, flux: { write: (t) => lignes.push(t) } };
  };
  async function ctl(j, args, o = {}) {
    const out = sortie();
    const err = sortie();
    const code = await principalCtl(args.map((a) => (a === "@cfg" ? j.fichier : a)), { stdout: out.flux, stderr: err.flux, env: j.env, tls: { ca: tls.caPem }, delais: RAPIDE, murale: o.murale });
    return { code, sortie: out.lignes.join(""), erreur: err.lignes.join(""), journal: err.lignes.filter((l) => l.startsWith("{")).map((l) => JSON.parse(l)) };
  }

  describe("copies de l'écrivain (EX-12.16, EX-12.17, EX-12.29, EX-12.30, EX-12.32, EX-12.33)", function () {
    it("EX-12.16 : chaque segment fermé, le manifeste, sa signature et la série des points sont copiés sous <prefix> + chemin relatif de 12.1 ; octets identiques ; EX-12.29 : une ligne de registre par copie, valide pour worm-v0", async function () {
      const j = await journal();
      const { c, P } = await periodeClose(j);
      try {
        const lignes = (await lireRegistres(path.join(c.repertoire, "worm"))).map((x) => x.ligne);
        const cles = lignes.map((l) => l.key).sort();
        const p10 = String(P).padStart(10, "0");
        expect(cles).to.include.members([`journal-test/manifestes/periode-${p10}.json`, `journal-test/manifestes/periode-${p10}.sig`, `journal-test/points/periode-${p10}.ndjson`]);
        expect(cles.filter((k) => k.startsWith("journal-test/segments/seg-0000000000000001-"))).to.have.length(1);
        const ops = admin(j);
        for (const l of lignes) {
          expect(valideWorm("ligne_copie", l).valide, JSON.stringify(valideWorm("ligne_copie", l).erreurs)).to.equal(true);
          expect(l.key.startsWith("journal-test/")).to.equal(true);
          const local = fs.readFileSync(path.join(c.repertoire, l.key.slice("journal-test/".length)));
          expect(N.sha256Hex(new Uint8Array(local))).to.equal(l.sha256);
          expect(l.length).to.equal(local.length);
          const e = await ops.empreinte(l.key, l.version_id);
          expect(e.sha256, l.key).to.equal(l.sha256);
          expect(l.lock).to.deep.include({ verdict: "conforme", legal_hold: "jamais" });
        }
        // Le fichier du registre porte l'époque de l'écrivain qui a copié (12.1).
        expect(fs.readdirSync(path.join(c.repertoire, "worm"))).to.deep.equal([`copies-${String(c.ecrivain.epoque).padStart(20, "0")}.ndjson`]);
        expect(c.journal.trouver("worm_lock_check").every((x) => x.data.verdict === "conforme" && x.data.when === "copie")).to.equal(true);
        expect(c.metriques.exposer()).to.match(/noortrace_worm_lock_checks_total\{verdict="conforme",when="copie"\} [1-9]/);
      } finally {
        await c.arreter();
      }
    });

    it("EX-12.16, EX-12.30 : la copie porte Content-MD5 et If-None-Match: *, jamais de mode ni d'échéance de rétention ; un Content-MD5 faux est refusé par le support", async function () {
      const r = requeteS3Copie("journal-test/x", Buffer.from("abc"));
      const noms = r.headers.map(([n]) => n.toLowerCase());
      expect(noms).to.deep.equal(["content-length", "content-md5", "if-none-match"]);
      expect(noms.some((x) => x.startsWith("x-amz-object-lock-mode") || x.startsWith("x-amz-object-lock-retain"))).to.equal(false);
      const j = await journal();
      const ops = admin(j);
      const faux = { ...r, headers: [["Content-Length", "3"], ["Content-MD5", "AAAAAAAAAAAAAAAAAAAAAA=="], ["If-None-Match", "*"]] };
      expect((await ops.acces.envoyer(faux)).statut).to.equal(400);
    });

    it("EX-12.16, EX-13.5 (3) : un second écrivain sur la même clé reçoit 412 ; la copie n'écrase rien ; même contenu : tenue pour faite, contenu différent : worm_copy_failed (objet_present_different)", async function () {
      const j = await journal();
      const { c, worm } = await coeur(j);
      try {
        const local = path.join(j.d, "a.ndjson");
        fs.writeFileSync(local, "contenu de A\n");
        const cle = cleObjetWorm("journal-test/", "segments/seg-0000000000000099-00000000000000000001.ndjson");
        const r1 = await worm.copier({ cle, chemin: local, nature: "segment" });
        expect(r1.version_id).to.be.a("string");
        // Même contenu (réponse perdue puis nouvel essai) : la version présente est reconnue.
        const autre = new ServiceCopiesWorm({ worm: j.config.storage.seal.worm, operations: worm.operations });
        autre.lier(c);
        fs.rmSync(path.join(c.repertoire, "worm"), { recursive: true, force: true });
        expect((await autre.copier({ cle, chemin: local, nature: "segment" })).version_id).to.equal(r1.version_id);
        // Contenu différent : jamais réécrit.
        fs.writeFileSync(local, "contenu d'un ecrivain perime\n");
        const r3 = await autre.copier({ cle, chemin: local, nature: "segment" });
        expect(r3.version_id).to.equal(null);
        expect(c.journal.trouver("worm_copy_failed").at(-1).data).to.include({ raison: "objet_present_different", statut: 412 });
        const l = await admin(j).listerVersions(cle);
        expect(l.versions).to.have.length(1);
      } finally {
        await c.arreter();
      }
    });

    it("EX-12.32 : l'écrivain ne copie jamais sous <prefix>gels/ ni hors des sous-préfixes qu'il copie (cle_refusee, rien n'est écrit)", async function () {
      const j = await journal();
      const { c, worm } = await coeur(j);
      try {
        const local = path.join(j.d, "x.json");
        fs.writeFileSync(local, "{}");
        for (const rel of ["gels/gel-20261201T090000Z-5f0c2a1e/0001-pose.json", "autre/x.json"]) {
          expect((await worm.copier({ cle: `journal-test/${rel}`, chemin: local, nature: "segment" })).version_id).to.equal(null);
          expect(c.journal.trouver("worm_copy_failed").at(-1).data.raison).to.equal("cle_refusee");
        }
        expect((await worm.copier({ cle: "autre-prefixe/segments/x", chemin: local, nature: "segment" })).version_id).to.equal(null);
        const l = await admin(j).listerVersions("");
        expect(l.versions.filter((v) => /gels\/|autre/.test(v.key))).to.deep.equal([]);
      } finally {
        await c.arreter();
      }
    });

    it("EX-13.5 (2) : le scellement refuse un segment d'époque inférieure à celle du dernier segment scellé (epoque_inferieure)", async function () {
      const j = await journal();
      const { c, worm } = await coeur(j);
      try {
        const f = path.join(j.d, "s.ndjson");
        fs.writeFileSync(f, "segment\n");
        expect((await worm.copier({ cle: "journal-test/segments/seg-0000000000000050-00000000000000000007.ndjson", chemin: f, nature: "segment" })).version_id).to.be.a("string");
        fs.writeFileSync(f, "segment perime\n");
        expect((await worm.copier({ cle: "journal-test/segments/seg-0000000000000051-00000000000000000006.ndjson", chemin: f, nature: "segment" })).version_id).to.equal(null);
        expect(c.journal.trouver("worm_copy_failed").at(-1).data.raison).to.equal("epoque_inferieure");
      } finally {
        await c.arreter();
      }
    });

    it("copy_pieces (EX-12.16) : les pièces référencées par le segment copié sont copiées sous <prefix>pieces/<xx>/<sha256>", async function () {
      const j = await journal({ copy_pieces: true });
      const { c } = await periodeClose(j);
      try {
        const cles = (await lireRegistres(path.join(c.repertoire, "worm"))).map((x) => x.ligne.key);
        const pieces = cles.filter((k) => k.startsWith("journal-test/pieces/"));
        expect(pieces.length).to.be.greaterThan(0);
        for (const k of pieces) expect(k).to.match(/^journal-test\/pieces\/([0-9a-f]{2})\/\1[0-9a-f]{62}$/);
      } finally {
        await c.arreter();
      }
    });

    it("panne du support (14.2 « Support WORM ») : copie en échec consignée, jamais bloquante ; le balayage de la supervision la réessaie (EX-12.16) et met à jour noortrace_worm_copy_pending", async function () {
      const j = await journal();
      const a = await coeur(j);
      await a.c.arreter();
      // Le support devient injoignable : un mandataire fermé.
      const coupe = await mandataireTls(tls, { port: s3.port });
      await coupe.fermer();
      const jc = { ...j, config: { ...j.config, storage: { ...j.config.storage, seal: { ...j.config.storage.seal, worm: { ...j.config.storage.seal.worm, endpoint: coupe.origine } } } } };
      const worm = supportWormDepuisConfiguration(jc.config, j.secrets, { tls: { ca: tls.caPem }, delais: RAPIDE });
      const b = await coeur(j, versHeureSuivante(), { worm });
      try {
        await b.c.tic();
        await worm.vider();
        expect(b.c.journal.trouver("worm_copy_failed").length).to.be.greaterThan(0);
        expect(b.c.journal.trouver("worm_copy_failed")[0].data.raison).to.equal("injoignable");
        expect(b.c.degrade.enModeDegrade).to.equal(false);
        // Le support revient : le balayage copie ce qui manque.
        worm.operations = supportWormDepuisConfiguration(j.config, j.secrets, { tls: { ca: tls.caPem }, delais: RAPIDE }).operations;
        const r = await worm.balayer();
        expect(r.copies).to.be.greaterThan(0);
        expect(r.manquantes).to.equal(0);
        expect(b.c.metriques.exposer()).to.match(/noortrace_worm_copy_pending 0/);
      } finally {
        await b.c.arreter();
      }
    });

    it("EX-12.33 : verrou plus court que la rétention (Days 30) → non_conforme, echeance_courte, consigné en erreur ; la copie compte comme faite", async function () {
      const j = await journal({ jours: 30 });
      const { c } = await periodeClose(j);
      try {
        const lignes = (await lireRegistres(path.join(c.repertoire, "worm"))).map((x) => x.ligne);
        expect(lignes.length).to.be.greaterThan(0);
        for (const l of lignes) expect(l.lock.verdict).to.equal("non_conforme");
        const k = c.journal.trouver("worm_lock_check");
        expect(k.every((x) => x.level === "error" && x.data.reasons.includes("echeance_courte"))).to.equal(true);
        expect(c.metriques.exposer()).to.match(/noortrace_worm_lock_nonconforming [1-9]/);
      } finally {
        await c.arreter();
      }
    });

    it("EX-12.33 : verrou absent (bucket à Object Lock sans rétention par défaut) → mode_absent et echeance_absente", async function () {
      const j = await journal({ sansRegle: true });
      const { c } = await periodeClose(j);
      try {
        const k = c.journal.trouver("worm_lock_check");
        expect(k.length).to.be.greaterThan(0);
        for (const x of k) expect(x.data.reasons).to.deep.equal(["mode_absent", "echeance_absente"]);
      } finally {
        await c.arreter();
      }
    });

    it("EX-12.33 : mode governance configuré face à un bucket COMPLIANCE → mode_non_conforme ; et l'inverse", async function () {
      const j = await journal({ mode: "governance" });
      const { c } = await periodeClose(j);
      try {
        expect(c.journal.trouver("worm_lock_check").every((x) => x.data.reasons.includes("mode_non_conforme"))).to.equal(true);
      } finally {
        await c.arreter();
      }
    });

    it("EX-12.31 : legal_hold_on_write → chaque copie porte x-amz-object-lock-legal-hold: ON, le contrôle attend on (conforme)", async function () {
      const j = await journal({ legal_hold_on_write: true });
      const { c } = await periodeClose(j);
      try {
        const lignes = (await lireRegistres(path.join(c.repertoire, "worm"))).map((x) => x.ligne);
        expect(lignes.length).to.be.greaterThan(0);
        for (const l of lignes) expect(l.lock).to.deep.include({ verdict: "conforme", legal_hold: "on" });
        const ops = admin(j);
        for (const l of lignes) expect(ops.etatGel(await ops.lireGel(l.key, l.version_id))).to.equal("on");
      } finally {
        await c.arreter();
      }
    });
  });

  describe("contrôles périodiques, relevé, registre des gels (EX-17.5, EX-17.6, EX-17.7)", function () {
    it("EX-17.5 : contrôles horaires (manifeste, signature, continuité, SHA-256 des copies, signataire) et quotidiens (relecture, rétention par défaut) en réussite", async function () {
      const j = await journal();
      const { c, worm } = await periodeClose(j);
      try {
        const s = new SupervisionWorm(worm);
        await s.tic();
        // Manifeste, signature, continuité, signataire et relecture : contrôles du cœur,
        // avec ou sans WORM (src/controles.mjs, R-A-11) ; copies et rétention : lot WORM.
        await c.controles.horaire(c.horlogeBrute.murale());
        await c.controles.quotidien(c.horlogeBrute.murale());
        const checks = c.journal.trouver("integrity_check").map((x) => [x.data.check, x.data.ok]);
        for (const k of ["manifeste", "signature", "copie_worm", "signataire", "relecture", "configuration_worm"]) expect(checks, k).to.deep.include([k, true]);
        expect(checks.filter(([, ok]) => !ok)).to.deep.equal([]);
        expect(c.journal.trouver("worm_lock_config_check")[0].data).to.deep.equal({ verdict: "conforme", mode: "COMPLIANCE", days: 4018, years: null });
        expect(c.journal.trouver("worm_lock_audit")[0].data).to.include({ non_conformes: 0, inattendues: 0 });
      } finally {
        await c.arreter();
      }
    });

    it("EX-17.5 : rétention par défaut non conforme (GOVERNANCE) → worm_lock_config_check non conforme, échec configuration_worm ; Years × 365 ≥ retain_days admis (11 ans refusés pour 4 018 jours, 12 admis)", async function () {
      const j = await journal({ modeBucket: "GOVERNANCE" });
      const { c, worm } = await periodeClose(j);
      try {
        await new SupervisionWorm(worm).tic();
        expect(c.journal.trouver("worm_lock_config_check")[0].data.verdict).to.equal("non_conforme");
        expect(c.metriques.exposer()).to.match(/noortrace_integrity_check_failures_total\{check="configuration_worm"\} 1/);
        // Une configuration en années : Years × 365 doit atteindre retain_days (11 × 365 = 4 015 < 4 018 ; 12 × 365 = 4 380).
        const ops = admin(j);
        const poser = async (ans) => {
          const corps = Buffer.from(`<?xml version="1.0" encoding="UTF-8"?><ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Years>${ans}</Years></DefaultRetention></Rule></ObjectLockConfiguration>`);
          expect((await ops.acces.envoyer({ method: "PUT", target: "/?object-lock", headers: [["Content-Length", String(corps.length)], ["Content-MD5", contentMd5(corps)]], body: corps })).statut).to.equal(200);
          return (await controlerConfigurationVerrou({ operations: worm.operations, worm: j.config.storage.seal.worm, journal: c.journal })).verdict;
        };
        expect(await poser(11)).to.equal("non_conforme");
        expect(await poser(12)).to.equal("conforme");
      } finally {
        await c.arreter();
      }
    });

    it("EX-17.5, EX-12.17 : une copie qui diffère du fichier local est un échec copie_worm", async function () {
      const j = await journal();
      const { c, worm } = await periodeClose(j);
      try {
        const seg = (await lireRegistres(path.join(c.repertoire, "worm"))).map((x) => x.ligne).find((l) => l.key.includes("/segments/"));
        fs.appendFileSync(path.join(c.repertoire, seg.key.slice("journal-test/".length)), "altération locale\n");
        await new SupervisionWorm(worm).horaire(c.horlogeBrute.murale());
        expect(c.journal.trouver("integrity_check").find((x) => x.data.check === "copie_worm" && x.data.key === seg.key).data.ok).to.equal(false);
      } finally {
        await c.arreter();
      }
    });

    it("EX-17.6 : relevé — une seconde version et un marqueur de suppression posés par un autre rôle sont consignés (worm_versions_unexpected), jauges à jour ; une version sans ligne au registre est inscrite", async function () {
      const j = await journal();
      const { c, worm } = await periodeClose(j);
      try {
        const lignes = (await lireRegistres(path.join(c.repertoire, "worm"))).map((x) => x.ligne);
        const ops = admin(j);
        const sig = lignes.find((l) => l.key.endsWith(".sig"));
        const pts = lignes.find((l) => l.key.endsWith(".ndjson") && l.key.includes("/points/"));
        // Seconde version (écriture sans condition, droit que l'écrivain n'a pas, EX-12.32).
        const r2 = { ...requeteS3Copie(sig.key, Buffer.from("seconde version")) };
        r2.headers = r2.headers.filter(([h]) => h !== "If-None-Match");
        expect((await ops.acces.envoyer(r2)).statut).to.equal(200);
        // Marqueur de suppression (DELETE simple).
        expect((await ops.acces.envoyer({ method: "DELETE", target: `/${pts.key}`, headers: [], body: null })).statut).to.equal(204);
        // Version d'une copie sans ligne au registre (registre perdu).
        const reg = path.join(c.repertoire, "worm", fs.readdirSync(path.join(c.repertoire, "worm"))[0]);
        const avant = fs.readFileSync(reg, "utf8").trim().split("\n");
        const manif = avant.findIndex((l) => l.includes("/manifestes/") && l.includes(".json"));
        fs.writeFileSync(reg, `${avant.filter((_, k) => k !== manif).join("\n")}\n`);
        const r = await releverVerrouillage({ operations: worm.operations, worm: j.config.storage.seal.worm, repertoire: c.repertoire, epoque: c.ecrivain.epoque, journal: c.journal, metriques: c.metriques, murale: () => Date.now(), gels: [] });
        expect(r.inattendues).to.equal(2);
        const u = c.journal.trouver("worm_versions_unexpected").map((x) => x.data);
        expect(u.find((x) => x.key === sig.key)).to.include({ versions: 2 });
        expect(u.find((x) => x.key === pts.key)).to.include({ marqueur: true });
        expect(c.metriques.exposer()).to.match(/noortrace_worm_versions_unexpected 2/);
        expect(c.journal.trouver("worm_lock_audit").at(-1).data).to.include({ inattendues: 2 });
        const apres = (await lireRegistres(path.join(c.repertoire, "worm"))).map((x) => x.ligne);
        const reinscrite = apres.find((l) => l.key === JSON.parse(avant[manif]).key);
        expect(reinscrite.version_id).to.equal(JSON.parse(avant[manif]).version_id);
        expect(valideWorm("ligne_copie", reinscrite).valide).to.equal(true);
      } finally {
        await c.arreter();
      }
    });

    it("EX-17.6 à la demande : noortrace-ctl worm releve (identifiants de l'écrivain, lecture seule), consigné ; code 0", async function () {
      const j = await journal();
      const { c } = await periodeClose(j);
      await c.arreter();
      const r = await ctl(j, ["worm", "releve", "--configuration", "@cfg"]);
      expect(r.code, r.erreur).to.equal(0);
      expect(JSON.parse(r.sortie)).to.include({ non_conformes: 0, inattendues: 0 });
      const ops = fs.readFileSync(j.config.supervision.ops_log.path, "utf8");
      expect(ops).to.contain('"event":"worm_lock_audit"');
    });
  });

  describe("gel juridique : outil noortrace-ctl worm gel (EX-12.34 à EX-12.41, EX-18.9)", function () {
    it("poser (EX-12.35 à EX-12.37, EX-12.40) : liste des objets et enregistrement pose écrits avant toute requête de gel ; chaque version gelée et relue ON ; pose_resultat ; code 0 ; journal sans identité", async function () {
      const j = await journal();
      const { c, P } = await periodeClose(j);
      await c.arreter();
      const r = await ctl(j, ["worm", "gel", "poser", "--configuration", "@cfg", "--identifiants", j.ref("gardien-pose"), "--identite", "j.dupont@assureur-demo.example", "--de", String(P), "--a", String(P), "--motif", "Litige LT-0042", "--reference", "dossier LT-0042"]);
      expect(r.code, r.erreur).to.equal(0);
      const gel = r.sortie.trim();
      expect(gel).to.match(/^gel-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$/);
      const ops = admin(j);
      const l = await ops.listerVersions(`journal-test/gels/${gel}/`);
      expect(l.versions.map((v) => v.key.split("/").at(-1)).sort()).to.deep.equal(["0001-pose.json", "0002-pose_resultat.json", "objets-0001.ndjson"]);
      const pose = JSON.parse((await ops.lire(`journal-test/gels/${gel}/0001-pose.json`)).corps.toString("utf8"));
      expect(valideWorm("enregistrement_gel", pose).valide).to.equal(true);
      expect(pose).to.include({ kind: "pose", actor: "j.dupont@assureur-demo.example", reference: "dossier LT-0042", prev_sha256: null });
      expect(pose.periods).to.deep.equal({ from: P, to: P });
      const objets = (await ops.lire(pose.objects.key)).corps;
      expect(N.sha256Hex(new Uint8Array(objets))).to.equal(pose.objects.sha256);
      for (const ligne of objets.toString("utf8").trim().split("\n")) {
        const o = JSON.parse(ligne);
        expect(ops.etatGel(await ops.lireGel(o.key, o.version_id)), o.key).to.equal("on");
      }
      const resultat = JSON.parse((await ops.lire(`journal-test/gels/${gel}/0002-pose_resultat.json`)).corps.toString("utf8"));
      expect(resultat.results).to.deep.equal({ ok: pose.objects.count, failed: [] });
      expect(resultat.prev_sha256).to.equal(empreinteEnregistrement(pose));
      const set = r.journal.find((x) => x.event === "worm_legal_hold_set");
      expect(set.component).to.equal("worm");
      expect(JSON.stringify(set)).to.not.contain("dupont");
      expect(set.data).to.include({ gel_id: gel, n: 2, kind: "pose_resultat", ok: pose.objects.count, failed: 0, anomalies: 0 });
    });

    it("demander-levee puis lever par une autre personne (EX-12.38) : empreinte imprimée, levee écrite avant les requêtes, versions OFF, levee_resultat ; garde respectée ; état relu par le rôle Lecteur (EX-12.41)", async function () {
      const j = await journal();
      const { c, P } = await periodeClose(j);
      await c.arreter();
      const gel = (await ctl(j, ["worm", "gel", "poser", "--configuration", "@cfg", "--identifiants", j.ref("gardien-pose"), "--identite", "j.dupont", "--de", String(P), "--a", String(P), "--motif", "litige"])).sortie.trim();
      const d = await ctl(j, ["worm", "gel", "demander-levee", "--configuration", "@cfg", "--identifiants", j.ref("gardien-pose"), "--identite", "j.dupont", "--gel", gel, "--motif", "litige clos"]);
      expect(d.code, d.erreur).to.equal(0);
      const demande = d.sortie.trim();
      expect(demande).to.match(/^0x[0-9a-f]{64}$/);
      const l = await ctl(j, ["worm", "gel", "lever", "--configuration", "@cfg", "--identifiants", j.ref("gardien-levee"), "--identite", "m.keller", "--gel", gel, "--demande", demande]);
      expect(l.code, l.erreur).to.equal(0);
      expect(l.journal.find((x) => x.event === "worm_legal_hold_released").data).to.include({ failed: 0, kept: 0 });
      const e = await ctl(j, ["worm", "gel", "etat", "--configuration", "@cfg", "--identifiants", j.ref("lecteur"), "--gel", gel]);
      expect(e.code).to.equal(0);
      const etat = JSON.parse(e.sortie);
      expect(etat).to.include({ actif: false, garde: "respectee" });
      expect(etat.records.map((x) => x.kind)).to.deep.equal(["pose", "pose_resultat", "demande_levee", "levee", "levee_resultat"]);
      expect(etat.records[2].record_sha256).to.equal(demande);
      expect(etat.versions.every((v) => v.legal_hold === "off")).to.equal(true);
    });

    it("EX-12.38 : levée par la même personne que la demande → code 3, worm_legal_hold_guard_refused (meme_identite), aucune requête de levée (versions encore ON), rien d'écrit", async function () {
      const j = await journal();
      const { c, P } = await periodeClose(j);
      await c.arreter();
      const gel = (await ctl(j, ["worm", "gel", "poser", "--configuration", "@cfg", "--identifiants", j.ref("gardien-pose"), "--identite", "j.dupont", "--de", String(P), "--a", String(P), "--motif", "litige"])).sortie.trim();
      const demande = (await ctl(j, ["worm", "gel", "demander-levee", "--configuration", "@cfg", "--identifiants", j.ref("gardien-pose"), "--identite", "j.dupont", "--gel", gel, "--motif", "clos"])).sortie.trim();
      const l = await ctl(j, ["worm", "gel", "lever", "--configuration", "@cfg", "--identifiants", j.ref("gardien-levee"), "--identite", "j.dupont", "--gel", gel, "--demande", demande]);
      expect(l.code).to.equal(3);
      expect(l.journal.find((x) => x.event === "worm_legal_hold_guard_refused").data.code).to.equal("meme_identite");
      const e = JSON.parse((await ctl(j, ["worm", "gel", "etat", "--configuration", "@cfg", "--identifiants", j.ref("lecteur"), "--gel", gel])).sortie);
      expect(e.records).to.have.length(3);
      expect(e.versions.every((v) => v.legal_hold === "on")).to.equal(true);
      // Empreinte qui n'est pas celle de la dernière demande : demande_inconnue.
      const l2 = await ctl(j, ["worm", "gel", "lever", "--configuration", "@cfg", "--identifiants", j.ref("gardien-levee"), "--identite", "m.keller", "--gel", gel, "--demande", `0x${"ab".repeat(32)}`]);
      expect(l2.code).to.equal(3);
      expect(l2.journal.find((x) => x.event === "worm_legal_hold_guard_refused").data.code).to.equal("demande_inconnue");
    });

    it("EX-12.38 : levée sept jours et une milliseconde après la demande → code 3 (demande_expiree) ; à sept jours tout juste → code 0", async function () {
      const j = await journal();
      const { c, P } = await periodeClose(j);
      await c.arreter();
      const t0 = Date.now();
      const gel = (await ctl(j, ["worm", "gel", "poser", "--configuration", "@cfg", "--identifiants", j.ref("gardien-pose"), "--identite", "j.dupont", "--de", String(P), "--a", String(P), "--motif", "litige"], { murale: () => t0 })).sortie.trim();
      const demande = (await ctl(j, ["worm", "gel", "demander-levee", "--configuration", "@cfg", "--identifiants", j.ref("gardien-pose"), "--identite", "j.dupont", "--gel", gel, "--motif", "clos"], { murale: () => t0 + 1000 })).sortie.trim();
      const tard = await ctl(j, ["worm", "gel", "lever", "--configuration", "@cfg", "--identifiants", j.ref("gardien-levee"), "--identite", "m.keller", "--gel", gel, "--demande", demande], { murale: () => t0 + 1000 + 604800001 });
      expect(tard.code).to.equal(3);
      expect(tard.journal.find((x) => x.event === "worm_legal_hold_guard_refused").data.code).to.equal("demande_expiree");
      const juste = await ctl(j, ["worm", "gel", "lever", "--configuration", "@cfg", "--identifiants", j.ref("gardien-levee"), "--identite", "m.keller", "--gel", gel, "--demande", demande], { murale: () => t0 + 1000 + 604800000 });
      expect(juste.code, juste.erreur).to.equal(0);
    });

    it("EX-12.36, EX-18.9 : identifiants de l'écrivain → code 2 (identifiants), rien n'est envoyé ; configuration sans support → 2 ; bornes --de/--a invalides → 2 ; option inconnue → 2", async function () {
      const j = await journal();
      const r = await ctl(j, ["worm", "gel", "poser", "--configuration", "@cfg", "--identifiants", JSON.stringify(j.brute.storage.seal.worm.credentials), "--identite", "j.dupont", "--de", "0", "--a", "0", "--motif", "x"]);
      expect(r.code).to.equal(2);
      expect(r.journal.find((x) => x.event === "worm_legal_hold_failed").data.raison).to.equal("identifiants");
      expect((await admin(j).listerVersions("journal-test/gels/")).versions).to.deep.equal([]);
      const sans = path.join(j.d, "sans-worm.json");
      fs.writeFileSync(sans, JSON.stringify({ ...j.brute, storage: { ...j.brute.storage, seal: { append_only_attribute: false, worm: null } } }));
      expect((await ctl(j, ["worm", "gel", "etat", "--configuration", sans, "--identifiants", j.ref("lecteur"), "--gel", "gel-20261201T090000Z-5f0c2a1e"])).code).to.equal(2);
      expect((await ctl(j, ["worm", "gel", "poser", "--configuration", "@cfg", "--identifiants", j.ref("gardien-pose"), "--identite", "x", "--de", "7200", "--a", "3600", "--motif", "x"])).code).to.equal(2);
      expect((await ctl(j, ["worm", "gel", "poser", "--configuration", "@cfg", "--identifiants", j.ref("gardien-pose"), "--identite", "x", "--de", "1000", "--a", "3600", "--motif", "x"])).code).to.equal(2);
      expect((await ctl(j, ["worm", "gel", "poser", "--configuration", "@cfg", "--identifiants", j.ref("gardien-pose"), "--inconnue", "x"])).code).to.equal(2);
      expect((await ctl(j, ["worm", "gel", "detruire"])).code).to.equal(2);
    });

    it("EX-12.40 : support injoignable à la première requête de liste → code 4, rien n'est écrit", async function () {
      const j = await journal();
      const coupe = await mandataireTls(tls, { port: s3.port });
      await coupe.fermer();
      const autre = JSON.parse(fs.readFileSync(j.fichier, "utf8"));
      autre.storage.seal.worm.endpoint = coupe.origine;
      const f = path.join(j.d, "coupe.json");
      fs.writeFileSync(f, JSON.stringify(autre));
      const r = await ctl(j, ["worm", "gel", "poser", "--configuration", f, "--identifiants", j.ref("gardien-pose"), "--identite", "x", "--de", "3600", "--a", "3600", "--motif", "x"]);
      expect(r.code).to.equal(4);
      expect(r.journal.find((x) => x.event === "worm_legal_hold_failed").data.raison).to.equal("injoignable");
      expect((await admin(j).listerVersions("journal-test/gels/")).versions).to.deep.equal([]);
    });

    it("EX-12.35, EX-12.40 : anomalies du périmètre (manifeste absent d'une période de la plage, pièces non copiées et purgeables) inscrites dans pose, versions présentes gelées, code 1, worm_versions_unexpected", async function () {
      const j = await journal({ pieces_days: 30 });
      const { c, P } = await periodeClose(j);
      await c.arreter();
      const r = await ctl(j, ["worm", "gel", "poser", "--configuration", "@cfg", "--identifiants", j.ref("gardien-pose"), "--identite", "j.dupont", "--de", String(P), "--a", String(P + 3600), "--motif", "litige"]);
      expect(r.code).to.equal(1);
      const gel = r.sortie.trim();
      const pose = JSON.parse((await admin(j).lire(`journal-test/gels/${gel}/0001-pose.json`)).corps.toString("utf8"));
      const kinds = pose.anomalies.map((a) => a.kind);
      expect(kinds).to.include.members(["manifeste_absent", "segments_indetermines", "objet_absent", "pieces_non_copiees"]);
      expect(r.journal.filter((x) => x.event === "worm_versions_unexpected").length).to.be.greaterThan(0);
    });

    it("EX-12.40 : deux gels qui se chevauchent — lever le premier laisse gelées les versions que couvre le second (results.kept, gel_id du second), code 0", async function () {
      const j = await journal();
      const { c, P } = await periodeClose(j);
      await c.arreter();
      const poser = async (motif) => (await ctl(j, ["worm", "gel", "poser", "--configuration", "@cfg", "--identifiants", j.ref("gardien-pose"), "--identite", "j.dupont", "--de", String(P), "--a", String(P), "--motif", motif])).sortie.trim();
      const g1 = await poser("premier");
      const g2 = await poser("second");
      const demande = (await ctl(j, ["worm", "gel", "demander-levee", "--configuration", "@cfg", "--identifiants", j.ref("gardien-pose"), "--identite", "j.dupont", "--gel", g1, "--motif", "clos"])).sortie.trim();
      const l = await ctl(j, ["worm", "gel", "lever", "--configuration", "@cfg", "--identifiants", j.ref("gardien-levee"), "--identite", "m.keller", "--gel", g1, "--demande", demande]);
      expect(l.code, l.erreur).to.equal(0);
      const ops = admin(j);
      const resultat = JSON.parse((await ops.lire(`journal-test/gels/${g1}/0005-levee_resultat.json`)).corps.toString("utf8"));
      expect(resultat.results.ok).to.equal(0);
      expect(resultat.results.kept.length).to.be.greaterThan(0);
      expect(resultat.results.kept.every((k) => k.gel_id === g2)).to.equal(true);
      for (const k of resultat.results.kept) expect(ops.etatGel(await ops.lireGel(k.key, k.version_id))).to.equal("on");
    });

    it("EX-12.40 : reprendre après une pose partielle (un objet en échec) écrit un second pose_resultat complet ; garde valide (pose_resultat → pose_resultat)", async function () {
      const j = await journal();
      const { c, P } = await periodeClose(j);
      await c.arreter();
      const ops = new OperationsS3({ worm: j.config.storage.seal.worm, identifiants: identifiantsS3(new TextEncoder().encode(identifiantsRole("gardien-pose"))), tls: { ca: tls.caPem }, delais: RAPIDE });
      let premier = true;
      const poserGel = ops.poserGel.bind(ops);
      ops.poserGel = async (k, v, on) => {
        if (premier) {
          premier = false;
          return poserGel(k, v, on);
        }
        if (k.includes("/points/")) return { statut: 503, code: "ServiceUnavailable" };
        return poserGel(k, v, on);
      };
      const lignes = [];
      const journalOutil = { consigner: (niveau, evenement, data) => lignes.push({ niveau, evenement, data }) };
      const out = [];
      const outil = new OutilGel({ config: j.config, operations: ops, journal: journalOutil, sortie: (t) => out.push(t) });
      expect(await outil.poser({ identite: "j.dupont", de: P, a: P, motif: "litige", reference: null })).to.equal(CODES_SORTIE_GEL.PARTIEL);
      const gel = out[0].trim();
      const r = await ctl(j, ["worm", "gel", "reprendre", "--configuration", "@cfg", "--identifiants", j.ref("gardien-pose"), "--identite", "j.dupont", "--gel", gel]);
      expect(r.code, r.erreur).to.equal(0);
      const e = JSON.parse((await ctl(j, ["worm", "gel", "etat", "--configuration", "@cfg", "--identifiants", j.ref("lecteur"), "--gel", gel])).sortie);
      expect(e.garde).to.equal("respectee");
      expect(e.records.map((x) => x.kind)).to.deep.equal(["pose", "pose_resultat", "pose_resultat"]);
      expect(e.versions.every((v) => v.legal_hold === "on")).to.equal(true);
    });

    it("EX-17.7 : la supervision lit le registre des gels (worm_legal_hold_observed par enregistrement) ; un gel levé hors de l'outil est alerté (version d'un gel actif non ON) ; un registre falsifié (levée par la même personne) viole la garde", async function () {
      const j = await journal();
      const { c, P, worm } = await periodeClose(j);
      try {
        const gel = (await ctl(j, ["worm", "gel", "poser", "--configuration", "@cfg", "--identifiants", j.ref("gardien-pose"), "--identite", "j.dupont", "--de", String(P), "--a", String(P), "--motif", "litige"])).sortie.trim();
        const ops = admin(j);
        // Levée hors de l'outil, par une seule personne, sur une version du gel.
        const pose = JSON.parse((await ops.lire(`journal-test/gels/${gel}/0001-pose.json`)).corps.toString("utf8"));
        const o = JSON.parse((await ops.lire(pose.objects.key)).corps.toString("utf8").split("\n")[0]);
        expect((await ops.poserGel(o.key, o.version_id, false)).statut).to.equal(200);
        const s = new SupervisionWorm(worm);
        await s.quotidien(c.horlogeBrute.murale());
        const obs = c.journal.trouver("worm_legal_hold_observed");
        expect(obs.map((x) => x.data.kind)).to.deep.equal(["pose", "pose_resultat"]);
        expect(obs.every((x) => x.data.garde === "respectee" && x.level === "info")).to.equal(true);
        const alerte = c.journal.trouver("worm_lock_check").find((x) => x.data.when === "registre_gels");
        expect(alerte.level).to.equal("error");
        expect(alerte.data).to.include({ key: o.key, version_id: o.version_id, gel_id: gel });
        expect(alerte.data.reasons).to.deep.equal(["gel_absent"]);
        // Registre falsifié : demande et levée de la même identité, écrites hors de l'outil.
        const res = JSON.parse((await ops.lire(`journal-test/gels/${gel}/0002-pose_resultat.json`)).corps.toString("utf8"));
        const dem = { ...res, n: 3, kind: "demande_levee", reason: "x", results: null, prev_sha256: empreinteEnregistrement(res) };
        const lev = { ...res, n: 4, kind: "levee", results: null, request_sha256: empreinteEnregistrement(dem), prev_sha256: empreinteEnregistrement(dem) };
        await ops.ecrireConditionnel(`journal-test/gels/${gel}/0003-demande_levee.json`, octetsEnregistrement(dem));
        await ops.ecrireConditionnel(`journal-test/gels/${gel}/0004-levee.json`, octetsEnregistrement(lev));
        const g = await lireRegistreGels({ operations: worm.operations, worm: j.config.storage.seal.worm, journal: c.journal, metriques: c.metriques, vus: s.vus });
        expect(g.gels[0].etat.actif).to.equal(true);
        const viole = c.journal.trouver("worm_legal_hold_observed").find((x) => x.data.n === 4);
        expect(viole.level).to.equal("error");
        expect(viole.data.garde).to.equal("meme_identite");
        expect(c.metriques.exposer()).to.match(/noortrace_worm_legal_holds_active 1/);
      } finally {
        await c.arreter();
      }
    });
  });

  describe("supports Azure et Google Cloud Storage (simulateur fidèle aux requêtes d'EX-12.39)", function () {
    it("gel, levée et état d'une version par les requêtes exactes ; verdict d'EX-12.33 ; les opérations que CT-2 0.5 ne fixe pas lèvent ErreurNonFixe et l'outil s'arrête (code 4, rien n'est écrit)", async function () {
      const sim = new SimulateurAzureGcs();
      await sim.ecouter();
      try {
        const id = new TextEncoder().encode(JSON.stringify({ bearer_token: "jeton-de-test" }));
        const az = new OperationsAzure({ worm: { type: "azure-immutable-blob", bucket: "noortrace-demo-worm", prefix: "journal-demo/", endpoint: sim.origine }, identifiants: JSON.parse(Buffer.from(id).toString()), tls: {}, delais: RAPIDE });
        az.acces.origine = new URL(sim.origine);
        const k = "journal-demo/segments/seg-0000000000000001-00000000000000000001.ndjson";
        sim.ajouter("azure", k, "2026-11-10T11:00:05.1234567Z");
        expect(az.etatGel(await az.lireGel(k, "2026-11-10T11:00:05.1234567Z"))).to.equal("jamais");
        expect((await az.poserGel(k, "2026-11-10T11:00:05.1234567Z", true)).statut).to.equal(200);
        expect(az.etatGel(await az.lireGel(k, "2026-11-10T11:00:05.1234567Z"))).to.equal("on");
        expect(sim.requetes.at(-2).target).to.equal(`/noortrace-demo-worm/${k}?comp=legalhold&versionid=2026-11-10T11%3A00%3A05.1234567Z`);
        expect(sim.requetes.at(-2).authorization).to.equal("Bearer jeton-de-test");
        const gcs = new OperationsGcs({ worm: { type: "gcs-object-retention", bucket: "noortrace-demo-worm", prefix: "journal-demo/", endpoint: null }, identifiants: { bearer_token: "jeton-de-test" }, origine: sim.origine, delais: RAPIDE });
        sim.ajouter("gcs", k, "1794308405123456");
        expect((await gcs.poserGel(k, "1794308405123456", true)).statut).to.equal(200);
        expect(gcs.etatGel(await gcs.lireGel(k, "1794308405123456"))).to.equal("on");
        expect((await gcs.poserGel(k, "1794308405123456", false)).statut).to.equal(200);
        expect(gcs.etatGel(await gcs.lireGel(k, "1794308405123456"))).to.equal("off");
        for (const f of ["copier", "listerVersions", "lire", "ecrireConditionnel", "configurationVerrou"]) {
          let e = null;
          try {
            await az[f]("x");
          } catch (x) {
            e = x;
          }
          expect(e, f).to.be.instanceOf(ErreurNonFixe);
        }
        // L'outil de gel sur Azure : la liste des versions vient du registre des copies ; l'écriture du
        // registre des gels n'est pas fixée par CT-2 0.5 : arrêt avant toute requête de gel, code 4.
        const j = await journal();
        const cfg = JSON.parse(fs.readFileSync(j.fichier, "utf8"));
        cfg.storage.seal.worm = { ...cfg.storage.seal.worm, type: "azure-immutable-blob", endpoint: sim.origine.replace("http:", "https:"), legal_hold_on_write: false };
        const f = path.join(j.d, "azure.json");
        fs.writeFileSync(f, JSON.stringify(cfg));
        const porteur = fichierSecret(path.join(j.d, "secrets", "porteur"), JSON.stringify({ bearer_token: "jeton-de-test" }));
        fs.mkdirSync(path.join(j.d, "registre-vide"), { recursive: true });
        const avant = sim.requetes.length;
        const r = await ctl(j, ["worm", "gel", "poser", "--configuration", f, "--identifiants", JSON.stringify({ file: porteur }), "--identite", "x", "--de", "3600", "--a", "3600", "--motif", "x", "--registre-copies", path.join(j.d, "registre-vide")]);
        expect(r.code, r.erreur).to.equal(4);
        expect(r.journal.find((x) => x.event === "worm_legal_hold_failed").data.raison).to.equal("operation_non_fixee");
        expect(sim.requetes.length).to.equal(avant);
      } finally {
        await sim.fermer();
      }
    });
  });
});
