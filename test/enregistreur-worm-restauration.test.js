// Reconstruction d'un journal depuis ses copies WORM (CT-2 EX-12.17 ; CT-8
// §11.4 chemin B, EX-10.14 `noortrace-ctl worm restaurer`), avec de vrais
// processus et de vrais services (S3 à Object Lock, PostgreSQL) :
// le démon réel A écrit, ses segments fermés sont copiés ; A est tué et son
// stockage local détruit ; `bin/noortrace-ctl worm reconstruire` relit les
// copies (sans registre des copies, puis avec la copie d'archive du registre),
// contrôle SHA-256 et longueur de chaque objet relu contre le registre, et la
// chaîne reconstruite ; le démon réel B reprend sur le répertoire reconstruit
// avec une époque plus grande ; le journal est accepté par N.verifierJournal,
// et les dossiers d'un événement restauré et d'un événement de B par le noyau
// et par le binaire Go (go1.27.3, en attente sans lui). Échecs : copie
// manquante, copie altérée, copie d'une autre version, chaîne rompue,
// destination existante ou dans l'original.
// Sans Docker, les cas sont en attente et leur titre nomme la condition.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import { verifierRepertoireDossier } from "@noortrace/noyau/dossier-fichiers";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { Coeur, validerConfiguration, resoudreSecrets, lireEvenements, lireRegistres, OperationsS3, identifiantsS3, principalCtl, requeteS3Copie } from "@noortrace/enregistreur";
import { RACINE, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import {
  IMAGES, dockerDisponible, demarrerS3, demarrerPostgresql, arreterTout, certificats, mandataireTls, creerBucketVerrouille, identifiantsRole, attendre, portLibre,
} from "./fixtures/enregistreur-worm/outils.mjs";
import { configurationHa, ClientMcpHttp, lancerDemon, sante } from "./fixtures/enregistreur-ha/outils.mjs";

const BIN_CTL = path.join(RACINE, "paquets", "enregistreur", "bin", "noortrace-ctl");

function construireVerificateur(dir) {
  const dirGo = process.env.NOORTRACE_GO_BIN ?? null;
  const env = { ...process.env, GOTOOLCHAIN: "local" };
  if (dirGo) env.PATH = `${dirGo}${path.delimiter}${env.PATH}`;
  const v = spawnSync("go", ["version"], { env, encoding: "utf8" });
  if (v.status !== 0 || !/go1\.27\.3 /.test(v.stdout)) return null;
  const sortie = path.join(dir, "noortrace-verifier");
  execFileSync(path.join(RACINE, "verificateur", "scripts", "construire.sh"), ["-o", sortie], { env: { ...env, GOFLAGS: "-mod=vendor" }, cwd: path.join(RACINE, "verificateur"), stdio: "pipe" });
  return sortie;
}

function ctlProcessus(args, env) {
  return new Promise((res) => {
    const p = spawn(process.execPath, [BIN_CTL, ...args], { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
    let sortie = "";
    let erreur = "";
    p.stdout.on("data", (d) => (sortie += d));
    p.stderr.on("data", (d) => (erreur += d));
    p.on("exit", (code) => res({ code, sortie, erreur }));
  });
}

function horlogeHeureSuivante() {
  const d = 3600000 - (Date.now() % 3600000) + 3000;
  return { murale: () => Date.now() + d, monotone: () => performance.now() + 1e7 + d };
}

describe("reconstruction du journal depuis les copies WORM (CT-2 EX-12.17, CT-8 §11.4 chemin B, EX-10.14)", function () {
  this.timeout(900000);
  const docker = dockerDisponible([IMAGES.s3, IMAGES.postgresql]);
  let dir;
  let tls;
  let prox;
  let s3;
  let pg;
  let serveur;
  let bin = null;
  const ev = {};

  before(async function () {
    if (!docker.ok) return;
    dir = repertoireTemporaire("noortrace-worm-restauration-");
    [s3, pg] = await Promise.all([demarrerS3(`noortrace-test-restauration-s3-${process.pid}`), demarrerPostgresql(`noortrace-test-restauration-pg-${process.pid}`)]);
    tls = certificats(path.join(dir, "tls"));
    prox = await mandataireTls(tls, { port: s3.port });
    const service = new ServiceApprobationFactice({ org_id: "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab", journal_id: null });
    serveur = await service.servir(0);
    bin = construireVerificateur(dir);
    const bucket = `noortrace-restauration-${process.pid}`;
    await creerBucketVerrouille(prox.origine, bucket, { ca: tls.caPem });
    const journal_id = N.octetsVersHex(N.keccak256(N.utf8(`journal-restauration-${process.pid}`)));
    service.journal_id = journal_id;
    const worm = { type: "s3-object-lock", bucket, prefix: "restauration/", mode: "compliance", retain_days: 4018, endpoint: prox.origine, region: null, legal_hold_on_write: false, lock_audit_interval_days: 30, copy_pieces: true };
    const commun = { journal_id, store: { type: "postgresql", table: "bail_restauration" }, dsn: pg.dsn, approbation: serveur.address().port, worm, segment_max_bytes: 6144 };
    const A = configurationHa(path.join(dir, "a"), { ...commun, instance: "inst-a", portHttp: await portLibre(), portSante: await portLibre() });
    const B = configurationHa(path.join(dir, "b"), { ...commun, instance: "inst-b", portHttp: await portLibre(), portSante: await portLibre() });
    for (const [x, f] of [[A, "a"], [B, "b"]]) {
      x.fichier = path.join(dir, `${f}.json`);
      fs.writeFileSync(x.fichier, JSON.stringify(x.config));
      x.port = Number(x.config.supervision.health_listen.split(":")[1]);
      x.env = { ...x.env, NODE_EXTRA_CA_CERTS: tls.ca };
    }
    Object.assign(ev, { A, B, worm, journal_id });
    ev.repA = path.join(A.config.storage.root, A.config.recorder.org_id.slice(2), journal_id.slice(2));
    // 1. A écrit ; ses segments fermés sont copiés.
    const dA = lancerDemon(A.fichier, A.env, A.config.supervision.ops_log.path);
    ev.dA = dA;
    await attendre(async () => (await sante(A.port))?.corps?.status === "ok", 60000).catch((e) => {
      throw new Error(`${e.message}\n${dA.sortie}`);
    });
    const h = new ClientMcpHttp(A.config.mcp.http.listen);
    await h.ouvrir();
    for (let k = 1; k <= 8; k++) expect((await h.appeler("demo__ecrire", { id: `R${k}`, montant: String(k) })).result.isError).to.equal(false);
    await attendre(async () => (await lireRegistres(path.join(ev.repA, "worm"))).filter((x) => x.ligne.key.includes("/segments/")).length >= 2, 30000);
    // Copie d'archive du registre des copies (chemin A), avant la perte.
    ev.registreArchive = path.join(dir, "archive-worm");
    fs.cpSync(path.join(ev.repA, "worm"), ev.registreArchive, { recursive: true });
    ev.evtsA = await lireEvenements(ev.repA);
    // 2. A est tué, son stockage local détruit.
    dA.kill("SIGKILL");
    await dA.fin;
    ev.epoqueA = dA.lignes().find((l) => l.event === "lease_acquired").data.epoch;
    fs.rmSync(A.config.storage.root, { recursive: true, force: true });
    ev.copies = (await lireRegistres(ev.registreArchive)).map((x) => x.ligne);
  });

  after(async function () {
    ev.dA?.kill("SIGKILL");
    ev.dB?.kill("SIGKILL");
    await ev.C?.arreter();
    serveur?.close();
    serveur?.closeAllConnections?.();
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

  it("chemin B : noortrace-ctl worm reconstruire (processus réel, sans registre) relit chaque copie, vérifie la chaîne, recrée journal.json ; les événements des segments copiés sont restaurés octet pour octet, la perte du segment ouvert est celle de 13.5", async function () {
    const dest = ev.B.config.storage.root;
    const r = await ctlProcessus(["worm", "reconstruire", "--configuration", ev.B.fichier, "--vers", dest], ev.B.env);
    expect(r.code, r.erreur).to.equal(0);
    const s = JSON.parse(r.sortie);
    expect(s).to.include({ registre: false, epoque_max: ev.epoqueA });
    expect(s.perdus).to.include.members(["intentions/", "attente/", "approbations/", "worm/"]);
    ev.repB = path.join(dest, ev.A.config.recorder.org_id.slice(2), ev.journal_id.slice(2));
    const restaures = await lireEvenements(ev.repB);
    expect(restaures.length).to.equal(s.last_seq);
    expect(restaures.length).to.be.greaterThan(0);
    expect(restaures.length).to.be.below(ev.evtsA.length + 1);
    restaures.forEach((e, k) => expect(e).to.deep.equal(ev.evtsA[k]));
    for (const l of ev.copies.filter((x) => x.key.includes("/segments/"))) {
      const f = path.join(ev.repB, l.key.slice(ev.worm.prefix.length));
      expect(N.sha256Hex(new Uint8Array(fs.readFileSync(f))), l.key).to.equal(l.sha256);
    }
    const jj = JSON.parse(fs.readFileSync(path.join(ev.repB, "journal.json"), "utf8"));
    expect(jj).to.include({ version: 0, org_id: ev.A.config.recorder.org_id, journal_id: ev.journal_id });
    for (const x of ["intentions", "attente", "approbations", "worm"]) expect(fs.existsSync(path.join(ev.repB, x))).to.equal(false);
    ev.synthese = s;
  });

  it("avec la copie d'archive du registre des copies : SHA-256 et longueur de chaque objet relu contrôlés ; mêmes fichiers", async function () {
    const dest = path.join(dir, "reconstruit-registre");
    const r = await ctlProcessus(["worm", "reconstruire", "--configuration", ev.B.fichier, "--vers", dest, "--registre-copies", ev.registreArchive], ev.B.env);
    expect(r.code, r.erreur).to.equal(0);
    const s = JSON.parse(r.sortie);
    expect(s).to.include({ registre: true, last_seq: ev.synthese.last_seq, last_hash: ev.synthese.last_hash });
    expect(s.fichiers).to.equal(ev.copies.length);
  });

  it("le démon réel B reprend sur le répertoire reconstruit : époque strictement supérieure, segment neuf dont l'en-tête suit le dernier événement restauré ; il écrit", async function () {
    const { B } = ev;
    const dB = lancerDemon(B.fichier, B.env, B.config.supervision.ops_log.path);
    ev.dB = dB;
    await attendre(async () => (await sante(B.port))?.corps?.status === "ok", 60000).catch((e) => {
      throw new Error(`${e.message}\n${dB.sortie}`);
    });
    const h = new ClientMcpHttp(B.config.mcp.http.listen);
    await h.ouvrir();
    expect((await h.appeler("demo__ecrire", { id: "B1", montant: "9" })).result.isError).to.equal(false);
    dB.kill("SIGTERM");
    expect((await dB.fin).code).to.equal(0);
    const acq = dB.lignes().find((l) => l.event === "lease_acquired");
    expect(acq.data.epoch).to.be.greaterThan(ev.synthese.epoque_max);
    const segs = fs.readdirSync(path.join(ev.repB, "segments")).sort();
    const neuf = segs.find((n) => Number(n.slice(21, 41)) === acq.data.epoch);
    const entete = JSON.parse(fs.readFileSync(path.join(ev.repB, "segments", neuf), "utf8").split("\n")[0]);
    expect(entete).to.include({ first_seq: ev.synthese.last_seq + 1, prev_hash: ev.synthese.last_hash, epoch: acq.data.epoch });
  });

  it("le journal reconstruit et continué est accepté par N.verifierJournal ; dossiers d'un événement restauré et d'un événement de B valides pour le noyau ET le binaire Go", async function () {
    const v = validerConfiguration(new TextEncoder().encode(JSON.stringify({ ...ev.B.config, recorder: { ...ev.B.config.recorder, instance_id: "inst-c" } })));
    const s = resoudreSecrets(v.config, { env: ev.B.env });
    ev.C = await Coeur.demarrer({ config: v.config, secrets: s.secrets, horloge: horlogeHeureSuivante() });
    await ev.C.tic();
    const evts = await lireEvenements(ev.repB);
    const restaure = evts.find((e) => e.execution.tool === "demo__ecrire");
    const deB = evts.filter((e) => e.execution.tool === "demo__ecrire").at(-1);
    expect(deB.seq).to.be.greaterThan(ev.synthese.last_seq);
    const dossiers = [];
    for (const [nom, e] of [["restaure", restaure], ["b", deB]]) {
      const d = path.join(dir, `dossier-${nom}`);
      await ev.C.exporterDossier(e.seq, d);
      const rv = verifierRepertoireDossier(d);
      expect(rv.verdict, `${nom} ${JSON.stringify(rv)}`).to.equal("valide");
      dossiers.push(d);
    }
    const cles = JSON.parse(fs.readFileSync(path.join(dossiers[0], "cles.json"), "utf8"));
    const r = N.verifierJournal(evts, cles);
    expect(r.valide, JSON.stringify(r.diagnostics)).to.equal(true);
    await ev.C.arreter();
    ev.C = null;
    if (!bin) {
      this.test.title += " — binaire Go en attente : go1.27.3 introuvable (NOORTRACE_GO_BIN)";
      this.skip();
    }
    for (const d of dossiers) {
      const g = spawnSync(bin, [d, "--json"], { encoding: "utf8" });
      expect(g.status, g.stdout + g.stderr).to.equal(0);
      expect(JSON.parse(g.stdout).verdict).to.equal("valide");
    }
  });

  describe("échecs : rien n'est écrit dans la destination", function () {
    const sortie = () => {
      const l = [];
      return { l, flux: { write: (t) => l.push(t) } };
    };
    async function ctl(args, o = {}) {
      const out = sortie();
      const err = sortie();
      const code = await principalCtl(args, { stdout: out.flux, stderr: err.flux, env: ev.B.env, tls: { ca: tls.caPem }, delais: [10, 10, 10], ...o });
      const lignes = err.l.filter((x) => x.startsWith("{")).map((x) => JSON.parse(x));
      return { code, sortie: out.l.join(""), erreur: err.l.join(""), lignes, incidents: lignes.find((x) => x.event === "worm_restore_refused")?.data.incidents ?? [] };
    }
    const registreModifie = (f) => {
      const d = path.join(dir, `registre-${Math.random().toString(16).slice(2)}`);
      fs.cpSync(ev.registreArchive, d, { recursive: true });
      const fichier = path.join(d, fs.readdirSync(d).sort()[0]);
      const lignes = fs.readFileSync(fichier, "utf8").trim().split("\n").map((l) => JSON.parse(l));
      fs.writeFileSync(fichier, `${f(lignes).map((l) => JSON.stringify(l)).join("\n")}\n`);
      return d;
    };
    const admin = () => new OperationsS3({ worm: ev.worm, identifiants: identifiantsS3(new TextEncoder().encode(identifiantsRole("administrateur"))), tls: { ca: tls.caPem }, delais: [10] });

    it("copie manquante : une version inscrite au registre absente du support → code 1, copie_absente", async function () {
      const reg = registreModifie((ls) => [...ls, { ...ls[0], key: `${ev.worm.prefix}segments/seg-0000000000009999-${String(ev.epoqueA).padStart(20, "0")}.ndjson`, version_id: "version-absente" }]);
      const dest = path.join(dir, "echec-manquante");
      const r = await ctl(["worm", "reconstruire", "--configuration", ev.B.fichier, "--vers", dest, "--registre-copies", reg]);
      expect(r.code, r.erreur).to.equal(1);
      expect(r.incidents.map((x) => x.kind)).to.deep.equal(["copie_absente"]);
      expect(fs.existsSync(dest)).to.equal(false);
      expect(fs.readdirSync(dir).filter((n) => n.startsWith("echec-manquante"))).to.deep.equal([]);
    });

    it("copie altérée : SHA-256 relu différent de celui du registre → code 1, copie_alteree ; sans registre, une copie dont la chaîne est rompue (segment altéré, segment manquant) est refusée", async function () {
      const reg = registreModifie((ls) => ls.map((l, k) => (k === 0 ? { ...l, sha256: `0x${"00".repeat(32)}` } : l)));
      const dest = path.join(dir, "echec-alteree");
      const r = await ctl(["worm", "reconstruire", "--configuration", ev.B.fichier, "--vers", dest, "--registre-copies", reg]);
      expect(r.code).to.equal(1);
      expect(r.incidents[0].kind).to.equal("copie_alteree");
      expect(fs.existsSync(dest)).to.equal(false);
      // Sans registre : copies d'un autre préfixe déposées par un autre rôle, l'une altérée, puis une manquante.
      const segs = ev.copies.filter((x) => x.key.includes("/segments/")).sort((a, b) => (a.key < b.key ? -1 : 1));
      const ops = admin();
      const lire = async (k, v) => Buffer.from((await ops.lire(k, v)).corps);
      // Altération d'un octet : dernier chiffre de la première empreinte du premier événement.
      const alterer = (b) => {
        const lignes = b.toString("utf8").split("\n");
        lignes[1] = lignes[1].replace(/0x[0-9a-f]{63}([0-9a-f])/, (m, c) => m.slice(0, -1) + (c === "0" ? "1" : "0"));
        const r = Buffer.from(lignes.join("\n"));
        expect(r.equals(b)).to.equal(false);
        return r;
      };
      for (const [prefixe, transformer, attendu] of [
        ["altere/", (k, b) => (k === 1 ? alterer(b) : b), "copie_alteree"],
        // Segment manquant : le premier (la chaîne doit commencer à seq 1). Sans
        // registre, l'absence du dernier segment fermé ne se distingue pas de
        // la perte admise du segment ouvert (13.5) : seul le registre la révèle
        // (cas « copie manquante » ci-dessus).
        ["manquant/", (k, b) => (k === 0 ? null : b), "segment_absent"],
      ]) {
        for (let k = 0; k < segs.length; k++) {
          const b = transformer(k, await lire(segs[k].key, segs[k].version_id));
          if (b) expect((await ops.copier(prefixe + segs[k].key.slice(ev.worm.prefix.length), b)).statut).to.equal(200);
        }
        const cfg = JSON.parse(fs.readFileSync(ev.B.fichier, "utf8"));
        cfg.storage.seal.worm.prefix = prefixe;
        const f = path.join(dir, `${prefixe.slice(0, -1)}.json`);
        fs.writeFileSync(f, JSON.stringify(cfg));
        const d2 = path.join(dir, `echec-${prefixe.slice(0, -1)}`);
        const r2 = await ctl(["worm", "reconstruire", "--configuration", f, "--vers", d2]);
        expect(r2.code, `${prefixe} ${r2.erreur}`).to.equal(1);
        expect(r2.incidents.map((x) => x.kind), prefixe).to.include(attendu);
        expect(fs.existsSync(d2)).to.equal(false);
      }
    });

    it("registre archivé plus ancien que les copies : une copie sans ligne au registre (version unique) est relue, contrôlée par la chaîne, consignée worm_restore_unregistered ; code 0, fichier restauré", async function () {
      const reg = registreModifie((ls) => ls.filter((l, k) => !(k === ls.length - 1)));
      const retiree = (() => {
        const d = fs.readdirSync(ev.registreArchive).sort()[0];
        return JSON.parse(fs.readFileSync(path.join(ev.registreArchive, d), "utf8").trim().split("\n").at(-1)).key;
      })();
      const dest = path.join(dir, "ok-non-inscrite");
      const r = await ctl(["worm", "reconstruire", "--configuration", ev.B.fichier, "--vers", dest, "--registre-copies", reg]);
      expect(r.code, r.erreur).to.equal(0);
      expect(r.lignes.filter((x) => x.event === "worm_restore_unregistered").map((x) => x.data.key)).to.deep.equal([retiree]);
      const rel = retiree.slice(ev.worm.prefix.length);
      const rep = path.join(dest, ev.A.config.recorder.org_id.slice(2), ev.journal_id.slice(2));
      expect(fs.existsSync(path.join(rep, ...rel.split("/"))), rel).to.equal(true);
    });

    it("copie d'une autre version : une seconde version posée par un autre rôle — sans registre, versions_multiples (code 1) ; avec le registre, la version inscrite est restaurée (code 0) ; worm restaurer --version <autre> → version_non_inscrite (code 1), --version <inscrite> → code 0, SHA-256 égal ; destination dans l'original ou existante → code 2", async function () {
      const seg = ev.copies.find((x) => x.key.includes("/segments/"));
      const ops = admin();
      const r2 = { ...requeteS3Copie(seg.key, Buffer.from("seconde version, d'un autre role\n")) };
      r2.headers = r2.headers.filter(([h]) => h !== "If-None-Match");
      const autre = await ops.acces.envoyer(r2);
      expect(autre.statut).to.equal(200);
      const v2 = autre.entetes["x-amz-version-id"];
      const sans = await ctl(["worm", "reconstruire", "--configuration", ev.B.fichier, "--vers", path.join(dir, "echec-versions")]);
      expect(sans.code).to.equal(1);
      expect(sans.incidents).to.deep.include({ key: seg.key, kind: "versions_multiples", versions: 2 });
      const avec = await ctl(["worm", "reconstruire", "--configuration", ev.B.fichier, "--vers", path.join(dir, "ok-versions"), "--registre-copies", ev.registreArchive]);
      expect(avec.code, avec.erreur).to.equal(0);
      const d = path.join(dir, "restaurer-autre");
      const mauvaise = await ctl(["worm", "restaurer", seg.key, "--version", v2, "--configuration", ev.B.fichier, "--vers", d, "--registre-copies", ev.registreArchive]);
      expect(mauvaise.code).to.equal(1);
      expect(mauvaise.incidents[0].kind).to.equal("version_non_inscrite");
      expect(fs.existsSync(d)).to.equal(false);
      const bonne = await ctl(["worm", "restaurer", seg.key, "--version", seg.version_id, "--configuration", ev.B.fichier, "--vers", d, "--registre-copies", ev.registreArchive]);
      expect(bonne.code, bonne.erreur).to.equal(0);
      const fichier = path.join(d, seg.key.slice(ev.worm.prefix.length));
      expect(N.sha256Hex(new Uint8Array(fs.readFileSync(fichier)))).to.equal(seg.sha256);
      const dansOriginal = await ctl(["worm", "restaurer", seg.key, "--version", seg.version_id, "--configuration", ev.B.fichier, "--vers", path.join(ev.repB, "restaure"), "--registre-copies", ev.registreArchive]);
      expect(dansOriginal.code).to.equal(2);
      expect((await ctl(["worm", "restaurer", seg.key, "--version", seg.version_id, "--configuration", ev.B.fichier, "--vers", d, "--registre-copies", ev.registreArchive])).code).to.equal(2);
    });
  });
});
