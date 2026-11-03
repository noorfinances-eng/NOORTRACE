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
import { piecesReferencees } from "../paquets/enregistreur/src/worm/registre.mjs";
import { RACINE, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import {
  IMAGES, dockerDisponible, demarrerS3, demarrerPostgresql, arreterTout, certificats, mandataireTls, creerBucketVerrouille, identifiantsRole, attendre, portLibre,
} from "./fixtures/enregistreur-worm/outils.mjs";
import { configurationHa, ClientMcpHttp, lancerDemon, sante } from "./fixtures/enregistreur-ha/outils.mjs";
import { HorlogeReglable, pieceJson, reconstruireJournal, ErreurRestauration } from "@noortrace/enregistreur";
import { configurationDev, graine, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";

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
    // Aucune clôture de période pendant les écritures et l'archive : une clôture
    // copierait manifeste, signature, série et segment après l'archive.
    const avantHeure = 3600000 - (Date.now() % 3600000);
    if (avantHeure < 120000) await new Promise((r) => setTimeout(r, avantHeure + 15000));
    for (let k = 1; k <= 8; k++) expect((await h.appeler("demo__ecrire", { id: `R${k}`, montant: String(k) })).result.isError).to.equal(false);
    // Copies terminées avant l'archive : au moins deux segments fermés copiés, et
    // chaque pièce que référencent les segments copiés inscrite au registre. Avec
    // copy_pieces, les pièces d'un segment sont copiées APRÈS l'inscription de la
    // ligne du segment (src/worm/copies.mjs) ; une archive prise entre les deux
    // serait plus ancienne que des copies faites par A, que la reconstruction
    // restaure alors comme non inscrites (12.1 : le registre « ne fait foi de rien
    // et se reconstruit depuis la liste des versions ») : c'était la course
    // observée en intégration continue (10 fichiers pour 9 lignes archivées).
    const copiesTerminees = async () => {
      const lignes = (await lireRegistres(path.join(ev.repA, "worm"))).map((x) => x.ligne);
      const cles = new Set(lignes.map((l) => l.key));
      const segs = lignes.filter((l) => l.key.includes("/segments/"));
      if (segs.length < 2) return false;
      for (const l of segs) {
        const evts = fs.readFileSync(path.join(ev.repA, l.key.slice(worm.prefix.length)), "utf8").split("\n").filter(Boolean).slice(1).map((x) => JSON.parse(x));
        for (const s of piecesReferencees(evts)) {
          const hx = s.slice(2);
          if (fs.existsSync(path.join(ev.repA, "pieces", hx.slice(0, 2), hx)) && !cles.has(`${worm.prefix}pieces/${hx.slice(0, 2)}/${hx}`)) return false;
        }
      }
      return true;
    };
    await attendre(copiesTerminees, 60000);
    // 2. A est tué (aucune copie en cours), puis le registre est archivé (chemin A) et son stockage local détruit.
    dA.kill("SIGKILL");
    await dA.fin;
    ev.registreArchive = path.join(dir, "archive-worm");
    fs.cpSync(path.join(ev.repA, "worm"), ev.registreArchive, { recursive: true });
    ev.evtsA = await lireEvenements(ev.repA);
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

// Relecture adversariale A, R-A-6 (EX-12.10 pas 2, CT-8 EX-11.6, chemin B) :
// sans registre des copies, la reconstruction acceptait un segment fermé
// altéré puis rechaîné (hash recalculés, signatures d'origine) et une pièce
// dont le contenu n'est pas celui de son nom ; le démon reprenait dessus.
// Ces cas n'ont pas besoin de Docker : les copies sont servies en mémoire.
describe("reconstruction depuis les copies : signatures, pièces, signatures de manifeste et séries vérifiées (R-A-6)", function () {
  this.timeout(120000);
  const ms = (t) => N.decoderHorodatage(t);
  const delegation = { launched_by: "x", on_behalf_of: null, scope: "s", run_id: null };
  async function echange(c, k) {
    const p = pieceJson({ k });
    await c.ecrirePiece(p);
    return c.scellerEchange({ delegation, code: { model: null, prompt_version: null }, intent: null, requete: p.reference, reponse: p.reference, duration_ms: k, is_error: false });
  }

  /** Journal de deux périodes closes (une rotation de clé dans la première), copies de tous ses fichiers restaurables. */
  async function journalEtCopies(nom) {
    const dir = repertoireTemporaire(`noortrace-reconstruction-${nom}-`);
    const { config } = configurationDev(dir, { journal_id: N.octetsVersHex(N.keccak256(N.utf8(`journal-reconstruction-${nom}`))) });
    const h = new HorlogeReglable(ms("2026-11-10T10:14:00.000Z"));
    let c = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: h });
    for (let k = 1; k <= 3; k++) {
      h.avancer(1000);
      await echange(c, k);
    }
    await c.tournerCle("rec-test-02");
    await echange(c, 4);
    h.aller(ms("2026-11-10T11:00:00.300Z"));
    await c.tic();
    h.aller(ms("2026-11-10T11:05:00.000Z"));
    await echange(c, 5);
    h.aller(ms("2026-11-10T12:00:00.300Z"));
    await c.tic();
    await c.arreter();
    h.aller(ms("2026-11-10T12:06:00.000Z"));
    c = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: h });
    await c.arreter();
    const rep = c.repertoire;
    const objets = new Map();
    const parcourir = (d, rel = "") => {
      for (const n of fs.readdirSync(d)) {
        const p = path.join(d, n);
        const r = rel ? `${rel}/${n}` : n;
        if (fs.statSync(p).isDirectory()) parcourir(p, r);
        else objets.set(`j/${r}`, fs.readFileSync(p));
      }
    };
    parcourir(rep);
    const operations = {
      listerVersions: async () => ({ statut: 200, versions: [...objets.keys()].map((key) => ({ key, version_id: "v1", delete_marker: false })) }),
      lire: async (key) => ({ statut: 200, corps: objets.get(key) }),
    };
    const configWorm = structuredClone(config);
    configWorm.storage.seal.worm = { prefix: "j/" };
    return { dir, config, configWorm, objets, operations };
  }

  const reconstruire = (j, nom, o = {}) => reconstruireJournal({ config: j.configWorm, operations: j.operations, destination: path.join(j.dir, nom), registre: null, ...o });
  async function refus(j, nom, o) {
    let err;
    try {
      await reconstruire(j, nom, o);
    } catch (e) {
      err = e;
    }
    expect(err, "reconstruction refusée").to.be.instanceOf(ErreurRestauration);
    expect(fs.existsSync(path.join(j.dir, nom)), "rien n'est écrit").to.equal(false);
    return err.incidents;
  }

  it("copies intactes (rotation de clé comprise) : acceptées, signatures vérifiées avec les clés de la chaîne", async function () {
    const j = await journalEtCopies("intact");
    const r = await reconstruire(j, "restaure");
    expect(r.synthese.last_seq).to.be.greaterThan(5);
  });

  it("essai de la relecture : segment fermé altéré et rechaîné, manifeste recalculé, pièce falsifiée → refusée (signature, sha256 de la pièce)", async function () {
    const j = await journalEtCopies("altere");
    const segs = [...j.objets.keys()].filter((k) => k.startsWith("j/segments/")).sort();
    let prev = null;
    const nouveaux = new Map();
    for (const k of segs) {
      const lignes = j.objets.get(k).toString("utf8").split("\n").filter(Boolean);
      const entete = JSON.parse(lignes[0]);
      if (prev) entete.prev_hash = prev;
      const evts = lignes.slice(1).map((l) => JSON.parse(l));
      for (const e of evts) {
        if (prev) e.prev_hash = prev;
        if (e.seq === 3) e.execution.duration_ms = 999999;
        e.hash = N.hacherEvenement(e);
        prev = e.hash;
        nouveaux.set(e.seq, e.hash);
      }
      j.objets.set(k, Buffer.from([entete, ...evts].map((o) => N.jcs(o)).join("\n") + "\n"));
    }
    for (const k of [...j.objets.keys()].filter((x) => /manifestes\/.*\.json$/.test(x))) {
      const m = JSON.parse(j.objets.get(k).toString("utf8"));
      const hs = [];
      for (let q = m.first_seq; q <= m.last_seq; q++) hs.push(nouveaux.get(q));
      j.objets.set(k, Buffer.from(JSON.stringify(N.construireManifeste({ ...m, hashes: hs }), null, 2) + "\n"));
    }
    const clePiece = [...j.objets.keys()].find((x) => x.includes("/pieces/"));
    j.objets.set(clePiece, Buffer.from('{"falsifie":true}'));
    const incidents = await refus(j, "restaure");
    expect(incidents.map((i) => `${i.kind}:${i.raison ?? ""}`)).to.include.members(["copie_alteree:signature", "copie_alteree:sha256_piece"]);
  });

  it("pièce seule falsifiée (chaîne intacte) → refusée (sha256_piece)", async function () {
    const j = await journalEtCopies("piece");
    const clePiece = [...j.objets.keys()].find((x) => x.includes("/pieces/"));
    j.objets.set(clePiece, Buffer.from('{"falsifie":true}'));
    expect((await refus(j, "restaure")).map((i) => i.raison)).to.deep.equal(["sha256_piece"]);
  });

  it("signature de manifeste remplacée, série de points altérée → refusées (signature_manifeste, serie_points)", async function () {
    const j = await journalEtCopies("sig");
    const cleSig = [...j.objets.keys()].find((x) => x.endsWith(".sig"));
    const s = JSON.parse(j.objets.get(cleSig).toString("utf8"));
    s.sig = `0x${"11".repeat(64)}`;
    j.objets.set(cleSig, Buffer.from(JSON.stringify(s, null, 2) + "\n"));
    expect((await refus(j, "r1")).map((i) => i.raison)).to.deep.equal(["signature_manifeste"]);
    const k = await journalEtCopies("serie");
    const cleSerie = [...k.objets.keys()].find((x) => x.startsWith("j/points/"));
    const lignes = k.objets.get(cleSerie).toString("utf8").trim().split("\n").map((l) => JSON.parse(l));
    lignes[0].checkpoint_ts = "2026-11-10T10:59:59.999Z";
    k.objets.set(cleSerie, Buffer.from(lignes.map((l) => JSON.stringify(l)).join("\n") + "\n"));
    expect((await refus(k, "r2")).map((i) => i.raison)).to.deep.equal(["serie_points"]);
  });

  it("clé initiale inconnue (ni --cles, ni signataire de classe D) → refusée (cle_inconnue) ; donnée par cles.json → acceptée", async function () {
    const j = await journalEtCopies("cles");
    expect((await refus(j, "r1", { clePublique: async () => null })).map((i) => i.kind)).to.include("cle_inconnue");
    const publique = N.octetsVersHex(N.clePubliqueEd25519(graine("rec-test-01")));
    const r = await reconstruire(j, "r2", { clePublique: async (id) => (id === "rec-test-01" ? publique : null) });
    expect(r.synthese.fichiers).to.be.greaterThan(5);
  });

  it("démon sur un journal reconstruit puis altéré (segment fermé rechaîné) : vérification complète avant d'écrire → segment_corrupted, intervention, rien n'est écrit", async function () {
    const j = await journalEtCopies("demon");
    const r = await reconstruire(j, "restaure");
    const rep = path.join(r.synthese.destination, j.config.recorder.org_id.slice(2), j.config.recorder.journal_id.slice(2));
    const premier = path.join(rep, "segments", fs.readdirSync(path.join(rep, "segments")).sort()[0]);
    const lignes = fs.readFileSync(premier, "utf8").split("\n").filter(Boolean);
    const e = JSON.parse(lignes[3]);
    e.execution.duration_ms = 424242;
    e.hash = N.hacherEvenement(e);
    lignes[3] = N.jcs(e);
    fs.writeFileSync(premier, lignes.join("\n") + "\n");
    const avant = fs.readdirSync(path.join(rep, "segments")).length;
    const config2 = structuredClone(j.config);
    config2.storage.root = r.synthese.destination;
    const c = await Coeur.demarrer({ config: config2, secrets: secretsDev(), horloge: new HorlogeReglable(ms("2026-11-10T12:10:00.000Z")) });
    try {
      expect(c.journal.trouver("segment_corrupted")).to.have.length(1);
      expect(c.sante().corps.reasons).to.deep.equal(["stockage"]);
      expect(fs.readdirSync(path.join(rep, "segments")).length, "aucun segment ouvert").to.equal(avant);
    } finally {
      await c.arreter();
    }
    // Sans altération, le démon reprend sur le journal reconstruit (vérification réussie consignée).
    const k = await journalEtCopies("demon-ok");
    const r2 = await reconstruire(k, "restaure");
    const config3 = structuredClone(k.config);
    config3.storage.root = r2.synthese.destination;
    const c3 = await Coeur.demarrer({ config: config3, secrets: secretsDev(), horloge: new HorlogeReglable(ms("2026-11-10T12:10:00.000Z")) });
    try {
      expect(c3.journal.trouver("journal_reconstruit_verifie")[0].data.incidents).to.deep.equal([]);
      expect(c3.sante().corps).to.deep.equal({ status: "ok" });
    } finally {
      await c3.arreter();
    }
  });
});
