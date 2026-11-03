// Haute disponibilité et WORM : parcours de bout en bout avec de vrais
// processus et de vrais services (CT-2 §13.4, §13.5, §12.6, §12.11).
//
// Pour chaque magasin de bail réel (PostgreSQL, puis etcd) : deux démons
// réels `bin/noortrace --config` sur le même journal et le même stockage
// (13.1), même configuration hors identité d'instance et adresses d'écoute.
// Un hôte de test parle au frontal MCP (Streamable HTTP, jeton statique, ère
// héritée) ; les appels sont relayés à un serveur d'outils stdio lancé par le
// démon ; le service d'approbation est simulé et joint en HTTP. A écrit
// (lecture, écritures ; segments tournés par taille et copiés) ; B attend
// (`standby`, `-31010 bail_non_detenu`) ; A est tué (SIGKILL) pendant le relais
// d'une écriture ; B prend le bail avec une époque plus grande, relit le
// journal, produit l'événement de reprise de l'intention en vol (13.5) et
// reprend. Puis une instance du cœur clôt la période à l'heure suivante :
// chaque segment fermé et chaque clôture (manifeste, signature, série des
// points) est copié sur le support WORM réel (S3 à Object Lock), verrouillé
// en mode COMPLIANCE ; un gel est posé et levé par `bin/noortrace-ctl worm
// gel` selon 12.11 (deux personnes) ; le journal est accepté par
// `N.verifierJournal` ; les dossiers d'un événement écrit par A et d'un
// événement écrit par B sont valides pour le noyau ET pour le binaire Go
// `noortrace-verifier` (construit par verificateur/scripts/construire.sh avec
// go1.27.3, répertoire de `go` dans NOORTRACE_GO_BIN ; sans lui, ces deux
// vérifications sont en attente). Enfin (PostgreSQL), deux démons se
// disputent le journal : A figé (SIGSTOP) au-delà du TTL, B prend le bail ;
// A, repris (SIGCONT), constate la perte et redevient passif.
// Sans Docker, tout est en attente et le titre nomme la condition.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import { verifierRepertoireDossier } from "@noortrace/noyau/dossier-fichiers";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import {
  Coeur, validerConfiguration, resoudreSecrets, supportWormDepuisConfiguration, lireEvenements, lireRegistres, OperationsS3, identifiantsS3,
  controlerVerrou, echeanceMinimale,
} from "@noortrace/enregistreur";
import { RACINE, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import {
  IMAGES, dockerDisponible, demarrerS3, demarrerPostgresql, demarrerEtcd, arreterTout, certificats, mandataireTls, creerBucketVerrouille,
  identifiantsRole, fichierSecret, attendre, portLibre,
} from "./fixtures/enregistreur-worm/outils.mjs";
import { configurationHa, ClientMcpHttp, demarrerDemon, sante } from "./fixtures/enregistreur-ha/outils.mjs";

const BIN_CTL = path.join(RACINE, "paquets", "enregistreur", "bin", "noortrace-ctl");

/** Construit noortrace-verifier avec go1.27.3 (GOFLAGS limité à cette commande), ou rend null. */
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

function verifierParGo(bin, dossier) {
  const r = spawnSync(bin, [dossier, "--json"], { encoding: "utf8" });
  expect(r.status, r.stdout + r.stderr).to.equal(0);
  const rapport = JSON.parse(r.stdout);
  expect(rapport.verdict, dossier).to.equal("valide");
  expect(rapport.failed_checks).to.deep.equal([]);
  return rapport;
}

/** `bin/noortrace-ctl` en processus réel. */
function ctl(args, env) {
  return new Promise((res) => {
    const p = spawn(process.execPath, [BIN_CTL, ...args], { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
    let sortie = "";
    let erreur = "";
    p.stdout.on("data", (d) => (sortie += d));
    p.stderr.on("data", (d) => (erreur += d));
    p.on("exit", (code) => res({ code, sortie, erreur }));
  });
}

/** Horloge réelle décalée dans l'heure suivante, de moins d'une heure (tolérance d'EX-12.33). */
function horlogeHeureSuivante() {
  const d = 3600000 - (Date.now() % 3600000) + 3000;
  return { murale: () => Date.now() + d, monotone: () => performance.now() + 1e7 + d };
}

describe("haute disponibilité et WORM : parcours de bout en bout (deux démons réels, magasins de bail et support WORM réels)", function () {
  this.timeout(900000);
  const docker = dockerDisponible([IMAGES.s3, IMAGES.postgresql, IMAGES.etcd]);
  let dir;
  let s3;
  let pg;
  let etcd;
  let tls;
  let prox;
  let service;
  let serveurService;
  let bin = null;

  before(async function () {
    if (!docker.ok) return;
    dir = repertoireTemporaire("noortrace-ha-parcours-");
    [s3, pg, etcd] = await Promise.all([
      demarrerS3(`noortrace-test-parcours-s3-${process.pid}`),
      demarrerPostgresql(`noortrace-test-parcours-pg-${process.pid}`),
      demarrerEtcd(`noortrace-test-parcours-etcd-${process.pid}`),
    ]);
    tls = certificats(path.join(dir, "tls"));
    prox = await mandataireTls(tls, { port: s3.port });
    service = new ServiceApprobationFactice({ org_id: "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab", journal_id: null });
    serveurService = await service.servir(0);
    bin = construireVerificateur(dir);
  });

  after(async function () {
    serveurService?.close();
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

  /** Prépare deux configurations (A, B) sur un journal et un bucket neufs. */
  async function preparer(type, nom) {
    const d = path.join(dir, nom);
    const bucket = `noortrace-parcours-${process.pid}-${nom}`;
    await creerBucketVerrouille(prox.origine, bucket, { ca: tls.caPem });
    const journal_id = N.octetsVersHex(N.keccak256(N.utf8(`journal-parcours-${process.pid}-${nom}`)));
    service.journal_id = journal_id;
    const worm = { type: "s3-object-lock", bucket, prefix: `${nom}/`, mode: "compliance", retain_days: 4018, endpoint: prox.origine, region: null, legal_hold_on_write: false, lock_audit_interval_days: 30, copy_pieces: false };
    const store = type === "postgresql" ? { type, table: `bail_${nom.replace(/-/g, "_")}` } : { type, endpoints: [etcd.origine], prefix: "/noortrace/parcours/", tls: null };
    const commun = { journal_id, store, dsn: pg.dsn, approbation: serveurService.address().port, worm, segment_max_bytes: 6144 };
    const A = configurationHa(d, { ...commun, instance: "inst-a", portHttp: await portLibre(), portSante: await portLibre() });
    const B = configurationHa(d, { ...commun, instance: "inst-b", portHttp: await portLibre(), portSante: await portLibre() });
    for (const [x, f] of [[A, "a.json"], [B, "b.json"]]) {
      const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(x.config)));
      expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
      x.fichier = path.join(d, f);
      fs.writeFileSync(x.fichier, JSON.stringify(x.config));
      x.port = Number(x.config.supervision.health_listen.split(":")[1]);
      x.env = { ...x.env, NODE_EXTRA_CA_CERTS: tls.ca };
    }
    const repertoire = path.join(A.config.storage.root, A.config.recorder.org_id.slice(2), journal_id.slice(2));
    return { d, bucket, A, B, repertoire, worm };
  }

  const admin = (worm) => new OperationsS3({ worm, identifiants: identifiantsS3(new TextEncoder().encode(identifiantsRole("administrateur"))), tls: { ca: tls.caPem } });

  for (const type of ["postgresql", "etcd"]) {
    describe(`magasin de bail ${type}`, function () {
      const ev = {};

      before(async function () {
        if (!docker.ok) return;
        const p = await preparer(type, `parcours-${type}`);
        Object.assign(ev, p);
        const { A, B } = p;
        // 1. A démarre et prend le bail ; l'hôte appelle (lecture, écritures).
        // Ports d'écoute réattribués si l'un d'eux a été pris avant l'ouverture (EADDRINUSE).
        const dA = await demarrerDemon(A, "ok").catch((e) => {
          throw new Error(`A : ${e.message}`);
        });
        ev.dA = dA;
        const hA = new ClientMcpHttp(A.config.mcp.http.listen);
        await hA.ouvrir();
        ev.reponsesA = [];
        ev.reponsesA.push(await hA.appeler("demo__lire", { id: "S1" }));
        for (let k = 2; k <= 6; k++) ev.reponsesA.push(await hA.appeler("demo__ecrire", { id: `S${k}`, montant: String(10 * k) }));
        // 2. B démarre : instance passive.
        const dB = await demarrerDemon(B, "standby").catch((e) => {
          throw new Error(`B : ${e.message}`);
        });
        ev.dB = dB;
        ev.santeB = await sante(B.port);
        const hB = new ClientMcpHttp(B.config.mcp.http.listen);
        await hB.ouvrir();
        ev.reponseBPassive = await hB.appeler("demo__lire", { id: "S-passif" });
        // 3. Une écriture en vol chez A ; A est tué (SIGKILL) pendant le relais.
        const intentions = path.join(p.repertoire, "intentions");
        ev.lent = hA.appeler("demo__ecrire_lent", { id: "S-vol", attente_ms: 120000 }).catch((e) => ({ coupure: e.code ?? e.message }));
        await attendre(() => fs.readdirSync(intentions).some((n) => fs.readFileSync(path.join(intentions, n), "utf8").includes("demo__ecrire_lent")), 30000, 50);
        ev.epoqueA = Number(dA.lignes().find((l) => l.event === "lease_acquired").data.epoch);
        dA.kill("SIGKILL");
        ev.finA = await dA.fin;
        ev.lent = await ev.lent;
        // 4. B prend le bail, relit, reprend.
        await attendre(async () => (await sante(B.port))?.corps?.status === "ok", 60000).catch((e) => {
          throw new Error(`B actif : ${e.message}\n${dB.sortie}`);
        });
        const hB2 = new ClientMcpHttp(B.config.mcp.http.listen);
        await hB2.ouvrir();
        ev.reponsesB = [await hB2.appeler("demo__ecrire", { id: "S-B1", montant: "70" }), await hB2.appeler("demo__lire", { id: "S-B2" })];
        dB.kill("SIGTERM");
        ev.finB = await dB.fin;
        ev.lignesB = dB.lignes();
        // 5. Une instance du cœur clôt la période à l'heure suivante ; copies WORM.
        const v = validerConfiguration(new TextEncoder().encode(JSON.stringify({ ...B.config, recorder: { ...B.config.recorder, instance_id: "inst-c" } })));
        const s = resoudreSecrets(v.config, { env: B.env });
        const worm = supportWormDepuisConfiguration(v.config, s.secrets, { tls: { ca: tls.caPem } });
        const C = await Coeur.demarrer({ config: v.config, secrets: s.secrets, worm, horloge: horlogeHeureSuivante() });
        ev.C = C;
        await C.tic();
        await worm.vider();
        await worm.balayer();
        ev.evts = await lireEvenements(p.repertoire);
        ev.registre = (await lireRegistres(path.join(p.repertoire, "worm"))).map((x) => x.ligne);
      });

      after(async function () {
        ev.dA?.kill("SIGKILL");
        ev.dB?.kill("SIGKILL");
        await ev.C?.arreter();
      });

      it("A actif : chaque appel répondu ; B passif : santé standby, -31010 bail_non_detenu (13.4 pas 1, 14.2)", function () {
        for (const r of ev.reponsesA) expect(r.result?.isError, JSON.stringify(r)).to.equal(false);
        expect(ev.santeB.corps).to.deep.equal({ status: "standby" });
        expect(ev.reponseBPassive.error).to.deep.include({ code: -31010 });
        expect(ev.reponseBPassive.error.data).to.deep.equal({ reason: "bail_non_detenu" });
      });

      it("A tué pendant un relais d'écriture ; B prend le bail avec une époque plus grande, consigne la taille des fichiers d'époque inférieure, produit l'événement de reprise de l'intention en vol (13.4 pas 3 à 6, 13.5) ; arrêt propre de B", function () {
        expect(ev.finA.signal).to.equal("SIGKILL");
        const acq = ev.lignesB.filter((l) => l.event === "lease_acquired");
        expect(acq).to.have.length(1);
        expect(acq[0].data.epoch).to.be.greaterThan(ev.epoqueA);
        expect(acq[0].data.store).to.equal(type);
        expect(ev.lignesB.findIndex((l) => l.event === "lease_standby")).to.be.below(ev.lignesB.findIndex((l) => l.event === "lease_acquired"));
        expect(ev.lignesB.find((l) => l.event === "lease_predecessor_files").data.files.length).to.be.greaterThan(0);
        expect(ev.lignesB.filter((l) => l.event === "intent_recovered")).to.have.length(1);
        expect(ev.lignesB.filter((l) => l.event === "journal_fork")).to.have.length(0);
        for (const r of ev.reponsesB) expect(r.result?.isError, JSON.stringify(r)).to.equal(false);
        expect(ev.finB.code).to.equal(0);
      });

      it("sans perte au-delà de ce que 13.5 admet : chaque appel répondu par A a son événement ; l'écriture en vol a un événement de reprise ; seq sans trou ; segments d'époques croissantes", async function () {
        const appels = ev.evts.filter((e) => e.execution.tool.startsWith("demo__"));
        const tools = appels.map((e) => [e.execution.tool, e.execution.status, e.execution.is_error]);
        expect(tools.filter(([t, , err]) => t === "demo__lire" && !err)).to.have.length(2);
        expect(tools.filter(([t, , err]) => t === "demo__ecrire" && !err)).to.have.length(6);
        const reprise = appels.find((e) => e.execution.tool === "demo__ecrire_lent");
        expect(reprise.execution).to.include({ status: "executee", is_error: true, duration_ms: 0 });
        const piece = JSON.parse(fs.readFileSync(path.join(ev.repertoire, "pieces", reprise.execution.result.sha256.slice(2, 4), reprise.execution.result.sha256.slice(2)), "utf8"));
        expect(piece.noortrace_reprise).to.equal("resultat inconnu : enregistreur arrete pendant le relais");
        ev.evts.forEach((e, k) => expect(e.seq).to.equal(k + 1));
        const segs = fs.readdirSync(path.join(ev.repertoire, "segments")).sort();
        const epoques = segs.map((s) => Number(s.slice(21, 41)));
        expect(new Set(epoques).size).to.be.at.least(3);
        for (let k = 1; k < segs.length; k++) expect(Number(segs[k].slice(4, 20))).to.be.at.least(Number(segs[k - 1].slice(4, 20)));
        expect(segs.filter((s) => Number(s.slice(21, 41)) === ev.epoqueA).length, "segments tournés par A").to.be.at.least(2);
      });

      it("WORM réel : chaque segment fermé et chaque clôture (manifeste, signature, série des points) copiés, octets identiques, verrouillés en COMPLIANCE jusqu'à copied_at + 4 018 jours (EX-12.16, EX-12.29, EX-12.33)", async function () {
        const segs = fs.readdirSync(path.join(ev.repertoire, "segments")).sort();
        const courant = ev.C.ecrivain.segment.nom;
        const attendues = segs.filter((s) => s !== courant).map((s) => `${ev.worm.prefix}segments/${s}`);
        const manifestes = fs.readdirSync(path.join(ev.repertoire, "manifestes"));
        expect(manifestes.length).to.be.at.least(2);
        for (const m of manifestes) attendues.push(`${ev.worm.prefix}manifestes/${m}`);
        for (const m of manifestes.filter((x) => x.endsWith(".sig"))) attendues.push(`${ev.worm.prefix}points/${m.replace(".sig", ".ndjson")}`);
        const cles = ev.registre.map((l) => l.key);
        expect(cles).to.include.members(attendues);
        // Copies faites par A (segments tournés), par B (dernier segment de A) et par la clôture.
        expect(fs.readdirSync(path.join(ev.repertoire, "worm")).length).to.be.at.least(3);
        const ops = admin(ev.worm);
        for (const l of ev.registre.filter((x) => attendues.includes(x.key))) {
          const e = await ops.empreinte(l.key, l.version_id);
          expect(e.sha256, l.key).to.equal(l.sha256);
          const et = await ops.etat(l.key, l.version_id);
          const v = controlerVerrou({ type: "s3-object-lock", entetes: et.entetes, mode: "compliance", echeanceMin: echeanceMinimale(N.decoderHorodatage(l.copied_at), 4018), gelAttendu: false });
          expect(v.verdict, `${l.key} ${JSON.stringify(v)}`).to.equal("conforme");
          expect(v.mode).to.equal("COMPLIANCE");
        }
        // Le rôle de l'écrivain n'a rien écrit sous <prefix>gels/ (EX-12.32).
        expect((await ops.listerVersions(`${ev.worm.prefix}gels/`)).versions).to.deep.equal([]);
      });

      it("gel juridique par bin/noortrace-ctl (12.11) : pose par un gardien de pose, demande de levée, levée par une autre personne ; versions ON puis OFF ; registre relu par le rôle Lecteur", async function () {
        const P = Math.floor(N.decoderHorodatage(ev.evts[0].ts) / 3600000) * 3600;
        const env = { ...ev.B.env };
        const ref = (role) => JSON.stringify({ file: fichierSecret(path.join(ev.d, "secrets", role), identifiantsRole(role)) });
        const pose = await ctl(["worm", "gel", "poser", "--configuration", ev.B.fichier, "--identifiants", ref("gardien-pose"), "--identite", "a.gardien@client.example", "--de", String(P), "--a", String(P), "--motif", "Litige de parcours", "--journal-exploitation", path.join(ev.d, "gel.ndjson")], env);
        expect(pose.code, pose.erreur).to.equal(0);
        const gel = pose.sortie.trim();
        const ops = admin(ev.worm);
        const enreg = JSON.parse((await ops.lire(`${ev.worm.prefix}gels/${gel}/0001-pose.json`)).corps.toString("utf8"));
        const objets = (await ops.lire(enreg.objects.key)).corps.toString("utf8").trim().split("\n").map((l) => JSON.parse(l));
        expect(objets.map((o) => o.key)).to.include.members(ev.registre.filter((l) => l.key.includes("/segments/")).map((l) => l.key).filter((k) => objets.some((o) => o.key === k)));
        for (const o of objets) expect(ops.etatGel(await ops.lireGel(o.key, o.version_id)), o.key).to.equal("on");
        const demande = await ctl(["worm", "gel", "demander-levee", "--configuration", ev.B.fichier, "--identifiants", ref("gardien-pose"), "--identite", "a.gardien@client.example", "--gel", gel, "--motif", "Litige clos"], env);
        expect(demande.code, demande.erreur).to.equal(0);
        const refus = await ctl(["worm", "gel", "lever", "--configuration", ev.B.fichier, "--identifiants", ref("gardien-levee"), "--identite", "a.gardien@client.example", "--gel", gel, "--demande", demande.sortie.trim()], env);
        expect(refus.code).to.equal(3);
        const levee = await ctl(["worm", "gel", "lever", "--configuration", ev.B.fichier, "--identifiants", ref("gardien-levee"), "--identite", "b.gardien@client.example", "--gel", gel, "--demande", demande.sortie.trim()], env);
        expect(levee.code, levee.erreur).to.equal(0);
        for (const o of objets) expect(ops.etatGel(await ops.lireGel(o.key, o.version_id)), o.key).to.equal("off");
        const etat = await ctl(["worm", "gel", "etat", "--configuration", ev.B.fichier, "--identifiants", ref("lecteur"), "--gel", gel], env);
        expect(etat.code).to.equal(0);
        expect(JSON.parse(etat.sortie)).to.include({ actif: false, garde: "respectee" });
        const lignes = fs.readFileSync(path.join(ev.d, "gel.ndjson"), "utf8");
        expect(lignes).to.contain('"event":"worm_legal_hold_set"');
        expect(lignes).to.not.contain("a.gardien@client.example");
      });

      it("le journal est accepté par N.verifierJournal (CT-1 §7, E-1 à E-11)", async function () {
        const d = path.join(ev.d, "dossier-cles");
        await ev.C.exporterDossier(ev.evts.find((e) => e.execution.tool === "demo__lire").seq, d);
        const cles = JSON.parse(fs.readFileSync(path.join(d, "cles.json"), "utf8"));
        const r = N.verifierJournal(ev.evts, cles);
        expect(r.valide, JSON.stringify(r.diagnostics)).to.equal(true);
      });

      it("dossiers d'un événement écrit par A et d'un événement écrit par B : valides pour le noyau ET pour le binaire Go (go1.27.3)", async function () {
        const parA = ev.evts.find((e) => e.execution.tool === "demo__ecrire" && e.seq < ev.evts.find((x) => x.execution.tool === "demo__ecrire_lent").seq);
        const parB = ev.evts.filter((e) => e.execution.tool === "demo__ecrire").at(-1);
        expect(parB.seq).to.be.greaterThan(ev.evts.find((x) => x.execution.tool === "demo__ecrire_lent").seq);
        const dossiers = [];
        for (const [nom, e] of [["a", parA], ["b", parB]]) {
          const d = path.join(ev.d, `dossier-${nom}`);
          await ev.C.exporterDossier(e.seq, d);
          const r = verifierRepertoireDossier(d);
          expect(r.verdict, `${nom} : ${JSON.stringify(r.controles_en_echec)}`).to.equal("valide");
          dossiers.push(d);
        }
        if (!bin) {
          this.test.title += " — binaire Go en attente : go1.27.3 introuvable (NOORTRACE_GO_BIN)";
          this.skip();
        }
        for (const d of dossiers) verifierParGo(bin, d);
      });
    });
  }

  describe("deux démons se disputent le journal (PostgreSQL) : A figé au-delà du TTL", function () {
    it("B prend le bail ; A, repris, constate la perte (lease_lost), redevient passif (lease_standby) et rend -31010 bail_non_detenu ; aucune fourche ; journal valide", async function () {
      const p = await preparer("postgresql", "dispute");
      const { A, B } = p;
      const dA = await demarrerDemon(A, "ok");
      let dB = null;
      try {
        dB = await demarrerDemon(B, "standby");
        const hA = new ClientMcpHttp(A.config.mcp.http.listen);
        await hA.ouvrir();
        expect((await hA.appeler("demo__ecrire", { id: "D1", montant: "1" })).result.isError).to.equal(false);
        dA.kill("SIGSTOP");
        await attendre(async () => (await sante(B.port))?.corps?.status === "ok", 60000);
        dA.kill("SIGCONT");
        await attendre(() => dA.lignes().some((l) => l.event === "lease_lost"), 30000, 100);
        await attendre(() => dA.lignes().filter((l) => l.event === "lease_standby").length >= 1 && dA.lignes().findLastIndex((l) => l.event === "lease_standby") > dA.lignes().findIndex((l) => l.event === "lease_lost"), 30000, 100);
        await attendre(async () => (await sante(A.port))?.corps?.status === "standby", 30000);
        const hA2 = new ClientMcpHttp(A.config.mcp.http.listen);
        await hA2.ouvrir();
        expect((await hA2.appeler("demo__ecrire", { id: "D2", montant: "2" })).error.data).to.deep.equal({ reason: "bail_non_detenu" });
        const hB = new ClientMcpHttp(B.config.mcp.http.listen);
        await hB.ouvrir();
        expect((await hB.appeler("demo__ecrire", { id: "D3", montant: "3" })).result.isError).to.equal(false);
        dB.kill("SIGTERM");
        await dB.fin;
        dA.kill("SIGTERM");
        await dA.fin;
        expect(dB.lignes().filter((l) => l.event === "journal_fork")).to.deep.equal([]);
        const evts = await lireEvenements(p.repertoire);
        evts.forEach((e, k) => expect(e.seq).to.equal(k + 1));
        expect(evts.filter((e) => e.execution.tool === "demo__ecrire").map((e) => e.execution.is_error)).to.deep.equal([false, false]);
        const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(B.config)));
        const s = resoudreSecrets(v.config, { env: B.env });
        const C = await Coeur.demarrer({ config: v.config, secrets: s.secrets, horloge: horlogeHeureSuivante() });
        try {
          await C.tic();
          const d = path.join(p.d, "dossier");
          await C.exporterDossier(evts.at(-1).seq, d);
          const cles = JSON.parse(fs.readFileSync(path.join(d, "cles.json"), "utf8"));
          const r = N.verifierJournal(await lireEvenements(p.repertoire), cles);
          expect(r.valide, JSON.stringify(r.diagnostics)).to.equal(true);
        } finally {
          await C.arreter();
        }
      } finally {
        for (const x of [dA, dB]) {
          x?.kill("SIGCONT");
          x?.kill("SIGKILL");
        }
      }
    });
  });
});
