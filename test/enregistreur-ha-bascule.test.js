// TE-11 de CT-9 : haute disponibilité à écrivain unique (CT-2 §13), de bout
// en bout, pour le magasin de bail `file` puis pour `etcd` (etcd 3.5 réel,
// image épinglée par condensé, lancé dans Docker). Deux démons réels
// `bin/noortrace --config` sur le même journal et le même stockage (13.1) ; un
// hôte de test (Streamable HTTP, jeton statique) ; un serveur d'outils stdio
// de test ; service d'approbation simulé joint en HTTP.
//
//   1. A prend le bail et sert : une lecture, trois écritures ; B attend
//      (`standby`, -31010 `bail_non_detenu`).
//   2. Une écriture lente est relayée par A (intention durable), puis
//      l'instance titulaire est coupée de son bail sans être tuée : `file`,
//      l'auxiliaire `flock(1)` qui tient son verrou est tué (instance
//      isolée, 13.4 pas 2) ; `etcd`, A est figée (SIGSTOP) au-delà de
//      `lease.ttl_ms`. La bascule est mesurée sur l'horloge monotone du test,
//      de la coupure à la santé `ok` de B (13.4 pas 3 à 7), et bornée par
//      `lease.ttl_ms` + `lease.renew_ms` + 10 s de relecture.
//   3. B écrit ; l'ancienne instance A (reprise par SIGCONT pour `etcd`)
//      tente une écriture : refusée (-31010, ligne `lease_lost`, EX-13.6) ;
//      l'écriture lente, exécutée côté serveur, n'est pas rendue comme
//      acquise par A (-31017 ou coupure).
//   4. Les segments et le journal d'intention sont relus : une seule chaîne
//      (seq et prev_hash continus, aucun événement d'époque inférieure après
//      la première époque de B, aucune ligne `journal_fork`), segments
//      d'époques croissantes, l'intention de l'écriture en vol levée par son
//      événement de reprise (13.5 : seule perte admise pour un appel
//      d'écriture en vol) ; chaque appel répondu par A ou par B a son
//      événement.
//   5. Une instance du cœur clôt la période à l'heure suivante ; le journal
//      est accepté par le noyau, et les dossiers d'un événement écrit par A et
//      d'un événement écrit par B sont valides pour le noyau ET pour le
//      binaire Go `noortrace-verifier` (go1.27.3, NOORTRACE_GO_BIN ; sans lui,
//      cette dernière vérification est en attente).
// Sans Docker, le magasin `etcd` est en attente et son titre nomme la condition.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import { verifierRepertoireDossier } from "@noortrace/noyau/dossier-fichiers";
import { Coeur, validerConfiguration, resoudreSecrets, lireEvenements } from "@noortrace/enregistreur";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { RACINE, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { IMAGES, dockerDisponible, demarrerEtcd, arreterTout } from "./fixtures/enregistreur-worm/outils.mjs";
import { configurationHa } from "./fixtures/enregistreur-ha/outils.mjs";
import {
  REFERENCE, SERVEUR_OUTILS, demarrer, arreter, attendre, sante, appelerOutil, portLibre, repertoireJournal, tuerAuxiliaireBail,
} from "./fixtures/enregistreur-adversarial/demon.mjs";

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

/** Horloge réelle décalée dans l'heure suivante, de moins d'une heure. */
function horlogeHeureSuivante() {
  const d = 3600000 - (Date.now() % 3600000) + 3000;
  return { murale: () => Date.now() + d, monotone: () => performance.now() + 1e7 + d };
}

/** Segments bruts : [{ nom, epoch, first_seq, evenements }]. */
function segmentsBruts(journal) {
  return fs.readdirSync(path.join(journal, "segments")).filter((n) => n.startsWith("seg-")).sort().map((nom) => {
    const lignes = fs.readFileSync(path.join(journal, "segments", nom), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    return { nom, epoch: Number(lignes[0].epoch), first_seq: Number(lignes[0].first_seq), evenements: lignes.slice(1) };
  });
}

/** Lignes du journal d'intention (tous les fichiers intentions-<époque>.ndjson). */
function intentions(journal) {
  const rep = path.join(journal, "intentions");
  return fs.readdirSync(rep).sort().flatMap((n) => fs.readFileSync(path.join(rep, n), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)));
}

/**
 * Appel d'outil qui réessaie, au plus 20 s, quand le frontal HTTP ne
 * répond pas encore ou plus (ECONNREFUSED, ECONNRESET) : une instance qui
 * perd son bail se relance et redevient passive (13.4 pas 8), son frontal se
 * rouvre ; aucun appel n'est réessayé après une réponse.
 */
async function appel(port, jeton, nom, args) {
  const limite = Date.now() + 20000;
  for (;;) {
    try {
      return await appelerOutil(port, jeton, nom, args);
    } catch (e) {
      if (!["ECONNREFUSED", "ECONNRESET"].includes(e.code) || Date.now() > limite) throw e;
      await new Promise((r) => setTimeout(r, 100));
    }
  }
}

const TTL_MS = 4000;
const RENEW_MS = 1000;

describe("TE-11 — haute disponibilité à écrivain unique : bascule du bail (magasin file puis etcd), pertes admises, jeton de clôture ; dossiers vérifiés par les deux vérificateurs", function () {
  this.timeout(600000);
  const docker = dockerDisponible([IMAGES.etcd]);
  let dir;
  let etcd = null;
  let service;
  let serveurService;
  let bin = null;

  before(async function () {
    dir = repertoireTemporaire("noortrace-te11-");
    service = new ServiceApprobationFactice({ org_id: "0x00", journal_id: null });
    serveurService = await service.servir(0);
    if (docker.ok) etcd = await demarrerEtcd(`noortrace-test-te11-etcd-${process.pid}`);
    bin = construireVerificateur(dir);
  });

  after(function () {
    serveurService?.close();
    arreterTout();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  async function preparer(type) {
    const d = path.join(dir, type);
    fs.mkdirSync(d, { recursive: true });
    const journal_id = N.octetsVersHex(N.keccak256(N.utf8(`journal-te11-${process.pid}-${type}`)));
    const store = type === "file" ? { type, path: path.join(d, "bail", "verrou") } : { type, endpoints: [etcd.origine], prefix: "/noortrace/te11/", tls: null };
    const commun = { journal_id, store, approbation: serveurService.address().port, ttl_ms: TTL_MS, renew_ms: RENEW_MS, segment_max_bytes: 8192 };
    const x = {};
    for (const nom of ["a", "b"]) {
      const portHttp = await portLibre();
      const portSante = await portLibre();
      const c = configurationHa(d, { ...commun, instance: `inst-${nom}`, portHttp, portSante });
      c.config.policy.servers.demo.transport.command = [process.execPath, SERVEUR_OUTILS, "--executions", path.join(d, "executions.ndjson")];
      const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(c.config)));
      expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
      x[nom] = { ...c, dir: d, portHttp, portSante, ports: [portHttp], fichier: path.join(d, `${nom}.json`) };
    }
    service.org_id = x.a.config.recorder.org_id;
    service.journal_id = journal_id;
    return { d, A: x.a, B: x.b, journal: repertoireJournal(x.a.config) };
  }

  for (const type of ["file", "etcd"]) {
    describe(`magasin de bail ${type}`, function () {
      const ev = {};

      before(async function () {
        if (type === "etcd" && !docker.ok) return;
        const p = await preparer(type);
        Object.assign(ev, p);
        const { A, B } = p;
        const jeton = A.env.NOORTRACE_TEST_JETON_HOTE;
        const executions = path.join(p.d, "executions.ndjson");
        // 1. A sert ; B attend.
        const dA = await demarrer(REFERENCE, A, A.fichier);
        ev.dA = dA;
        ev.reponsesA = [await appel(A.portHttp, jeton, "demo__lire", { id: "S1" })];
        for (let k = 2; k <= 4; k++) ev.reponsesA.push(await appel(A.portHttp, jeton, "demo__ecrire", { id: `S${k}`, montant: String(10 * k) }));
        const dB = await demarrer(REFERENCE, B, B.fichier, "standby");
        ev.dB = dB;
        ev.santeB = await sante(B.portSante);
        ev.passiveB = await appel(B.portHttp, jeton, "demo__lire", { id: "S-passif" });
        ev.epoqueA = Number(dA.lignes().find((l) => l.event === "lease_acquired").data.epoch);
        // 2. Écriture lente en vol chez A, puis coupure de A de son bail.
        ev.lent = appelerOutil(A.portHttp, jeton, "demo__ecrire_lent", { id: "S-vol", attente_ms: 3000 }).catch((e) => ({ coupure: e.code ?? e.message }));
        await attendre(() => fs.existsSync(executions) && fs.readFileSync(executions, "utf8").includes("S-vol"), 15000);
        const t0 = performance.now();
        if (type === "file") tuerAuxiliaireBail(dA);
        else dA.kill("SIGSTOP");
        await attendre(async () => (await sante(B.portSante))?.corps?.status === "ok", 60000, 50);
        ev.bascule_ms = Math.round(performance.now() - t0);
        if (type === "etcd") dA.kill("SIGCONT");
        // 3. B écrit ; l'ancienne instance A tente une écriture.
        ev.reponsesB = [await appel(B.portHttp, jeton, "demo__ecrire", { id: "S-B1", montant: "70" }), await appel(B.portHttp, jeton, "demo__lire", { id: "S-B2" })];
        ev.lent = await ev.lent;
        ev.ecritureA = await appel(A.portHttp, jeton, "demo__ecrire", { id: "S-A-apres", montant: "90" });
        ev.lignesA = dA.lignes();
        await arreter(dA);
        await arreter(dB);
        ev.lignesB = dB.lignes();
        ev.executions = fs.readFileSync(executions, "utf8").trim().split("\n").map((l) => JSON.parse(l));
        // 4. Relecture des segments et du journal d'intention.
        ev.segments = segmentsBruts(p.journal);
        ev.intentions = intentions(p.journal);
        const att = path.join(p.journal, "attente");
        ev.attente = fs.existsSync(att) ? fs.readdirSync(att).filter((n) => /^attente-[0-9]{20}\.ndjson$/.test(n)).map((n) => ({ nom: n, epoch: Number(n.slice(8, 28)), lignes: fs.readFileSync(path.join(att, n), "utf8").split("\n").filter(Boolean).length })) : [];
        // 5. Clôture de la période à l'heure suivante par une instance du cœur.
        const v = validerConfiguration(new TextEncoder().encode(JSON.stringify({ ...B.config, recorder: { ...B.config.recorder, instance_id: "inst-c" } })));
        const s = resoudreSecrets(v.config, { env: B.env });
        ev.C = await Coeur.demarrer({ config: v.config, secrets: s.secrets, horloge: horlogeHeureSuivante() });
        await ev.C.tic();
        ev.evts = await lireEvenements(p.journal);
      });

      after(async function () {
        if (ev.dA && ev.dA.exitCode === null && ev.dA.signalCode === null) {
          ev.dA.kill("SIGCONT");
          ev.dA.kill("SIGKILL");
        }
        ev.dB?.kill("SIGKILL");
        await ev.C?.arreter();
      });

      beforeEach(function () {
        if (type === "etcd" && !docker.ok) {
          this.currentTest.title += ` — en attente : ${docker.condition}`;
          this.skip();
        }
      });

      it("A sert et B attend : chaque appel de A répondu ; B passif (santé standby, -31010 bail_non_detenu)", function () {
        for (const r of ev.reponsesA) expect(r.corps.result?.isError, JSON.stringify(r.corps)).to.equal(false);
        expect(ev.santeB.corps).to.deep.equal({ status: "standby" });
        expect(ev.passiveB.corps.error).to.deep.include({ code: -31010 });
      });

      it("bascule mesurée de la coupure de A à la santé ok de B, au plus lease.ttl_ms + lease.renew_ms + 10 s ; B prend le bail avec une époque plus grande et produit l'événement de reprise de l'intention en vol", function () {
        expect(ev.bascule_ms).to.be.a("number");
        expect(ev.bascule_ms, `bascule ${ev.bascule_ms} ms`).to.be.at.most(TTL_MS + RENEW_MS + 10000);
        const acq = ev.lignesB.filter((l) => l.event === "lease_acquired");
        expect(acq).to.have.length(1);
        expect(acq[0].data.store).to.equal(type);
        expect(acq[0].data.epoch).to.be.greaterThan(ev.epoqueA);
        expect(ev.lignesB.filter((l) => l.event === "intent_recovered")).to.have.length(1);
        for (const r of ev.reponsesB) expect(r.corps.result?.isError, JSON.stringify(r.corps)).to.equal(false);
      });

      it("écriture de l'ancienne instance refusée par l'époque : -31010, ligne lease_lost ; l'écriture en vol n'est pas rendue comme acquise par A ; aucune fourche", function () {
        expect(ev.ecritureA.corps?.error?.code, JSON.stringify(ev.ecritureA.corps)).to.equal(-31010);
        expect(ev.lignesA.some((l) => l.event === "lease_lost")).to.equal(true);
        const lent = ev.lent.corps;
        expect(lent?.result?.isError === false, JSON.stringify(ev.lent)).to.equal(false);
        expect(ev.executions.filter((x) => x.id === "S-A-apres")).to.deep.equal([]);
        for (const l of [...ev.lignesA, ...ev.lignesB]) expect(l.event).to.not.equal("journal_fork");
      });

      it("relecture des segments et du journal d'intention : une seule chaîne continue (seq et prev_hash), aucun événement d'époque inférieure après la première époque de B, segments d'époques croissantes ; l'intention de l'écriture en vol est levée par son événement de reprise", function () {
        const epB = ev.lignesB.find((l) => l.event === "lease_acquired").data.epoch;
        const tous = ev.segments.flatMap((s) => s.evenements.map((e) => ({ e, epoque: s.epoch }))).sort((x, y) => x.e.seq - y.e.seq);
        tous.forEach((x, k) => {
          expect(x.e.seq).to.equal(k + 1);
          if (k > 0) expect(x.e.prev_hash).to.equal(tous[k - 1].e.hash);
        });
        const debutB = Math.min(...ev.segments.filter((s) => s.epoch === epB).map((s) => s.first_seq));
        expect(tous.filter((x) => x.epoque < epB && x.e.seq >= debutB)).to.deep.equal([]);
        for (let k = 1; k < ev.segments.length; k++) expect(ev.segments[k].first_seq).to.be.at.least(ev.segments[k - 1].first_seq);
        const reprise = tous.map((x) => x.e).find((e) => e.execution.tool === "demo__ecrire_lent");
        expect(reprise.execution).to.include({ status: "executee", is_error: true, duration_ms: 0 });
        // L'intention en vol est celle que B a reprise (intent_recovered) ; sa levée désigne l'événement de reprise.
        const idVol = ev.lignesB.find((l) => l.event === "intent_recovered").data.intent_id;
        expect(ev.intentions.filter((l) => l.lifted === idVol).map((l) => l.seq), JSON.stringify(ev.intentions)).to.deep.equal([reprise.seq]);
      });

      it("pertes dans les bornes de CT-2 §13.5 : chaque appel répondu par A ou par B a son événement ; l'écriture en vol, exécutée une fois côté serveur, a son événement de reprise", function () {
        const appels = ev.evts.filter((e) => e.execution.tool.startsWith("demo__"));
        const ids = (outil) => appels.filter((e) => e.execution.tool === outil && !e.execution.is_error).length;
        expect(ids("demo__lire")).to.equal(2);
        expect(ids("demo__ecrire")).to.equal(4);
        expect(appels.filter((e) => e.execution.tool === "demo__ecrire_lent" && e.execution.is_error && e.execution.duration_ms === 0)).to.have.length(1);
        expect(ev.executions.filter((x) => x.outil === "ecrire_lent")).to.have.length(1);
      });

      it("ancienne instance : aucun fichier d'attente ouvert sous une époque inférieure à celle de B après sa prise du bail (EX-13.5 (1)) ; une fois la période close, l'écriture en vol n'a qu'un événement, celui de reprise (EX-4.46 : l'événement en attente est scellé à la place de l'événement de reprise, jamais en plus ; 13.5)", function () {
        const epB = ev.lignesB.find((l) => l.event === "lease_acquired").data.epoch;
        const lents = ev.evts.filter((e) => e.execution.tool === "demo__ecrire_lent").map((e) => ({ seq: e.seq, is_error: e.execution.is_error, duration_ms: e.execution.duration_ms }));
        const constat = { fichiers_attente_d_epoque_inferieure: ev.attente.filter((f) => f.epoch < epB), evenements_de_l_ecriture_en_vol: lents };
        expect(constat, JSON.stringify(constat)).to.deep.equal({ fichiers_attente_d_epoque_inferieure: [], evenements_de_l_ecriture_en_vol: lents.filter((x) => x.is_error && x.duration_ms === 0).slice(0, 1) });
      });

      it("période close à l'heure suivante : journal accepté par le noyau ; dossiers d'un événement écrit par A et d'un événement écrit par B valides pour le noyau ET pour le binaire Go (go1.27.3)", async function () {
        const lent = ev.evts.find((x) => x.execution.tool === "demo__ecrire_lent");
        const parA = ev.evts.find((e) => e.execution.tool === "demo__ecrire" && e.seq < lent.seq);
        const parB = ev.evts.filter((e) => e.execution.tool === "demo__ecrire").at(-1);
        expect(parB.seq).to.be.greaterThan(lent.seq);
        const dossiers = [];
        for (const [nom, e] of [["a", parA], ["b", parB]]) {
          const d = path.join(ev.d, `dossier-${nom}`);
          await ev.C.exporterDossier(e.seq, d);
          if (nom === "a") {
            const cles = JSON.parse(fs.readFileSync(path.join(d, "cles.json"), "utf8"));
            const j = N.verifierJournal(ev.evts, cles);
            expect(j.valide, JSON.stringify(j.diagnostics)).to.equal(true);
          }
          const r = verifierRepertoireDossier(d);
          expect(r.verdict, `${nom} : ${JSON.stringify(r.controles_en_echec)}`).to.equal("valide");
          dossiers.push(d);
        }
        if (!bin) {
          this.test.title += " — binaire Go en attente : go1.27.3 introuvable (NOORTRACE_GO_BIN)";
          this.skip();
        }
        for (const d of dossiers) {
          const r = spawnSync(bin, [d, "--json"], { encoding: "utf8" });
          expect(r.status, r.stdout + r.stderr).to.equal(0);
          const rapport = JSON.parse(r.stdout);
          expect(rapport.verdict).to.equal("valide");
          expect(rapport.failed_checks).to.deep.equal([]);
        }
      });
    });
  }
});
