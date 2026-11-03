// Haute disponibilité (CT-2 §13 en entier : EX-13.1 à EX-13.10, 13.2, 13.4,
// 13.5) et lignes « Bail » de §14.2, §15.4 et §17, en réussite et en échec,
// contre de vrais magasins de bail : PostgreSQL 16 et etcd 3.5 (images
// épinglées par condensé, lancées dans Docker). Situations hostiles : bail
// perdu pendant une écriture (après le fdatasync), bail repris par une autre
// instance, partition réseau simulée (le magasin devient injoignable),
// horloge murale qui saute, époque qui recule, fichiers d'une époque
// supérieure présents, clé du MAC de relais différente, fourche (fichier
// d'époque inférieure qui grandit après la reprise).
// Sans Docker, chaque cas est mis en attente et son titre nomme la condition.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as N from "@noortrace/noyau";
import {
  Coeur, validerConfiguration, resoudreSecrets, MagasinBailPostgresql, MagasinBailEtcd, ClientEtcd, requetesBailPg, ErreurEnregistreur,
  pieceTexte, principal,
} from "@noortrace/enregistreur";
import { configurationDev, repertoireTemporaire, CLE_MAC_HEX } from "./fixtures/enregistreur-coeur/outils.mjs";
import {
  IMAGES, dockerDisponible, demarrerPostgresql, demarrerEtcd, arreterTout, psql, PartitionTcp, fichierSecret, attendre,
} from "./fixtures/enregistreur-worm/outils.mjs";

const dormir = (ms) => new Promise((r) => setTimeout(r, ms));
const b64 = (t) => Buffer.from(t, "utf8").toString("base64");

describe("haute disponibilité : exigences de §13 contre PostgreSQL et etcd réels", function () {
  this.timeout(600000);
  const docker = dockerDisponible([IMAGES.postgresql, IMAGES.etcd]);
  let dir;
  let pg;
  let etcd;
  let n = 0;

  before(async function () {
    if (!docker.ok) return;
    dir = repertoireTemporaire("noortrace-ha-exigences-");
    [pg, etcd] = await Promise.all([demarrerPostgresql(`noortrace-test-ha-pg-${process.pid}`), demarrerEtcd(`noortrace-test-ha-etcd-${process.pid}`)]);
  });

  after(function () {
    arreterTout();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  beforeEach(function () {
    if (!docker.ok) {
      this.currentTest.title += ` — en attente : ${docker.condition}`;
      this.skip();
    }
  });

  const base = () => ({ org_id: "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab", journal_id: N.octetsVersHex(N.keccak256(N.utf8(`ha-${process.pid}-${++n}`))), ttl_ms: 3000, renew_ms: 500, acquire_wait_ms: 2000 });
  const magasins = {
    postgresql: (b, instance, o = {}) => new MagasinBailPostgresql({ ...b, instance, dsn: o.dsn ?? pg.dsn, table: o.table ?? "noortrace_lease", monotone: o.monotone }),
    etcd: (b, instance, o = {}) => new MagasinBailEtcd({ ...b, instance, endpoints: o.endpoints ?? [etcd.origine], prefix: "/noortrace/bail/", tls: null, monotone: o.monotone }),
  };

  /** Configuration de développement avec un magasin de bail réseau. */
  function configuration(type, o = {}) {
    const d = path.join(dir, `c${++n}`);
    const { config, env } = configurationDev(d, { journal_id: o.journal_id ?? N.octetsVersHex(N.keccak256(N.utf8(`ha-cfg-${process.pid}-${n}`))), instance_id: o.instance ?? "inst-a" });
    config.recorder.instance_id = o.instance ?? "inst-a";
    if (o.storage) config.storage.root = o.storage;
    const store = type === "postgresql"
      ? { type, dsn: { file: fichierSecret(path.join(d, "secrets", "dsn"), o.dsn ?? pg.dsn) }, table: o.table ?? "noortrace_lease" }
      : { type, endpoints: o.endpoints ?? [etcd.origine], prefix: "/noortrace/bail/", tls: null };
    config.lease = { store, ttl_ms: o.ttl_ms ?? 3000, renew_ms: o.renew_ms ?? 500, acquire_wait_ms: o.acquire_wait_ms ?? 2000, fencing: o.fencing ?? null };
    const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(config)));
    expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
    const s = resoudreSecrets(v.config, { env });
    expect(s.erreurs).to.deep.equal([]);
    return { d, config: v.config, brute: config, env, secrets: s.secrets };
  }

  for (const type of ["postgresql", "etcd"]) {
    describe(`magasin ${type} (13.2)`, function () {
      it("EX-13.4 : l'époque est strictement croissante à chaque acquisition, par n'importe quelle instance ; un second détenteur est refusé (bail_non_detenu)", async function () {
        const b = base();
        const vues = [];
        for (const inst of ["inst-a", "inst-b", "inst-a", "inst-c"]) {
          const m = magasins[type](b, inst);
          const e = await m.acquerir();
          vues.push(e);
          const autre = magasins[type](b, "intrus");
          let refus = null;
          try {
            await autre.acquerir();
          } catch (x) {
            refus = x;
          }
          expect(refus).to.be.instanceOf(ErreurEnregistreur);
          expect(refus.raison).to.equal("bail_non_detenu");
          await autre.liberer();
          expect(m.valide()).to.equal(true);
          expect(await m.verifierApresEcriture()).to.equal(true);
          await m.liberer();
        }
        for (let k = 1; k < vues.length; k++) expect(vues[k]).to.be.greaterThan(vues[k - 1]);
        expect(vues[0]).to.be.at.least(1);
      });

      it("EX-13.3, 13.4 pas 2 et 3 : un détenteur qui cesse de renouveler perd le bail au plus ttl_ms après son dernier renouvellement ; l'autre l'acquiert avec une époque plus grande ; l'ancien ne se vérifie plus (EX-13.10 (2))", async function () {
        const b = base();
        const a = magasins[type](b, "inst-a");
        const ea = await a.acquerir();
        await dormir(1500);
        expect(a.valide(), "renouvelé").to.equal(true);
        a.perdre();
        const bb = magasins[type](b, "inst-b");
        const t0 = Date.now();
        let eb;
        await attendre(async () => {
          try {
            eb = await bb.acquerir();
            return true;
          } catch (e) {
            if (e.raison !== "bail_non_detenu") throw e;
            return false;
          }
        }, 15000, 100);
        expect(Date.now() - t0).to.be.below(b.ttl_ms + 2500);
        expect(eb).to.be.greaterThan(ea);
        expect(await a._verifier()).to.equal(false);
        await bb.liberer();
        a._fermer();
      });

      it("EX-13.3 : validité mesurée sur l'horloge monotone (t_renew + ttl − renew_ms) ; un saut de l'horloge murale n'y change rien", async function () {
        let mono = 1000;
        const b = base();
        const m = magasins[type](b, "inst-a", { monotone: () => mono });
        await m.acquerir();
        clearTimeout(m.minuteur);
        const date = Date.now;
        try {
          Date.now = () => date() + 7200000;
          expect(m.valide()).to.equal(true);
        } finally {
          Date.now = date;
        }
        mono += b.ttl_ms - b.renew_ms - 1;
        expect(m.valide()).to.equal(true);
        mono += 1;
        expect(m.valide()).to.equal(false);
        expect(await m.verifierApresEcriture()).to.equal(false);
        m.detenu = true;
        await m.liberer();
      });

      it("partition réseau simulée : le magasin devient injoignable → renouvellements en échec comptés, puis lease_lost (bail_echu) et mode dégradé « bail » ; au démarrage, abandon après acquire_wait_ms", async function () {
        const cible = type === "postgresql" ? pg : etcd;
        const p = new PartitionTcp({ port: cible.port });
        await p.ecouter();
        try {
          const c = configuration(type, type === "postgresql" ? { dsn: pg.dsn.replace(`:${pg.port}/`, `:${p.port}/`) } : { endpoints: [`http://127.0.0.1:${p.port}`] });
          const coeur = await Coeur.demarrer({ config: c.config, secrets: c.secrets });
          try {
            expect(coeur.bail.valide()).to.equal(true);
            p.couper();
            await attendre(() => coeur.degrade.actif("bail"), 15000, 100);
            const perte = coeur.journal.trouver("lease_lost");
            expect(perte).to.have.length(1);
            expect(perte[0].data.cause).to.equal("bail_echu");
            expect(coeur.metriques.exposer()).to.match(new RegExp(`noortrace_lease_renew_failures_total\\{store="${type}"\\} [1-9]`));
            expect(coeur.metriques.exposer()).to.match(/noortrace_lease_epoch 0/);
            expect(coeur.sante().statut).to.equal(503);
            let e = null;
            try {
              await coeur.ecrirePiece(pieceTexte("apres la perte"));
              await coeur.scellerPartiel({});
            } catch (x) {
              e = x;
            }
            expect(e?.raison).to.be.oneOf(["bail", "stockage"]);
          } finally {
            await coeur.arreter();
          }
          // Démarrage pendant la partition : abandon après acquire_wait_ms (raison bail).
          const c2 = configuration(type, { ...(type === "postgresql" ? { dsn: pg.dsn.replace(`:${pg.port}/`, `:${p.port}/`) } : { endpoints: [`http://127.0.0.1:${p.port}`] }), acquire_wait_ms: 800 });
          let refus = null;
          const t0 = Date.now();
          try {
            await Coeur.demarrer({ config: c2.config, secrets: c2.secrets });
          } catch (x) {
            refus = x;
          }
          expect(refus?.raison).to.equal("bail");
          expect(Date.now() - t0).to.be.below(20000);
        } finally {
          await p.fermer();
        }
      });
    });
  }

  describe("cœur et magasin réseau (EX-13.1, EX-13.5, EX-13.6, EX-13.9, EX-13.10, 13.4)", function () {
    it("13.2 : requêtes SQL exactes (UPDATE conditionnel avec clock_timestamp(), renouvellement par détenteur et époque) ; la ligne du journal porte l'instance et l'époque", async function () {
      const sql = requetesBailPg("noortrace_lease");
      expect(sql.acquerir).to.equal(`UPDATE "noortrace_lease" SET holder = $1, epoch = epoch + 1, expires_at = clock_timestamp() + $2 * interval '1 millisecond' WHERE name = $3 AND (holder IS NULL OR expires_at < clock_timestamp()) RETURNING epoch`);
      expect(sql.renouveler).to.equal(`UPDATE "noortrace_lease" SET expires_at = clock_timestamp() + $1 * interval '1 millisecond' WHERE name = $2 AND holder = $3 AND epoch = $4`);
      expect(sql.acquerir).to.not.contain("now()");
      const c = configuration("postgresql", { table: "bail_sql" });
      const coeur = await Coeur.demarrer({ config: c.config, secrets: c.secrets });
      try {
        const ligne = psql(pg.nom, `select holder || '|' || epoch from bail_sql where name = '${c.config.recorder.org_id}/${c.config.recorder.journal_id}'`);
        expect(ligne).to.equal(`inst-a|${coeur.ecrivain.epoque}`);
        // EX-13.1 : l'époque est dans l'en-tête du segment et le nom des fichiers, jamais dans un événement.
        const segs = fs.readdirSync(path.join(coeur.repertoire, "segments"));
        expect(segs.at(-1)).to.match(new RegExp(`-${String(coeur.ecrivain.epoque).padStart(20, "0")}\\.ndjson$`));
        const entete = JSON.parse(fs.readFileSync(path.join(coeur.repertoire, "segments", segs.at(-1)), "utf8").split("\n")[0]);
        expect(entete.epoch).to.equal(coeur.ecrivain.epoque);
      } finally {
        await coeur.arreter();
      }
    });

    it("etcd : la clé <prefix><org_id>/<journal_id> porte l'instance tant que le bail est détenu ; l'époque est sa mod_revision ; elle disparaît à la libération", async function () {
      const c = configuration("etcd");
      const coeur = await Coeur.demarrer({ config: c.config, secrets: c.secrets });
      const cle = `/noortrace/bail/${c.config.recorder.org_id}/${c.config.recorder.journal_id}`;
      const client = new ClientEtcd([etcd.origine], null);
      try {
        const r = await client.appeler("/v3/kv/range", { key: b64(cle) });
        expect(Buffer.from(r.kvs[0].value, "base64").toString()).to.equal("inst-a");
        expect(Number(r.kvs[0].mod_revision)).to.equal(coeur.ecrivain.epoque);
        expect(r.kvs[0].lease).to.be.a("string");
      } finally {
        await coeur.arreter();
      }
      const apres = await client.appeler("/v3/kv/range", { key: b64(cle) });
      expect(apres.kvs ?? []).to.deep.equal([]);
    });

    it("EX-13.6, 14.2 « Bail perdu » : le bail repris par une autre instance → renouvellement refusé, lease_lost, mode dégradé « bail » : écritures et lectures bloquées (raison bail), santé down", async function () {
      const c = configuration("postgresql", { table: "bail_vole" });
      const coeur = await Coeur.demarrer({ config: c.config, secrets: c.secrets });
      try {
        psql(pg.nom, `update bail_vole set holder = 'inst-voleuse', epoch = epoch + 1, expires_at = clock_timestamp() + interval '1 hour'`);
        await attendre(() => coeur.degrade.actif("bail"), 10000, 50);
        expect(coeur.journal.trouver("lease_lost")[0].data).to.include({ store: "postgresql", cause: "renouvellement_refuse" });
        expect(coeur.etatSante().raisons).to.include("bail");
        let e = null;
        try {
          await coeur.ecrivain.sceller({});
        } catch (x) {
          e = x;
        }
        expect(e).to.be.instanceOf(ErreurEnregistreur);
        expect(e.raison).to.equal("bail");
      } finally {
        await coeur.arreter();
      }
    });

    it("EX-13.10 (2) : bail perdu pendant une écriture — repris après le contrôle d'avant fdatasync : la revérification après fdatasync échoue, lease_lost_after_write avec le seq, l'événement n'est pas rendu comme acquis", async function () {
      const c = configuration("postgresql", { table: "bail_ecriture", ttl_ms: 60000, renew_ms: 20000 });
      const coeur = await Coeur.demarrer({ config: c.config, secrets: c.secrets });
      try {
        // Le magasin passe à une autre instance ; la validité monotone du cœur court encore (renouvellement lointain).
        psql(pg.nom, `update bail_ecriture set holder = 'inst-b', epoch = epoch + 1, expires_at = clock_timestamp() + interval '1 hour'`);
        expect(coeur.bail.valide()).to.equal(true);
        let e = null;
        try {
          await coeur.tournerCle("rec-test-02");
        } catch (x) {
          e = x;
        }
        expect(e?.raison).to.equal("bail");
        const l = coeur.journal.trouver("lease_lost_after_write");
        expect(l).to.have.length(1);
        expect(l[0].data.seq).to.be.a("number");
        expect(coeur.degrade.actif("bail")).to.equal(true);
      } finally {
        await coeur.arreter();
      }
    });

    it("EX-13.5 (1), époque qui recule : un fichier d'intention d'une époque supérieure présent, ou une époque du magasin inférieure aux segments, refuse l'écriture (raison bail)", async function () {
      for (const sorte of ["intentions", "segments"]) {
        const c = configuration("postgresql", { table: `bail_recul_${sorte}` });
        // Premier démarrage : époque 1, segment d'époque 1.
        const c1 = await Coeur.demarrer({ config: c.config, secrets: c.secrets });
        const rep = c1.repertoire;
        await c1.arreter();
        if (sorte === "segments") {
          // L'époque du magasin recule (ligne remise à zéro par un tiers).
          psql(pg.nom, `update bail_recul_segments set epoch = 0, holder = null`);
        } else {
          fs.writeFileSync(path.join(rep, sorte, "intentions-00000000000000000099.ndjson"), "");
        }
        let e = null;
        try {
          await Coeur.demarrer({ config: c.config, secrets: c.secrets });
        } catch (x) {
          e = x;
        }
        expect(e, sorte).to.be.instanceOf(ErreurEnregistreur);
        expect(e.raison, sorte).to.equal("bail");
        expect(e.message, sorte).to.match(/EX-13\.5/);
      }
    });

    it("EX-13.5 (1) : un fichier d'attente n'est jamais ouvert sous une époque supérieure présente (événement gardé en mémoire seulement)", async function () {
      const c = configuration("postgresql", { table: "bail_attente" });
      const coeur = await Coeur.demarrer({ config: c.config, secrets: c.secrets });
      try {
        fs.mkdirSync(path.join(coeur.repertoire, "attente"), { recursive: true });
        fs.writeFileSync(path.join(coeur.repertoire, "attente", "attente-00000000000000000099.ndjson"), "");
        coeur.mettreEnAttente({ execution: { tool: "x" } }, []);
        await dormir(200);
        expect(fs.readdirSync(path.join(coeur.repertoire, "attente"))).to.deep.equal(["attente-00000000000000000099.ndjson"]);
        expect(coeur.attente).to.have.length(1);
        coeur.attente.length = 0;
      } finally {
        await coeur.arreter();
      }
    });

    it("EX-13.9 : redémarrage sur le même hôte : nouvelle époque, nouveau segment ; le précédent est fermé par sa seule existence", async function () {
      const c = configuration("etcd");
      const a = await Coeur.demarrer({ config: c.config, secrets: c.secrets });
      const e1 = a.ecrivain.epoque;
      const rep = a.repertoire;
      await a.arreter();
      const b = await Coeur.demarrer({ config: c.config, secrets: c.secrets });
      try {
        expect(b.ecrivain.epoque).to.be.greaterThan(e1);
        const segs = fs.readdirSync(path.join(rep, "segments")).sort();
        expect(segs).to.have.length(2);
        expect(segs[0]).to.match(new RegExp(`${String(e1).padStart(20, "0")}\\.ndjson$`));
        expect(b.journal.trouver("lease_predecessor_files")[0].data.files.map((f) => f.fichier)).to.include(`segments/${segs[0]}`);
      } finally {
        await b.arreter();
      }
    });

    it("13.4 pas 1, EX-17.1, 14.2 « Bail non détenu » : instance passive — lease_standby, santé standby, /readyz 503, -31010 bail_non_detenu sans parler au service d'approbation ; elle prend le bail quand l'active le rend, avec une époque plus grande", async function () {
      const c = configuration("postgresql", { table: "bail_passive" });
      const a = await Coeur.demarrer({ config: c.config, secrets: c.secrets });
      const cb = configuration("postgresql", { table: "bail_passive", journal_id: c.config.recorder.journal_id, storage: c.config.storage.root, instance: "inst-b" });
      let appelsService = 0;
      const refuse = () => {
        appelsService++;
        return Promise.reject(new Error("service joint par une instance passive"));
      };
      const service = { charger: refuse, evaluer: refuse, ouvrir: refuse, decisions: refuse, acquitter: refuse, consommer: refuse, expiration: refuse };
      const b = await Coeur.demarrer({ config: cb.config, secrets: cb.secrets, attendreBail: true, service, supervision: true });
      const lireSonde = (chemin) => fetch(`http://127.0.0.1:${b.serveur.address().port}${chemin}`).then(async (r) => ({ statut: r.status, corps: await r.text() }));
      try {
        expect(b.passif).to.equal(true);
        expect(b.sante()).to.deep.equal({ statut: 200, corps: { status: "standby" } });
        expect(await lireSonde("/healthz")).to.deep.equal({ statut: 200, corps: '{"status":"standby"}' });
        expect((await lireSonde("/readyz")).statut).to.equal(503);
        expect(b.journal.trouver("lease_standby")).to.have.length(1);
        for (const f of [() => b.evaluer({}), () => b.ecrirePiece(pieceTexte("x"))]) {
          let e = null;
          try {
            await f();
          } catch (x) {
            e = x;
          }
          expect(e.raison).to.equal("bail_non_detenu");
          expect(e.code).to.equal(-31010);
        }
        b.definirOutils([]);
        expect(appelsService).to.equal(0);
        const ea = a.ecrivain.epoque;
        await a.arreter();
        await b.demarrage;
        expect(b.passif).to.equal(false);
        expect(b.ecrivain.epoque).to.be.greaterThan(ea);
        expect(b.sante().corps.status).to.equal("ok");
        expect((await lireSonde("/readyz")).statut).to.equal(200);
      } finally {
        await b.arreter();
      }
    });

    it("13.4 pas 1, EX-7.22 : clé du MAC de relais différente de celle du dernier fichier mac-* → relay_mac_key_mismatch, le bail n'est pas pris (refus, ou attente avec attendreBail)", async function () {
      const c = configuration("postgresql", { table: "bail_mac" });
      const a = await Coeur.demarrer({ config: c.config, secrets: c.secrets });
      await a.arreter();
      const autre = new Map(c.secrets);
      autre.set("/storage/relay_mac_key", new Uint8Array(Buffer.alloc(32, 7)));
      let e = null;
      try {
        await Coeur.demarrer({ config: c.config, secrets: autre });
      } catch (x) {
        e = x;
      }
      expect(e?.message).to.match(/relay_mac_key_mismatch/);
      expect(psql(pg.nom, "select coalesce(holder, 'aucun') from bail_mac")).to.equal("aucun");
      const b = await Coeur.demarrer({ config: c.config, secrets: autre, attendreBail: true });
      try {
        expect(b.passif).to.equal(true);
        expect(b.journal.trouver("relay_mac_key_mismatch")).to.have.length(1);
        await dormir(1200);
        expect(b.passif).to.equal(true);
        expect(psql(pg.nom, "select coalesce(holder, 'aucun') from bail_mac")).to.equal("aucun");
      } finally {
        await b.arreter();
      }
      // La bonne clé : la passive prend le bail.
      expect(Buffer.from(c.secrets.get("/storage/relay_mac_key")).toString("hex")).to.equal(CLE_MAC_HEX);
    });

    it("EX-13.10 (3), 17.4 « Fourche » : un fichier d'époque inférieure qui grandit après la reprise est signalé (journal_fork, une fois)", async function () {
      const c = configuration("postgresql", { table: "bail_fourche" });
      const a = await Coeur.demarrer({ config: c.config, secrets: c.secrets });
      const segA = path.join(a.repertoire, "segments", fs.readdirSync(path.join(a.repertoire, "segments")).at(-1));
      await a.arreter();
      const b = await Coeur.demarrer({ config: c.config, secrets: c.secrets });
      try {
        const base = b.journal.trouver("lease_predecessor_files")[0].data.files;
        expect(base.find((f) => segA.endsWith(f.fichier)).octets).to.equal(fs.statSync(segA).size);
        await b.fourche.controler({ force: true });
        expect(b.journal.trouver("journal_fork")).to.have.length(0);
        fs.appendFileSync(segA, '{"seq":999}\n');
        await b.tic();
        await b.fourche.controler({ force: true });
        const f = b.journal.trouver("journal_fork");
        expect(f).to.have.length(1);
        expect(f[0].level).to.equal("error");
        expect(f[0].data.fichier).to.equal(`segments/${path.basename(segA)}`);
        expect(f[0].data.octets).to.be.greaterThan(f[0].data.octets_avant);
      } finally {
        await b.arreter();
      }
    });

    it("EX-15.4 (lignes « bail ») : renew_ms < ttl_ms / 2 exigé ; en production, lease.fencing exigé avec postgresql ou etcd, admis avec détachement ; noortrace validate-config", async function () {
      const c = configuration("postgresql");
      const valider = (cfg) => validerConfiguration(new TextEncoder().encode(JSON.stringify(cfg)));
      const x = JSON.parse(JSON.stringify(c.brute));
      x.lease.renew_ms = 1500;
      expect(valider(x).erreurs.map((e) => e.pointeur)).to.include("/lease/renew_ms");
      const p = JSON.parse(JSON.stringify(c.brute));
      p.recorder.environment = "production";
      expect(valider(p).erreurs.map((e) => e.pointeur)).to.include("/lease/fencing");
      p.lease.fencing = "detachement";
      expect(valider(p).erreurs.map((e) => e.pointeur)).to.not.include("/lease/fencing");
      const f = path.join(c.d, "cfg.json");
      fs.writeFileSync(f, JSON.stringify(x));
      const out = [];
      expect(await principal(["validate-config", f], { stdout: { write: (t) => out.push(t) }, stderr: { write: () => {} } })).to.equal(2);
      expect(out.join("")).to.contain("/lease/renew_ms");
    });
  });
});
