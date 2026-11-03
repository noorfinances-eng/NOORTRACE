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
//
// Défaut D-1 (révélé par TE-11, test/enregistreur-ha-bascule.test.js) et
// EX-17.2 : une instance qui n'est plus détentrice du bail, ou dont l'époque
// est dépassée par une autre présente dans le répertoire du journal, n'écrit
// rien (ni attente, ni intention, ni segment) ; la reprise d'une attente ne
// scelle jamais ce qu'un événement de reprise a déjà couvert ; `instance_id`
// dans `data` de chaque ligne du journal d'exploitation d'un déploiement à
// plusieurs instances (`postgresql`, `etcd`), absent avec `file`. Ces cas,
// sur le magasin `file` et le cœur seul, ne demandent pas Docker.

import { expect } from "chai";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import * as N from "@noortrace/noyau";
import {
  Coeur, validerConfiguration, resoudreSecrets, MagasinBailPostgresql, MagasinBailEtcd, ClientEtcd, requetesBailPg, ErreurEnregistreur,
  pieceTexte, principal, pieceJson, lireEvenements, principalCtl, instanceExploitation,
} from "@noortrace/enregistreur";
import { configurationDev, repertoireTemporaire, secretsDev, CLE_MAC_HEX } from "./fixtures/enregistreur-coeur/outils.mjs";
import { configurationHa, demarrerDemon, lancerDemon } from "./fixtures/enregistreur-ha/outils.mjs";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
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

    it("EX-17.2 : déploiement à plusieurs instances (postgresql, etcd) — chaque ligne du journal d'exploitation, en mémoire et dans le fichier, porte instance_id dans data ; deux instances successives s'y distinguent", async function () {
      for (const type of ["postgresql", "etcd"]) {
        const c = configuration(type, type === "postgresql" ? { table: "bail_instance" } : {});
        const a = await Coeur.demarrer({ config: c.config, secrets: c.secrets });
        await a.arreter();
        const cb = { ...c.config, recorder: { ...c.config.recorder, instance_id: "inst-b" } };
        const b = await Coeur.demarrer({ config: cb, secrets: c.secrets });
        await b.arreter();
        for (const [x, inst] of [[a, "inst-a"], [b, "inst-b"]]) {
          expect(x.journal.lignes.length, type).to.be.greaterThan(3);
          expect(x.journal.lignes.filter((l) => l.data.instance_id !== inst), type).to.deep.equal([]);
          expect(x.journal.trouver("lease_acquired")[0].data, type).to.include({ store: type, instance_id: inst });
        }
        const fichier = fs.readFileSync(c.config.supervision.ops_log.path, "utf8").trim().split("\n").map((l) => JSON.parse(l));
        expect(fichier.length, type).to.equal(a.journal.lignes.length + b.journal.lignes.length);
        expect(fichier.filter((l) => !["inst-a", "inst-b"].includes(l.data.instance_id)), type).to.deep.equal([]);
        expect(fichier.filter((l) => l.event === "startup").map((l) => l.data.instance_id), type).to.deep.equal(["inst-a", "inst-b"]);
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

describe("D-1 et EX-17.2 : instance qui n'est plus détentrice ou dont l'époque est dépassée — rien n'est écrit (EX-13.1, EX-13.5 (1), EX-13.6) ; attente couverte par une reprise jamais scellée (EX-4.46, 13.5) ; instance_id du journal d'exploitation (magasin file, sans Docker)", function () {
  this.timeout(120000);
  let racine;
  let k = 0;

  before(function () {
    racine = repertoireTemporaire("noortrace-ha-d1-");
  });

  after(function () {
    if (racine) fs.rmSync(racine, { recursive: true, force: true });
  });

  /** Configuration de développement (magasin `file`), instance `inst-a`. */
  function preparer(o = {}) {
    const d = path.join(racine, `c${++k}`);
    const { config } = configurationDev(d, { journal_id: N.octetsVersHex(N.keccak256(N.utf8(`ha-d1-${process.pid}-${k}`))), instance_id: "inst-a" });
    if (o.modifier) o.modifier(config);
    const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(config)));
    expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
    return { d, config: v.config };
  }
  const autreInstance = (config, instance_id) => ({ ...config, recorder: { ...config.recorder, instance_id } });
  const autorise = { rule: null, decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null };
  const appelEcriture = (args) => ({ host: { id: "agent-sinistres-stdio" }, delegation: { launched_by: "agent-sinistres", on_behalf_of: null, scope: "s", run_id: null }, tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", class: "ecriture", arguments: args.reference, context: [], intent: null, code: {} });
  /** Relais d'écriture en vol : pièce « arguments » et intention durables (4.4 pas 4 et 8). */
  async function relaisEnVol(coeur, id) {
    const args = pieceJson({ claim_id: id });
    await coeur.ecrirePiece(args);
    return coeur.preparerRelais(appelEcriture(args), { reponse: autorise, argumentsEnClair: { claim_id: id }, upstream_id: `e-${id}` });
  }
  const resultat = (id) => ({ resultat: pieceJson({ content: [{ type: "text", text: id }], isError: false }), resultatRedige: {}, argumentsRediges: {}, duration_ms: 7, is_error: false });
  const fichiersAttente = (rep) => (fs.existsSync(path.join(rep, "attente")) ? fs.readdirSync(path.join(rep, "attente")).sort() : []);
  const fichierIntentions = (coeur) => path.join(coeur.repertoire, "intentions", `intentions-${String(coeur.ecrivain.epoque).padStart(20, "0")}.ndjson`);
  async function terminer(coeur, relais, id) {
    try {
      await coeur.terminerRelais(relais, resultat(id));
      return null;
    } catch (e) {
      return e;
    }
  }
  async function erreurDe(p) {
    try {
      await p;
      return null;
    } catch (e) {
      return e;
    }
  }
  const evenementsOutil = async (rep) => (await lireEvenements(rep)).filter((e) => e.execution.tool === "sap__payments.create").map((e) => ({ is_error: e.execution.is_error, duration_ms: e.execution.duration_ms }));

  it("bail perdu, repris par B (événement de reprise de l'écriture en vol) : A termine l'écriture (-31017) sans ouvrir de fichier d'attente, n'écrit plus d'intention ; une instance suivante ne trouve qu'un événement, celui de reprise", async function () {
    const { config } = preparer();
    const A = await Coeur.demarrer({ config, secrets: secretsDev() });
    let B = null;
    try {
      const relais = await relaisEnVol(A, "D1a");
      // A isolée de son bail (13.4 pas 2) : verrou rendu, B l'acquiert avec e+1 et reprend l'intention en vol.
      await A.bail.liberer();
      B = await Coeur.demarrer({ config: autreInstance(config, "inst-b"), secrets: secretsDev() });
      expect(B.ecrivain.epoque).to.be.greaterThan(A.ecrivain.epoque);
      expect(B.journal.trouver("intent_recovered").map((l) => l.data.intent_id)).to.deep.equal([relais.intention.intent_id]);
      // B a supprimé le fichier d'intention de A, toutes ses intentions levées (EX-12.13) ;
      // A garde son descripteur : ce qu'elle écrirait se mesure par lui.
      expect(fs.existsSync(fichierIntentions(A))).to.equal(false);
      const tailleIntentions = A.ecrivain.intentions.taille;
      const err = await terminer(A, relais, "D1a");
      expect(err?.code, String(err)).to.equal(-31017);
      expect(A.attente, "gardé en mémoire seulement (EX-4.46)").to.have.length(1);
      await dormir(300);
      expect(fichiersAttente(A.repertoire)).to.deep.equal([]);
      const err2 = await erreurDe(relaisEnVol(A, "D1a-2"));
      expect(err2?.raison).to.equal("bail");
      expect(A.ecrivain.intentions.taille, "aucune ligne d'intention écrite sans bail").to.equal(tailleIntentions);
      expect(fs.existsSync(fichierIntentions(A))).to.equal(false);
      A.attente.length = 0;
    } finally {
      await A.arreter();
      await B?.arreter();
    }
    const C = await Coeur.demarrer({ config: autreInstance(config, "inst-c"), secrets: secretsDev() });
    try {
      expect(await evenementsOutil(C.repertoire)).to.deep.equal([{ is_error: true, duration_ms: 0 }]);
    } finally {
      await C.arreter();
    }
  });

  it("EX-13.5 (1) lu sur le répertoire du journal : une époque supérieure présente dans segments/ seulement, bail encore tenu pour valide → ni événement, ni fichier d'attente, ni intention ; lease_lost (epoque_superieure_presente), mode dégradé « bail »", async function () {
    const { config } = preparer();
    const A = await Coeur.demarrer({ config, secrets: secretsDev() });
    try {
      const relais = await relaisEnVol(A, "D1b");
      const fi = fichierIntentions(A);
      // Un repreneur d'époque supérieure a ouvert son segment (13.4 pas 5).
      fs.writeFileSync(path.join(A.repertoire, "segments", `seg-${"9".padStart(16, "0")}-${String(A.ecrivain.epoque + 1).padStart(20, "0")}.ndjson`), "");
      expect(A.bail.valide()).to.equal(true);
      const tailleIntentions = fs.statSync(fi).size;
      const tailleSegments = fs.readdirSync(path.join(A.repertoire, "segments")).map((n) => fs.statSync(path.join(A.repertoire, "segments", n)).size);
      const err = await terminer(A, relais, "D1b");
      expect(err?.code, String(err)).to.equal(-31017);
      await dormir(300);
      expect(fichiersAttente(A.repertoire)).to.deep.equal([]);
      const err2 = await erreurDe(relaisEnVol(A, "D1b-2"));
      expect(err2?.raison).to.equal("bail");
      expect(fs.statSync(fi).size).to.equal(tailleIntentions);
      expect(fs.readdirSync(path.join(A.repertoire, "segments")).map((n) => fs.statSync(path.join(A.repertoire, "segments", n)).size)).to.deep.equal(tailleSegments);
      const l = A.journal.trouver("lease_lost").filter((x) => x.data.cause === "epoque_superieure_presente");
      expect(l).to.have.length(1);
      expect(l[0].data).to.include({ epoch: A.ecrivain.epoque, epoch_present: A.ecrivain.epoque + 1, directory: "segments" });
      expect(A.degrade.actif("bail")).to.equal(true);
      A.attente.length = 0;
    } finally {
      await A.arreter();
    }
  });

  it("une époque supérieure présente dans intentions/ ou approbations/ seulement refuse l'ouverture du fichier d'attente (EX-13.5 (1), répertoire du journal) ; la même configuration sans elle l'ouvre", async function () {
    for (const [sous, nom] of [["intentions", (e) => `intentions-${e}.ndjson`], ["approbations", (e) => `mac-${e}.ndjson`], [null, null]]) {
      const { config } = preparer();
      const A = await Coeur.demarrer({ config, secrets: secretsDev() });
      try {
        if (sous) fs.writeFileSync(path.join(A.repertoire, sous, nom(String(A.ecrivain.epoque + 5).padStart(20, "0"))), "");
        A.mettreEnAttente({ execution: { tool: "x" } }, []);
        await dormir(300);
        expect(fichiersAttente(A.repertoire), String(sous)).to.deep.equal(sous ? [] : [`attente-${String(A.ecrivain.epoque).padStart(20, "0")}.ndjson`]);
        expect(A.attente).to.have.length(1);
        A.attente.length = 0;
      } finally {
        await A.arreter();
      }
    }
  });

  it("reprise d'une attente dont l'intention est déjà levée par un événement de reprise : non scellée (pending_superseded), un seul événement pour l'écriture (EX-4.46 : à la place, jamais en plus ; 13.5) ; journal accepté par le noyau", async function () {
    const { config } = preparer();
    const A = await Coeur.demarrer({ config, secrets: secretsDev() });
    const relais = await relaisEnVol(A, "D1c");
    // Panne du signataire après relais, bail tenu : -31017, événement en attente écrit au fichier (EX-4.46, 14.5).
    A.signataire.backend.signer = async () => {
      throw new Error("module injoignable");
    };
    const err = await terminer(A, relais, "D1c");
    expect(err?.code).to.equal(-31017);
    await dormir(300);
    const nomAttente = `attente-${String(A.ecrivain.epoque).padStart(20, "0")}.ndjson`;
    expect(fichiersAttente(A.repertoire)).to.deep.equal([nomAttente]);
    const ligne = fs.readFileSync(path.join(A.repertoire, "attente", nomAttente));
    A.attente.length = 0;
    await A.arreter();
    // Le repreneur ne voit pas ce fichier (écrit après sa reprise) : il reprend l'intention en vol.
    fs.rmSync(path.join(A.repertoire, "attente", nomAttente));
    const B = await Coeur.demarrer({ config: autreInstance(config, "inst-b"), secrets: secretsDev() });
    expect(B.journal.trouver("intent_recovered").map((l) => l.data.intent_id)).to.deep.equal([relais.intention.intent_id]);
    await B.arreter();
    fs.writeFileSync(path.join(A.repertoire, "attente", nomAttente), ligne);
    const C = await Coeur.demarrer({ config: autreInstance(config, "inst-c"), secrets: secretsDev() });
    try {
      expect(C.journal.trouver("pending_superseded").map((l) => l.data)).to.deep.equal([{ pending_id: JSON.parse(ligne.toString("utf8")).pending_id, intent_id: relais.intention.intent_id }]);
      expect(C.journal.trouver("pending_flushed")).to.deep.equal([]);
      expect(await evenementsOutil(C.repertoire)).to.deep.equal([{ is_error: true, duration_ms: 0 }]);
      expect(fichiersAttente(C.repertoire)).to.deep.equal([]);
      const evts = await lireEvenements(C.repertoire);
      const cles = {
        version: 0,
        org_id: config.recorder.org_id,
        journal_id: config.recorder.journal_id,
        keys: [{ key_id: "rec-test-01", algorithm: "ed25519", public_key: await C.signataire.clePubliqueHex("rec-test-01"), valid_from: "2020-01-01T00:00:00.000Z", valid_to: null, source: "clé de test" }],
      };
      const j = N.verifierJournal(evts, cles);
      expect(j.valide, JSON.stringify(j.diagnostics)).to.equal(true);
    } finally {
      await C.arreter();
    }
  });

  it("EX-17.2, magasin file (une instance, CT-8 IC-10) : aucune ligne ne porte instance_id ; instanceExploitation ne le rend qu'avec postgresql ou etcd", async function () {
    const { config } = preparer();
    const A = await Coeur.demarrer({ config, secrets: secretsDev() });
    await A.arreter();
    expect(A.journal.lignes.length).to.be.greaterThan(3);
    expect(A.journal.lignes.filter((l) => "instance_id" in l.data)).to.deep.equal([]);
    expect(instanceExploitation(config)).to.equal(null);
    expect(instanceExploitation({ ...config, lease: { ...config.lease, store: { type: "postgresql" } } })).to.equal("inst-a");
    expect(instanceExploitation({ ...config, lease: { ...config.lease, store: { type: "etcd" } } })).to.equal("inst-a");
  });

  it("EX-17.2 : noortrace-ctl écrit dans le journal d'exploitation de l'instance dont il lit la configuration ; avec postgresql, ses lignes portent instance_id, avec file non", async function () {
    for (const type of ["postgresql", "file"]) {
      const { d, config } = preparer({
        modifier: (c) => {
          if (type === "postgresql") c.lease = { ...c.lease, store: { type, dsn: { env: "NOORTRACE_TEST_DSN" }, table: "noortrace_lease" }, renew_ms: 1000 };
        },
      });
      const f = path.join(d, "cfg.json");
      fs.writeFileSync(f, JSON.stringify(config));
      const code = await principalCtl(["worm", "releve", "--configuration", f], { stdout: { write: () => {} }, stderr: { write: () => {} }, env: {} });
      expect(code, type).to.equal(2);
      const lignes = fs.readFileSync(config.supervision.ops_log.path, "utf8").trim().split("\n").map((l) => JSON.parse(l));
      expect(lignes.map((l) => l.event), type).to.deep.equal(["worm_legal_hold_failed"]);
      expect(lignes[0].data, type).to.deep.equal(type === "postgresql" ? { raison: "configuration", instance_id: "inst-a" } : { raison: "configuration" });
    }
  });
});

describe("outils des tests : port d'écoute pris entre son choix et son ouverture (EADDRINUSE) — le démon réel est relancé sur d'autres ports, en nombre d'essais borné", function () {
  this.timeout(120000);
  let dir;
  let serveur;
  const occupes = [];

  before(async function () {
    dir = repertoireTemporaire("noortrace-ha-ports-");
    const service = new ServiceApprobationFactice({ org_id: "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab", journal_id: null });
    serveur = await service.servir(0);
  });

  after(function () {
    serveur?.close();
    for (const s of occupes) s.close();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  /** Écoute TCP tenue par le test sur un port choisi par le système (connexions coupées aussitôt). */
  async function occuper() {
    const s = net.createServer((c) => c.destroy());
    await new Promise((r) => s.listen(0, "127.0.0.1", r));
    occupes.push(s);
    return s.address().port;
  }

  it("EX-15.4 : démarrage refusé sur une adresse d'écoute prise (EADDRINUSE) — rapport sur stderr, le processus s'arrête avec le code 2 (il restait vivant, fils de rédaction ouverts)", async function () {
    const d = path.join(dir, "refus");
    const x = configurationHa(d, { instance: "inst-refus", store: { type: "file", path: path.join(d, "bail", "verrou") }, approbation: serveur.address().port, portHttp: 0, portSante: await occuper() });
    const fichier = path.join(d, "configuration.json");
    fs.writeFileSync(fichier, JSON.stringify(x.config));
    const p = lancerDemon(fichier, x.env, x.config.supervision.ops_log.path);
    const fin = await Promise.race([p.fin, dormir(20000).then(() => null)]);
    if (!fin) p.kill("SIGKILL");
    await p.ferme;
    expect(fin, p.sortie).to.deep.equal({ code: 2, signal: null });
    expect(p.sortie).to.match(/demarrage_refuse : demarrage : listen EADDRINUSE/);
  });

  it("santé et frontal MCP sur deux ports déjà pris : demarrerDemon relance bin/noortrace sur des ports libres, réécrit la configuration ; santé ok sur le nouveau port", async function () {
    const [pSante, pHttp] = [await occuper(), await occuper()];
    const d = path.join(dir, "relance");
    const x = configurationHa(d, { instance: "inst-ports", store: { type: "file", path: path.join(d, "bail", "verrou") }, approbation: serveur.address().port, portHttp: pHttp, portSante: pSante });
    x.fichier = path.join(d, "configuration.json");
    x.port = pSante;
    const demon = await demarrerDemon(x, "ok");
    try {
      expect(x.port).to.not.equal(pSante);
      expect(x.config.supervision.health_listen).to.equal(`127.0.0.1:${x.port}`);
      expect(x.config.mcp.http.listen).to.not.equal(`127.0.0.1:${pHttp}`);
      expect(JSON.parse(fs.readFileSync(x.fichier, "utf8")).supervision.health_listen).to.equal(`127.0.0.1:${x.port}`);
      expect(demon.exitCode).to.equal(null);
    } finally {
      demon.kill("SIGTERM");
      await demon.fin;
    }
  });
});
