// Attributs `a` et `i` posés par le compagnon `noortrace-attributs` (CT-2
// EX-12.18, EX-13.5 (2), EX-18.4 ; CT-8 EX-3.9), sur un vrai système de
// fichiers ext4, avec de vrais processus : le démon réel `bin/noortrace`,
// lancé SANS `CAP_LINUX_IMMUTABLE` (setpriv), écrit par ses descripteurs
// ouverts pendant que le compagnon, processus distinct, pose `a` sur le
// segment courant et le journal d'intention et `i` sur chaque segment fermé
// et chaque manifeste ; une réécriture, une troncature, une suppression ou
// un ajout par un autre processus échouent ; un processus aux droits du démon
// ne peut pas retirer l'attribut ; le démon redémarre avec un journal
// d'intention d'époque inférieure qu'il ne peut plus supprimer.
// Sans compte 0 ni système de fichiers qui accepte `chattr +a`, ou sans
// `setpriv`, les cas sont en attente et leur titre nomme la condition.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { Coeur, validerConfiguration, resoudreSecrets, passageAttributs, principalAttributs, lireAttributs } from "@noortrace/enregistreur";
import { RACINE, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { portLibre } from "./fixtures/enregistreur-worm/outils.mjs";
import { configurationHa, ClientMcpHttp, demarrerDemon } from "./fixtures/enregistreur-ha/outils.mjs";

const BIN_ATTRIBUTS = path.join(RACINE, "paquets", "enregistreur", "bin", "noortrace-attributs");
const SANS_CAPACITE = ["setpriv", "--bounding-set=-linux_immutable", "--inh-caps=-all", "--"];

/** Condition : compte 0, `chattr +a` effectif sous os.tmpdir(), setpriv présent. */
function attributsDisponibles() {
  if (process.getuid?.() !== 0) return { ok: false, condition: "compte 0 (CAP_LINUX_IMMUTABLE) requis pour poser a et i" };
  if (spawnSync("setpriv", ["--version"]).status !== 0) return { ok: false, condition: "setpriv absent (démon sans CAP_LINUX_IMMUTABLE)" };
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-attributs-essai-"));
  const f = path.join(d, "x");
  fs.writeFileSync(f, "x");
  const r = spawnSync("chattr", ["+a", f]);
  spawnSync("chattr", ["-a", f]);
  fs.rmSync(d, { recursive: true, force: true });
  return r.status === 0 ? { ok: true } : { ok: false, condition: "système de fichiers sans attribut a (chattr +a refusé)" };
}

/** Une commande shell d'un autre processus ; rend son code. */
const sh = (cmd, args = [], env = process.env) => spawnSync(cmd, args, { encoding: "utf8", env });

describe("compagnon des attributs a et i (CT-2 EX-12.18, CT-8 EX-3.9) : démon réel sans la capacité, ext4", function () {
  this.timeout(300000);
  const cond = attributsDisponibles();
  let dir;
  let serveur;
  let ev = {};

  before(async function () {
    if (!cond.ok) return;
    dir = repertoireTemporaire("noortrace-worm-attributs-");
    const service = new ServiceApprobationFactice({ org_id: "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab", journal_id: null });
    serveur = await service.servir(0);
    const A = configurationHa(dir, {
      instance: "inst-attributs", store: { type: "file", path: path.join(dir, "bail", "verrou") }, approbation: serveur.address().port,
      worm: null, segment_max_bytes: 6144, portHttp: await portLibre(), portSante: await portLibre(),
    });
    service.journal_id = A.config.recorder.journal_id;
    A.config.storage.seal.append_only_attribute = true;
    const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(A.config)));
    expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
    A.fichier = path.join(dir, "configuration.json");
    fs.writeFileSync(A.fichier, JSON.stringify(A.config));
    ev.A = A;
    ev.rep = path.join(A.config.storage.root, A.config.recorder.org_id.slice(2), A.config.recorder.journal_id.slice(2));
    ev.racine = A.config.storage.root;
    // État de la sonde du compagnon sous un TMPDIR propre au test (supprimé avec lui).
    ev.envCompagnon = { ...process.env, TMPDIR: path.join(dir, "tmp-compagnon") };
    fs.mkdirSync(ev.envCompagnon.TMPDIR, { recursive: true });
  });

  after(async function () {
    ev.d?.kill("SIGKILL");
    serveur?.close();
    serveur?.closeAllConnections?.();
    if (dir) {
      sh("chattr", ["-R", "-a", "-i", dir]);
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  beforeEach(function () {
    if (!cond.ok) {
      this.currentTest.title += ` — en attente : ${cond.condition}`;
      this.skip();
    }
  });

  it("le démon, lancé sans CAP_LINUX_IMMUTABLE, écrit ; le compagnon (processus distinct) pose a sur le segment courant et le journal d'intention ; le démon continue d'écrire par ses descripteurs ouverts", async function () {
    const { A } = ev;
    // Ports d'écoute réattribués si l'un d'eux a été pris avant l'ouverture (EADDRINUSE).
    ev.d = await demarrerDemon(A, "ok", { prefixe: SANS_CAPACITE });
    const statut = fs.readFileSync(`/proc/${ev.d.pid}/status`, "utf8");
    const capEff = BigInt(`0x${/CapEff:\s+([0-9a-f]+)/.exec(statut)[1]}`);
    expect(capEff & (1n << 9n), "CAP_LINUX_IMMUTABLE (bit 9) absent du démon").to.equal(0n);
    const h = new ClientMcpHttp(A.config.mcp.http.listen);
    await h.ouvrir();
    expect((await h.appeler("demo__ecrire", { id: "P1", montant: "1" })).result.isError).to.equal(false);
    const r = sh(process.execPath, [BIN_ATTRIBUTS, "--racine", ev.racine, "--une-fois"], ev.envCompagnon);
    expect(r.status, r.stderr).to.equal(0);
    const segs = fs.readdirSync(path.join(ev.rep, "segments")).sort();
    const courant = path.join(ev.rep, "segments", segs.at(-1));
    const intention = path.join(ev.rep, "intentions", fs.readdirSync(path.join(ev.rep, "intentions")).sort().at(-1));
    expect(lireAttributs(courant)).to.match(/a/);
    expect(lireAttributs(intention)).to.match(/a/);
    const avant = fs.statSync(courant).size;
    const avantI = fs.statSync(intention).size;
    for (let k = 2; k <= 4; k++) expect((await h.appeler("demo__ecrire", { id: `P${k}`, montant: String(k) })).result.isError).to.equal(false);
    expect(fs.statSync(intention).size).to.be.greaterThan(avantI);
    const segs2 = fs.readdirSync(path.join(ev.rep, "segments")).sort();
    const grandi = segs2.includes(segs.at(-1)) && fs.statSync(courant).size > avant;
    expect(grandi || segs2.length > segs.length, "le segment courant a reçu des lignes, ou a été tourné").to.equal(true);
    ev.h = h;
    ev.courant = courant;
    ev.intention = intention;
  });

  it("une réécriture, une troncature, une suppression par un autre processus échouent (a) ; un ajout aussi sur un fichier i ; un processus aux droits du démon ne peut pas retirer l'attribut", async function () {
    // Rotation par taille : des segments fermés, puis un passage du compagnon.
    for (let k = 5; k <= 9; k++) expect((await ev.h.appeler("demo__ecrire", { id: `P${k}`, montant: String(k) })).result.isError).to.equal(false);
    expect(sh(process.execPath, [BIN_ATTRIBUTS, "--racine", ev.racine, "--une-fois"], ev.envCompagnon).status).to.equal(0);
    const segs = fs.readdirSync(path.join(ev.rep, "segments")).sort();
    expect(segs.length).to.be.at.least(2);
    const ferme = path.join(ev.rep, "segments", segs[0]);
    const courant = path.join(ev.rep, "segments", segs.at(-1));
    expect(lireAttributs(ferme)).to.match(/i/);
    expect(lireAttributs(ferme)).to.not.match(/a/);
    expect(lireAttributs(courant)).to.match(/a/);
    for (const f of [courant, ev.intention]) {
      expect(sh("sh", ["-c", `printf x > '${f}'`]).status, `réécriture de ${f}`).to.not.equal(0);
      expect(sh("truncate", ["-s", "0", f]).status, `troncature de ${f}`).to.not.equal(0);
      expect(sh("rm", ["-f", f]).status, `suppression de ${f}`).to.not.equal(0);
      expect(fs.existsSync(f)).to.equal(true);
    }
    expect(sh("sh", ["-c", `printf x >> '${ferme}'`]).status, "ajout sur un segment fermé (i)").to.not.equal(0);
    expect(sh("truncate", ["-s", "0", ferme]).status).to.not.equal(0);
    // Droits du démon : sans CAP_LINUX_IMMUTABLE (comme lui), puis sous un compte non 0.
    const r1 = sh(SANS_CAPACITE[0], [...SANS_CAPACITE.slice(1), "chattr", "-a", courant]);
    expect(r1.status).to.not.equal(0);
    expect(r1.stderr).to.match(/Operation not permitted/);
    const r2 = sh("setpriv", ["--reuid=10001", "--regid=10001", "--clear-groups", "--inh-caps=-all", "--", "chattr", "-i", ferme]);
    expect(r2.status).to.not.equal(0);
    expect(lireAttributs(courant)).to.match(/a/);
    expect(lireAttributs(ferme)).to.match(/i/);
    // Le démon écrit encore.
    expect((await ev.h.appeler("demo__lire", { id: "L1" })).result.isError).to.equal(false);
  });

  it("i sur chaque manifeste et sa signature après la clôture ; le démon redémarre avec un journal d'intention d'époque inférieure qu'il ne peut plus supprimer (intention_file_kept), et le compagnon pose a sur le nouveau", async function () {
    ev.d.kill("SIGTERM");
    expect((await ev.d.fin).code).to.equal(0);
    const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(ev.A.config)));
    const s = resoudreSecrets(v.config, { env: ev.A.env });
    const d = 3600000 - (Date.now() % 3600000) + 2000;
    const C = await Coeur.demarrer({ config: v.config, secrets: s.secrets, horloge: { murale: () => Date.now() + d, monotone: () => performance.now() + 1e7 + d } });
    try {
      await C.tic();
      expect(C.journal.trouver("intention_file_kept").length).to.be.at.least(1);
      expect(C.journal.trouver("intention_file_kept")[0].data.raison).to.equal("append_only");
    } finally {
      await C.arreter();
    }
    expect(sh(process.execPath, [BIN_ATTRIBUTS, "--racine", ev.racine, "--une-fois"], ev.envCompagnon).status).to.equal(0);
    const man = fs.readdirSync(path.join(ev.rep, "manifestes"));
    expect(man.length).to.be.at.least(2);
    for (const m of man) expect(lireAttributs(path.join(ev.rep, "manifestes", m)), m).to.match(/i/);
    const ints = fs.readdirSync(path.join(ev.rep, "intentions")).sort();
    expect(ints.length).to.be.at.least(2);
    expect(lireAttributs(path.join(ev.rep, "intentions", ints.at(-1)))).to.match(/a/);
  });

  it("EX-13.5 (2) : un segment fermé d'époque inférieure à celle du dernier segment scellé n'est pas scellé (attribute_refused) ; la sonde rend 0 après un passage réussi, 1 sur un état périmé", async function () {
    const segs = fs.readdirSync(path.join(ev.rep, "segments")).sort();
    const perime = path.join(ev.rep, "segments", `seg-0000000000000002-${"0".repeat(19)}0.ndjson`);
    fs.writeFileSync(perime, "segment d'un ecrivain perime\n");
    const lignes = [];
    const r = passageAttributs(ev.racine, { consigner: (niveau, evenement, data) => lignes.push({ niveau, evenement, data }) });
    expect(r.refus.map((x) => path.basename(x.fichier))).to.deep.equal([path.basename(perime)]);
    expect(lignes.find((l) => l.evenement === "attribute_refused").data.raison).to.equal("epoque_inferieure");
    expect(lireAttributs(perime)).to.not.match(/i/);
    expect(segs.length).to.be.greaterThan(0);
    fs.rmSync(perime);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-worm-attributs-sonde-"));
    const ancien = process.env.TMPDIR;
    process.env.TMPDIR = tmp;
    try {
      expect(await principalAttributs(["sonde"])).to.equal(1);
      expect(await principalAttributs(["--racine", ev.racine, "--une-fois", "--intervalle-s", "60"], { stderr: { write: () => {} } })).to.equal(0);
      expect(await principalAttributs(["sonde"])).to.equal(0);
      expect(await principalAttributs(["sonde"], { maintenant: () => Date.now() + 200000 })).to.equal(1);
      expect(await principalAttributs(["--intervalle-s", "61", "--racine", ev.racine], { stderr: { write: () => {} } })).to.equal(2);
    } finally {
      if (ancien === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = ancien;
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("conflit de texte (EX-12.10 pas 3 et EX-12.18) : une fin incomplète ajoutée au segment courant, qui porte a, ne peut pas être retranchée (ftruncate refusé, EPERM) : le démarrage du démon échoue ; aucun texte ne fixe qui retire a avant la troncature", async function () {
    const segs = fs.readdirSync(path.join(ev.rep, "segments")).sort();
    const courant = path.join(ev.rep, "segments", segs.at(-1));
    expect(sh(process.execPath, [BIN_ATTRIBUTS, "--racine", ev.racine, "--une-fois"], ev.envCompagnon).status).to.equal(0);
    expect(lireAttributs(courant)).to.match(/a/);
    // L'ajout reste permis sous a : une ligne inachevée, comme un arrêt pendant l'écriture.
    expect(sh("sh", ["-c", `printf '{"seq":' >> '${courant}'`]).status).to.equal(0);
    const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(ev.A.config)));
    const s = resoudreSecrets(v.config, { env: ev.A.env });
    let erreur = null;
    try {
      const C = await Coeur.demarrer({ config: v.config, secrets: s.secrets });
      await C.arreter();
    } catch (e) {
      erreur = e;
    }
    expect(erreur, "démarrage refusé").to.not.equal(null);
    expect(`${erreur.code} ${erreur.message}`).to.match(/EPERM|not permitted/);
    expect(lireAttributs(courant)).to.match(/a/);
  });
});

// Étape 7 : sans `DAC_READ_SEARCH`, le compte 0
// ne parcourt pas `storage.root` (0700, compte 10001). Le compagnon avalait
// l'erreur de lecture, rendait 0 et sa sonde disait sain : panne silencieuse.
// Il échoue désormais bruyamment.
describe("compagnon des attributs (CT-2 EX-12.18, CT-8 EX-3.9) : racine illisible sans DAC_READ_SEARCH, panne bruyante", function () {
  this.timeout(60000);
  const SANS_LECTURE = ["setpriv", "--bounding-set=-dac_read_search,-dac_override", "--inh-caps=-all", "--"];
  let dir;

  before(function () {
    if (process.getuid?.() !== 0 || spawnSync("setpriv", ["--version"]).status !== 0) {
      this.currentTest && (this.currentTest.title += " — en attente : compte 0 et setpriv requis");
      this.skip();
    }
    dir = repertoireTemporaire("noortrace-attributs-illisible-");
  });

  after(function () {
    if (dir) {
      sh("chattr", ["-R", "-a", "-i", dir]);
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("sans DAC_READ_SEARCH ni DAC_OVERRIDE (compte 0) : --une-fois rend 1 et consigne attribute_unreadable sur la racine ; la sonde dit malade (1) ; en service, le compagnon s'arrête avec le code 1 (attribute_root_unreadable) ; avec la capacité, le même passage rend 0", function () {
    const racine = path.join(dir, "journal");
    const seg = path.join(racine, "a".repeat(64), "b".repeat(64), "segments");
    fs.mkdirSync(seg, { recursive: true });
    fs.writeFileSync(path.join(seg, "seg-0000000000000001-00000000000000000001.ndjson"), "{}\n", { mode: 0o400 });
    for (const d of [racine, path.dirname(path.dirname(seg)), path.dirname(seg), seg]) {
      fs.chownSync(d, 10001, 10001);
      fs.chmodSync(d, 0o700);
    }
    const tmp = path.join(dir, "tmp-compagnon");
    fs.mkdirSync(tmp);
    const env = { ...process.env, TMPDIR: tmp };
    const une = sh(SANS_LECTURE[0], [...SANS_LECTURE.slice(1), process.execPath, BIN_ATTRIBUTS, "--racine", racine, "--une-fois"], env);
    expect(une.status, une.stderr).to.equal(1);
    const lignes = une.stderr.split("\n").filter((l) => l.startsWith("{")).map((l) => JSON.parse(l));
    const e = lignes.find((l) => l.event === "attribute_unreadable");
    expect(e, une.stderr).to.not.equal(undefined);
    expect(e.level).to.equal("error");
    expect(e.data.fichier).to.equal(".");
    expect(e.data.message).to.match(/EACCES/);
    expect(sh(process.execPath, [BIN_ATTRIBUTS, "sonde"], env).status, "sonde après un passage aveugle").to.equal(1);
    const service = sh(SANS_LECTURE[0], [...SANS_LECTURE.slice(1), process.execPath, BIN_ATTRIBUTS, "--racine", racine, "--intervalle-s", "1"], { ...env });
    expect(service.status, service.stderr).to.equal(1);
    expect(service.stderr).to.include('"event":"attribute_root_unreadable"');
    expect(sh(process.execPath, [BIN_ATTRIBUTS, "sonde"], env).status).to.equal(1);
    // Racine absente : même refus.
    const absente = sh(process.execPath, [BIN_ATTRIBUTS, "--racine", path.join(dir, "absente"), "--une-fois"], env);
    expect(absente.status).to.equal(1);
    expect(absente.stderr).to.include('"event":"attribute_unreadable"');
    // Avec la capacité de lecture (compte 0 complet), la racine est parcourue ;
    // la pose dépend du système de fichiers et n'est pas jugée ici.
    const r = passageAttributs(racine);
    expect(r.racineIllisible).to.equal(false);
    expect(r.erreurs.filter((x) => /EACCES/.test(x.message))).to.deep.equal([]);
  });
});
