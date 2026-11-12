// Signataires des classes A, B et C : parcours de bout en bout sur le démon
// réel `bin/noortrace --config` (CT-2 §11, §14.2 ligne « clé indisponible »,
// EX-11.15, EX-14.11), et TA-33 (CT-9, MN-33).
//
// Pour chaque signataire, un journal est d'abord ouvert par une instance du
// cœur dont l'horloge retarde de 25 heures (la clé initiale est en vigueur
// depuis plus d'un jour) ; le démon réel le reprend avec
// `signer.rotation.planned_every_days: 1` : la rotation planifiée (EX-11.15)
// a lieu au premier tic, en cours de route ; un hôte de test appelle des
// outils par le frontal MCP (Streamable HTTP, jeton statique) ; le démon est
// arrêté ; une instance du cœur clôt la période à l'heure suivante ; le
// journal est accepté par `N.verifierJournal` et les dossiers d'un événement
// signé par l'ancienne clé et d'un événement signé par la nouvelle sont
// valides pour le noyau ET pour le binaire Go `noortrace-verifier`
// (construit par verificateur/scripts/construire.sh avec go1.27.3, dont le
// répertoire est dans NOORTRACE_GO_BIN ; sans lui, ces vérifications sont en
// attente).
//
// - classe A, configuration de DÉVELOPPEMENT : PKCS#11 sur SoftHSM2 réel
//   (SoftHSM2 vaut la classe D, 11.2 : il n'est pas un signataire de
//   production) ;
// - classe B, configuration de PRODUCTION : Vault Transit réel, puis OpenBao
//   Transit réel ;
// - classe C, configuration de PRODUCTION : enveloppe AWS KMS par LocalStack
//   réel, puis TPM 2.0 logiciel réel (swtpm).
//
// TE-16, ligne « clé indisponible » de la matrice de §14.2 (avec « panne
// après relais ») : Vault suspendu pendant une lecture puis une écriture,
// réponses à l'hôte, journal d'exploitation, événement en attente, puis
// rétablissement.
//
// En production, le serveur d'outils stdio tourne sous `nobody`, utilisateur
// distinct de celui du démon (EX-3.5) : les parcours de production exigent un
// démon lancé par le superutilisateur, et sont en attente sinon (condition
// nommée) ; le travail « parcours-superutilisateur » de l'intégration continue
// les joue sous sudo, sans essai en attente.
//
// TA-31 et TA-33 (CT-9) sont joués par test/adversarial.test.js
// (fixtures/enregistreur-signataires/ta.mjs).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import { verifierRepertoireDossier } from "@noortrace/noyau/dossier-fichiers";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { Coeur, validerConfiguration, resoudreSecrets, lireEvenements, signataireDepuisConfiguration } from "@noortrace/enregistreur";
import { RACINE, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { certificats } from "./fixtures/enregistreur-worm/outils.mjs";
import { REFERENCE, detruireMutants, configurationDemon, demarrer, arreter, appelerOutil, attendre, sante } from "./fixtures/enregistreur-adversarial/demon.mjs";
import {
  IMAGES_SIGNATAIRES, dockerEtImage, softHsmDisponible, jetonSoftHsm, demarrerTransit, demarrerKmsLocalStack, tpmDisponible, demarrerSwtpm,
  arreterConteneurs, suspendreConteneur,
} from "./fixtures/enregistreur-signataires/outils.mjs";

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

/**
 * En production, le serveur d'outils stdio tourne sous un utilisateur
 * distinct de celui du démon (EX-3.5) : seul un démon lancé par le
 * superutilisateur peut en changer. Sinon, le parcours est en attente.
 */
const superutilisateur = () =>
  typeof process.getuid === "function" && process.getuid() === 0
    ? { ok: true, condition: null }
    : { ok: false, condition: "le démon doit être lancé par le superutilisateur pour lancer le serveur stdio sous un utilisateur distinct (EX-3.5)" };
/** Première condition non remplie, dans l'ordre ; chaque condition n'est évaluée que si les précédentes sont remplies. */
const conditions = (...fs) => {
  for (const f of fs) {
    const d = f();
    if (!d.ok) return d;
  }
  return { ok: true, condition: null };
};

// Dans un crochet beforeEach, ctx.test est le crochet : l'essai est ctx.currentTest.
const enAttente = (ctx, condition) => {
  (ctx.currentTest ?? ctx.test).title += ` — en attente : ${condition}`;
  ctx.skip();
};

/** Horloge réelle décalée de `d` ms (monotone comprise). */
const horlogeDecalee = (d) => ({ murale: () => Date.now() + d, monotone: () => performance.now() + 1e7 + d });
/** Décalage vers l'heure suivante, de moins d'une heure. */
const versHeureSuivante = () => 3600000 - (Date.now() % 3600000) + 3000;

let dir;
let tls;
let service;
let serveurService;
let bin = null;
before(async function () {
  this.timeout(600000);
  dir = repertoireTemporaire("noortrace-signataires-parcours-");
  tls = certificats(path.join(dir, "tls"));
  service = new ServiceApprobationFactice({ org_id: "0x00", journal_id: null });
  serveurService = await service.servir(0);
  bin = construireVerificateur(dir);
});
after(function () {
  serveurService?.close();
  arreterConteneurs();
  detruireMutants();
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

let n = 0;
/**
 * Configuration d'un démon réel (fixtures du lot adversarial : frontal MCP en
 * Streamable HTTP, serveur d'outils stdio `demo`, bail `file`) dont le
 * signataire est `signer` ; en production, le serveur d'outils tourne sous
 * `nobody`, épinglé par le sha256 de l'exécutable (EX-3.5).
 */
async function configurationParcours(signer, o) {
  const d = path.join(dir, `p${++n}-${o.nom}`);
  fs.mkdirSync(d, { recursive: true });
  const c = await configurationDemon(d, { approbation: serveurService.address().port });
  c.config.recorder.environment = o.environment;
  c.config.signer = { ...c.config.signer, ...signer, rotation: { planned_every_days: 1, next_key_id: signer.next_key_id ?? null } };
  delete c.config.signer.next_key_id;
  c.config.signer.health_interval_ms = o.health_interval_ms ?? 10000;
  if (o.environment === "production") {
    const t = c.config.policy.servers.demo.transport;
    t.user = "nobody";
    t.integrity = { sha256: N.sha256Hex(new Uint8Array(fs.readFileSync(t.command[0]))) };
  }
  Object.assign(c.env, o.env ?? {});
  const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(c.config)));
  expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
  c.avertissements = v.avertissements;
  service.org_id = c.config.recorder.org_id;
  service.journal_id = c.config.recorder.journal_id;
  return c;
}

/** Ouvre le journal par une instance du cœur dont l'horloge retarde de 25 h (événement de politique signé par la clé initiale). */
async function ouvrirJournalAncien(c, o) {
  // Journal d'exploitation propre à cette instance : celui du démon ne porte que ses lignes.
  const v = validerConfiguration(new TextEncoder().encode(JSON.stringify({ ...c.config, supervision: { ...c.config.supervision, ops_log: { ...c.config.supervision.ops_log, path: path.join(c.dir, "exploitation-ouverture.ndjson") } } })));
  const s = resoudreSecrets(v.config, { env: { ...process.env, ...c.env } });
  expect(s.erreurs).to.deep.equal([]);
  const backend = await signataireDepuisConfiguration(v.config, s.secrets, { env: { ...process.env, ...c.env }, ca: o.ca ?? null });
  const coeur = await Coeur.demarrer({ config: v.config, secrets: s.secrets, signataire: backend, horloge: horlogeDecalee(-25 * 3600000) });
  await coeur.arreter();
}

/** Parcours complet ; rend les observations. */
async function parcours(c, o = {}) {
  const ev = { c };
  await ouvrirJournalAncien(c, o);
  const p = await demarrer(REFERENCE, c, path.join(c.dir, "configuration.json"));
  ev.demon = p;
  try {
    await attendre(() => p.lignes().some((l) => l.event === "key_rotated"), 30000).catch((e) => {
      throw new Error(`rotation planifiée : ${e.message}\n${p.sortie.slice(-2000)}`);
    });
    const jeton = c.env.NOORTRACE_TEST_JETON_HOTE;
    ev.reponses = [];
    ev.reponses.push(await appelerOutil(c.portHttp, jeton, "demo__lire", { id: "S1" }));
    for (const k of [2, 3]) ev.reponses.push(await appelerOutil(c.portHttp, jeton, "demo__ecrire", { id: `S${k}`, montant: String(10 * k) }));
    ev.sante = await sante(c.portSante);
  } finally {
    await arreter(p);
  }
  ev.fin = await p.fin;
  ev.lignes = p.lignes();
  // Clôture de la période par une instance du cœur, à l'heure suivante.
  const v = validerConfiguration(new TextEncoder().encode(JSON.stringify({ ...c.config, recorder: { ...c.config.recorder, instance_id: "inst-cloture" }, supervision: { ...c.config.supervision, ops_log: { ...c.config.supervision.ops_log, path: path.join(c.dir, "exploitation-cloture.ndjson") } } })));
  const s = resoudreSecrets(v.config, { env: { ...process.env, ...c.env } });
  const backend = await signataireDepuisConfiguration(v.config, s.secrets, { env: { ...process.env, ...c.env }, ca: o.ca ?? null });
  const C = await Coeur.demarrer({ config: v.config, secrets: s.secrets, signataire: backend, horloge: horlogeDecalee(versHeureSuivante()) });
  try {
    await C.tic();
    ev.evts = await lireEvenements(C.repertoire);
    const rotation = ev.evts.find((e) => e.execution.tool === "noortrace.journal.rotation-cle");
    ev.rotation = rotation;
    ev.avant = ev.evts.find((e) => e.seq < rotation.seq);
    ev.apres = ev.evts.filter((e) => e.execution.tool === "demo__ecrire").at(-1);
    ev.dossiers = [];
    for (const [nom, e] of [["avant", ev.avant], ["apres", ev.apres]]) {
      const d = path.join(c.dir, `dossier-${nom}`);
      await C.exporterDossier(e.seq, d);
      ev.dossiers.push(d);
    }
    ev.cles = JSON.parse(fs.readFileSync(path.join(ev.dossiers[1], "cles.json"), "utf8"));
  } finally {
    await C.arreter();
  }
  return ev;
}

/** Assertions communes d'un parcours. */
function verifierParcours(ev, classe, type) {
  expect(ev.fin.code, ev.demon.sortie.slice(-2000)).to.equal(0);
  const pret = ev.lignes.filter((l) => l.event === "signer_ready");
  expect(pret, "signer_ready").to.have.length(1);
  expect(pret[0].data).to.include({ class: classe, backend: type, key_id: ev.c.config.signer.key_id });
  const demarrage = ev.lignes.find((l) => l.event === "startup");
  expect(demarrage.data).to.include({ class: classe, backend: type });
  const rot = ev.lignes.filter((l) => l.event === "key_rotated");
  expect(rot).to.have.length(1);
  expect(rot[0].data).to.deep.equal({ old_key_id: ev.c.config.signer.key_id, new_key_id: ev.c.config.signer.rotation.next_key_id });
  for (const r of ev.reponses) expect(r.corps?.result?.isError, JSON.stringify(r.corps)).to.equal(false);
  expect(ev.sante.corps).to.deep.equal({ status: "ok" });
  expect(ev.avant.recorder_key_id).to.equal(ev.c.config.signer.key_id);
  expect(ev.apres.recorder_key_id).to.equal(ev.c.config.signer.rotation.next_key_id);
  expect(ev.rotation.recorder_key_id, "rotation signée par l'ancienne clé (CT-1 §8)").to.equal(ev.c.config.signer.key_id);
  ev.evts.forEach((e, k) => expect(e.seq).to.equal(k + 1));
  const r = N.verifierJournal(ev.evts, ev.cles);
  expect(r.valide, JSON.stringify(r.diagnostics)).to.equal(true);
  for (const d of ev.dossiers) {
    const x = verifierRepertoireDossier(d);
    expect(x.verdict, `${d} : ${JSON.stringify(x.controles_en_echec)}`).to.equal("valide");
  }
}

function verifierParGo(ctx, ev) {
  if (!bin) enAttente(ctx, "go1.27.3 absent (NOORTRACE_GO_BIN)");
  for (const d of ev.dossiers) {
    const r = spawnSync(bin, [d, "--json"], { encoding: "utf8" });
    expect(r.status, r.stdout + r.stderr).to.equal(0);
    const rapport = JSON.parse(r.stdout);
    expect(rapport.verdict, d).to.equal("valide");
    expect(rapport.failed_checks).to.deep.equal([]);
  }
}

// ------------------------------------------------------------------ classe A (développement)

describe("parcours, classe A en développement : PKCS#11 sur SoftHSM2 réel (SoftHSM2 n'est pas admis comme signataire de production, 11.2)", function () {
  this.timeout(300000);
  const dispo = softHsmDisponible();
  const ev = {};
  before(async function () {
    if (!dispo.ok) return;
    const j = jetonSoftHsm(path.join(dir, "hsm-parcours"));
    j.ceremonie("rec-a-01", "oid");
    j.ceremonie("rec-a-02", "curveName");
    const c = await configurationParcours(
      { class: "A", key_id: "rec-a-01", next_key_id: "rec-a-02", backend: { type: "pkcs11", module: j.module, token_label: j.etiquette, key_label: "rec-a-01", pin: { env: "NOORTRACE_TEST_PIN_PKCS11" }, mechanism: "CKM_EDDSA" } },
      { nom: "a", environment: "developpement", env: { NOORTRACE_TEST_PIN_PKCS11: j.pin, ...j.env } },
    );
    Object.assign(ev, await parcours(c));
    ev.pin = j.pin;
  });
  beforeEach(function () {
    if (!dispo.ok) enAttente(this, dispo.condition);
  });

  it("démon réel : clé publique lue par l'auxiliaire, signature de test, signer_ready (classe A, étiquettes, forme OID) ; rotation planifiée au premier tic ; appels répondus ; arrêt propre", function () {
    verifierParcours(ev, "A", "pkcs11");
    const pret = ev.lignes.find((l) => l.event === "signer_ready");
    expect(pret.data.pkcs11).to.deep.equal({ ec_params: "oid", ec_point: "der" });
    expect(JSON.stringify(ev.lignes)).to.not.include(`"${ev.pin}"`);
  });

  it("dossiers d'avant et d'après la rotation : valides pour le binaire Go (go1.27.3)", function () {
    verifierParGo(this, ev);
  });
});

// ------------------------------------------------------------------ classe B (production)

for (const type of ["vault-transit", "openbao-transit"]) {
  describe(`parcours, classe B en production : ${type} réel (conteneur épinglé par condensé)`, function () {
    this.timeout(400000);
    const dispo = conditions(superutilisateur, () => dockerEtImage(IMAGES_SIGNATAIRES[type]));
    const ev = {};
    let srv;
    before(async function () {
      if (!dispo.ok) return;
      srv = await demarrerTransit(type, `noortrace-test-parcours-${type}-${process.pid}`, tls);
      await srv.creerCle("rec-sinistres-2026-01");
      await srv.creerCle("rec-sinistres-2026-02");
      const jeton = await srv.jetonUsage(["rec-sinistres-2026-01", "rec-sinistres-2026-02"]);
      const c = await configurationParcours(
        { class: "B", key_id: "rec-sinistres-2026-01", next_key_id: "rec-sinistres-2026-02", backend: { type, url: srv.origine, mount: "transit", key_name: "rec-sinistres-2026-01", token: { env: "NOORTRACE_TEST_JETON_TRANSIT" }, namespace: null } },
        { nom: type, environment: "production", env: { NOORTRACE_TEST_JETON_TRANSIT: jeton, NODE_EXTRA_CA_CERTS: tls.ca } },
      );
      Object.assign(ev, await parcours(c, { ca: tls.caPem }));
      ev.jeton = jeton;
    });
    after(async function () {
      await srv?.arreter();
    });
    beforeEach(function () {
      if (!dispo.ok) enAttente(this, dispo.condition);
    });

    it("démon réel en production : signer_ready (classe B, URL, clé, version ; jamais le jeton) ; rotation planifiée vers rec-sinistres-2026-02 ; appels répondus ; journal accepté par N.verifierJournal ; dossiers valides pour le noyau", function () {
      verifierParcours(ev, "B", type);
      expect(ev.c.config.recorder.environment).to.equal("production");
      const pret = ev.lignes.find((l) => l.event === "signer_ready");
      expect(pret.data.backend_key).to.deep.include({ key_name: "rec-sinistres-2026-01", key_version: 1 });
      expect(JSON.stringify(ev.lignes)).to.not.include(ev.jeton);
    });

    it("dossiers d'avant et d'après la rotation : valides pour le binaire Go (go1.27.3)", function () {
      verifierParGo(this, ev);
    });
  });
}

// ------------------------------------------------------------------ classe C (production)

describe("parcours, classe C en production : enveloppe AWS KMS par LocalStack réel", function () {
  this.timeout(400000);
  const dispo = conditions(superutilisateur, () => dockerEtImage(IMAGES_SIGNATAIRES.kms));
  const ev = {};
  let ls;
  before(async function () {
    if (!dispo.ok) return;
    ls = await demarrerKmsLocalStack(`noortrace-test-parcours-kms-${process.pid}`);
    const arn = await ls.creerCleSymetrique();
    const d = path.join(dir, "graines-kms");
    fs.mkdirSync(d);
    const fichier = path.join(d, "rec-c-01.bin");
    const c = await configurationParcours(
      { class: "C", key_id: "rec-c-01", next_key_id: "rec-c-02", backend: { type: "envelope", sealed_seed_file: fichier, wrap: { type: "aws-kms", key_arn: arn, region: "us-east-1" } } },
      { nom: "kms", environment: "production", env: ls.env },
    );
    const ctx = (k) => ({ org_id: c.config.recorder.org_id, journal_id: c.config.recorder.journal_id, key_id: k });
    ev.graine = N.sha256(N.utf8("graine de parcours c-01"));
    fs.writeFileSync(fichier, await ls.chiffrerGraine(arn, ev.graine, ctx("rec-c-01")));
    fs.writeFileSync(path.join(d, "rec-c-02.bin"), await ls.chiffrerGraine(arn, N.sha256(N.utf8("graine de parcours c-02")), ctx("rec-c-02")));
    Object.assign(ev, await parcours(c));
  });
  after(function () {
    ls?.arreter();
  });
  beforeEach(function () {
    if (!dispo.ok) enAttente(this, dispo.condition);
  });

  it("démon réel en production : graine déchiffrée (Decrypt, contexte org_id, journal_id, key_id), signer_ready (classe C, aws-kms ; jamais la graine) ; rotation planifiée ; journal et dossiers valides pour le noyau", function () {
    verifierParcours(ev, "C", "envelope");
    expect(ev.lignes.find((l) => l.event === "signer_ready").data.backend_key).to.include({ wrap: "aws-kms" });
    const texte = JSON.stringify(ev.lignes);
    expect(texte).to.not.include(Buffer.from(ev.graine).toString("hex"));
    expect(texte).to.not.include(Buffer.from(ev.graine).toString("base64"));
  });

  it("dossiers d'avant et d'après la rotation : valides pour le binaire Go (go1.27.3)", function () {
    verifierParGo(this, ev);
  });
});

describe("parcours, classe C en production : enveloppe TPM 2.0 logiciel réel (swtpm), politique PCR", function () {
  this.timeout(300000);
  const dispo = conditions(superutilisateur, tpmDisponible);
  const ev = {};
  let tpm;
  before(async function () {
    if (!dispo.ok) return;
    tpm = await demarrerSwtpm(path.join(dir, "tpm-parcours"));
    const d = path.join(dir, "graines-tpm");
    fs.mkdirSync(d);
    ev.graine = N.sha256(N.utf8("graine de parcours tpm c-01"));
    const w = tpm.sceller(ev.graine, "sha256:0,1,2,3", path.join(d, "rec-c-01"));
    tpm.sceller(N.sha256(N.utf8("graine de parcours tpm c-02")), "sha256:0,1,2,3", path.join(d, "rec-c-02"));
    const c = await configurationParcours(
      { class: "C", key_id: "rec-c-01", next_key_id: "rec-c-02", backend: { type: "envelope", sealed_seed_file: w.private_file, wrap: { type: "tpm2", ...w, pcrs: "sha256:0,1,2,3" } } },
      { nom: "tpm", environment: "production", env: tpm.env },
    );
    Object.assign(ev, await parcours(c));
  });
  after(function () {
    tpm?.arreter();
  });
  beforeEach(function () {
    if (!dispo.ok) enAttente(this, dispo.condition);
  });

  it("démon réel en production : graine descellée (tpm2_unseal -p pcr:sha256:0,1,2,3), signer_ready (classe C, tpm2) ; rotation planifiée ; journal et dossiers valides pour le noyau", function () {
    verifierParcours(ev, "C", "envelope");
    expect(ev.lignes.find((l) => l.event === "signer_ready").data.backend_key).to.include({ wrap: "tpm2", pcrs: "sha256:0,1,2,3" });
    expect(JSON.stringify(ev.lignes)).to.not.include(Buffer.from(ev.graine).toString("hex"));
  });

  it("dossiers d'avant et d'après la rotation : valides pour le binaire Go (go1.27.3)", function () {
    verifierParGo(this, ev);
  });
});

// ------------------------------------------------------------------ TE-16, ligne « clé indisponible »

/** Lignes d'événements des segments d'un journal. */
const nbEvenements = async (rep) => (fs.existsSync(path.join(rep, "segments")) ? (await lireEvenements(rep)).length : 0);

/** Points de contrôle écrits dans les séries `points/periode-*.ndjson` d'un journal (CT-2 EX-12.26). */
const nbPoints = (rep) => {
  const d = path.join(rep, "points");
  if (!fs.existsSync(d)) return 0;
  return fs.readdirSync(d).filter((x) => x.endsWith(".ndjson"))
    .reduce((n, x) => n + fs.readFileSync(path.join(d, x), "utf8").split("\n").filter(Boolean).length, 0);
};

describe("CT-9 TE-16, ligne « clé indisponible » de la matrice de CT-2 §14.2 (et « panne après relais »), rejouée sur le démon réel : Vault suspendu pendant une lecture puis une écriture, puis rétabli", function () {
  this.timeout(400000);
  const dispo = conditions(superutilisateur, () => dockerEtImage(IMAGES_SIGNATAIRES["vault-transit"]));
  const ev = {};
  before(async function () {
    if (!dispo.ok) return;
    const srv = await demarrerTransit("vault-transit", `noortrace-test-te16-${process.pid}`, tls);
    try {
      await srv.creerCle("rec-te16-01");
      const jeton = await srv.jetonUsage(["rec-te16-01"]);
      const c = await configurationParcours(
        { class: "B", key_id: "rec-te16-01", timeout_ms: 800, backend: { type: "vault-transit", url: srv.origine, mount: "transit", key_name: "rec-te16-01", token: { env: "NOORTRACE_TEST_JETON_TRANSIT" }, namespace: null } },
        { nom: "te16", environment: "production", health_interval_ms: 3600000, env: { NOORTRACE_TEST_JETON_TRANSIT: jeton, NODE_EXTRA_CA_CERTS: tls.ca } },
      );
      c.config.signer.rotation = { planned_every_days: null, next_key_id: null };
      ev.c = c;
      const p = await demarrer(REFERENCE, c, path.join(c.dir, "configuration.json"));
      const j = c.env.NOORTRACE_TEST_JETON_HOTE;
      try {
        // Précondition : la lecture L1 doit arriver avant que la panne soit
        // connue. Trois signatures ou appels au signataire du démon la feraient
        // connaître sans L1 : le premier health() (au premier tic du démon, qui
        // peut suivre le retour de `demarrer` ; ensuite une fois par heure), le
        // point de contrôle de chaque instant aligné (checkpoint_interval_s) et
        // la clôture de période à l'heure pleine, qui en est un. Signataire
        // coupé, chacun met le démon en mode « clé » : L1 serait alors bloquée
        // (-31010), et le chemin « panne après relais » ne serait pas joué ;
        // avant la correction de l'écrivain, une clôture en échec ne le mettait
        // pas en mode « clé » et l'écriture E1 était relayée (-31017). On attend
        // donc qu'un point aligné soit écrit, Vault disponible : le tic qui l'a
        // écrit a fait avant lui le premier health() (Coeur.tic), et le point
        // suivant est à un intervalle entier, que la suspension et L1 ne
        // franchissent pas (vérifié après L1). Un point du premier intervalle
        // de l'heure ne compte pas : à l'heure pleine, le même tic écrit le
        // point de clôture, puis signe le manifeste et le premier point de la
        // période suivante (ecrivain.mjs, _clore).
        const intervalleMs = (c.config.checkpoint_interval_s ?? 60) * 1000;
        const periodeMs = N.DUREE_PERIODE * 1000;
        let points = nbPoints(c.journal);
        await attendre(() => {
          const n = nbPoints(c.journal);
          if (n === points) return false;
          points = n;
          return Date.now() % periodeMs >= intervalleMs;
        }, 2 * intervalleMs + 30000);
        const instantAligne = Math.floor(Date.now() / intervalleMs);
        ev.avant = await nbEvenements(c.journal);
        // Signataire coupé (service suspendu) ; L1, relayée, voit sa signature échouer.
        suspendreConteneur(srv.nom, true);
        ev.lecture = await appelerOutil(c.portHttp, j, "demo__lire", { id: "L1" });
        if (Math.floor(Date.now() / intervalleMs) !== instantAligne) {
          throw new Error(`TE-16 : précondition non tenue, un instant aligné (point de contrôle de ${intervalleMs} ms) est passé entre la suspension du signataire et la réponse à L1`);
        }
        // Puis une écriture, et une lecture, pendant la panne.
        ev.ecriture = await appelerOutil(c.portHttp, j, "demo__ecrire", { id: "E1", montant: "5" });
        ev.lecture2 = await appelerOutil(c.portHttp, j, "demo__lire", { id: "L2" });
        ev.santePanne = await sante(c.portSante);
        ev.pendant = await nbEvenements(c.journal);
        // Rétablissement : sortie du mode « clé » (health() puis signature de test), événement en attente scellé.
        suspendreConteneur(srv.nom, false);
        await attendre(() => p.lignes().some((l) => l.event === "degraded_exit" && l.data?.reason === "cle"), 30000);
        await attendre(() => p.lignes().some((l) => l.event === "pending_flushed"), 30000);
        ev.apres = await appelerOutil(c.portHttp, j, "demo__ecrire", { id: "E2", montant: "6" });
        ev.santeApres = await sante(c.portSante);
      } finally {
        await arreter(p);
      }
      ev.lignes = p.lignes();
      ev.evts = await lireEvenements(c.journal);
    } finally {
      await srv.arreter();
    }
  });
  beforeEach(function () {
    if (!dispo.ok) enAttente(this, dispo.condition);
  });

  it("lecture relayée quand la signature échoue : -31017 (panne après relais), événement complet gardé en attente (EX-4.46) ; call_executed_not_durable consigné", function () {
    expect(ev.lecture.corps?.error?.code, JSON.stringify(ev.lecture.corps)).to.equal(-31017);
    expect(ev.lignes.some((l) => l.event === "call_executed_not_durable")).to.equal(true);
  });

  it("pendant la panne, écriture ET lecture bloquées (« clé indisponible = bloquant pour tout ») : -31010, data.reason « cle », message fixe ASCII ; aucun événement scellé ; santé down « cle » (EX-14.5, EX-14.11)", function () {
    for (const r of [ev.ecriture, ev.lecture2]) {
      expect(r.corps?.error?.code, JSON.stringify(r.corps)).to.equal(-31010);
      expect(r.corps.error.data).to.deep.equal({ reason: "cle" });
      expect(r.corps.error.message).to.match(/^[\x20-\x7e]+$/);
    }
    expect(ev.pendant).to.equal(ev.avant);
    expect(ev.santePanne.statut).to.equal(503);
    expect(ev.santePanne.corps.reasons).to.include("cle");
  });

  it("journal d'exploitation : signer_unavailable (type de backend, classe, erreur sans secret), degraded_enter « cle », call_blocked, puis degraded_exit et pending_flushed (EX-14.7, EX-14.10)", function () {
    const indispo = ev.lignes.filter((l) => l.event === "signer_unavailable");
    expect(indispo.length).to.be.at.least(1);
    expect(indispo[0].data).to.include({ backend: "vault-transit", class: "B" });
    expect(JSON.stringify(indispo)).to.not.include(ev.c.env.NOORTRACE_TEST_JETON_TRANSIT);
    expect(ev.lignes.some((l) => l.event === "degraded_enter" && l.data?.reason === "cle")).to.equal(true);
    expect(ev.lignes.some((l) => l.event === "call_blocked")).to.equal(true);
    expect(ev.lignes.some((l) => l.event === "degraded_exit" && l.data?.reason === "cle")).to.equal(true);
  });

  it("rétabli : l'événement en attente de la lecture est scellé (une fois), les appels suivants sont répondus, santé ok ; aucune écriture relayée sans événement durable", function () {
    const lectures = ev.evts.filter((e) => e.execution.tool === "demo__lire");
    expect(lectures.map((e) => e.execution.arguments)).to.have.length(1);
    expect(ev.evts.filter((e) => e.execution.tool === "demo__ecrire")).to.have.length(1);
    expect(ev.apres.corps?.result?.isError, JSON.stringify(ev.apres.corps)).to.equal(false);
    expect(ev.santeApres.corps).to.deep.equal({ status: "ok" });
    ev.evts.forEach((e, k) => expect(e.seq).to.equal(k + 1));
  });
});
