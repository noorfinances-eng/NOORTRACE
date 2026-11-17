// CT-9 TE-16 : lignes de la matrice des pannes de CT-2 §14.2 rejouées sur le
// démon réel `bin/noortrace --config`, chacune finie par le dossier d'un
// événement scellé après le rétablissement, vérifié par les deux
// vérificateurs de CT-6 : l'implémentation de référence
// (`scripts/verify/dossier.mjs`) et le binaire Go `noortrace-verifier`
// (NOORTRACE_VERIFIER_BIN, construit par verificateur/scripts/construire.sh ;
// sans lui, la vérification Go de chaque ligne est en attente, condition
// nommée).
//
// Pour chaque ligne : un journal propre ; la dépendance est coupée pendant un
// appel d'écriture et un appel de lecture (frontal MCP, Streamable HTTP) ; on
// relève ce qui est rendu à l'hôte, le journal d'exploitation et les
// événements en attente ; la dépendance est rétablie, un dernier appel est
// répondu et scellé ; le démon est arrêté, une instance du cœur clôt la
// période à l'heure suivante et exporte le dossier de ce dernier événement.
//
// Pannes provoquées sur le démon réel, sans le modifier :
//   - stockage : le segment courant est rendu immuable (`chattr +i`, EPERM à
//     l'écriture, même sur un descripteur ouvert), puis rendu (`chattr -i`) ;
//     superutilisateur et système de fichiers qui l'admettent exigés ;
//   - disque presque plein : racine du stockage sur un tmpfs de 32 Mio monté
//     pour l'essai, `storage.min_free_bytes` à 8 Mio, fichier de remplissage ;
//     superutilisateur exigé ;
//   - serveur d'outils : processus stdio tué pendant l'appel ; délai de
//     l'outil plus court que sa réponse ;
//   - service d'approbation : service simulé qui répond `non_pret` ;
//   - bail : seconde instance sur le même journal et le même bail `file` ;
//     bail perdu par l'auxiliaire `flock(1)` de l'active tué ;
//   - horloge murale du démon pilotée par libfaketime (NOORTRACE_LIBFAKETIME,
//     décalage relu à chaque appel, horloges monotones intactes) : recul au-delà
//     de clock.max_backstep_ms, puis avance au-delà de clock.max_forward_ms ;
//   - configuration : fichier invalide au démarrage, puis au rechargement
//     (SIGHUP).
// Les lignes « Clé indisponible » et « Panne après relais » par le signataire
// (Vault suspendu) sont rejouées par test/enregistreur-signataires-parcours.test.js,
// « Support WORM » par test/enregistreur-journal-soi.test.js (S3 à Object Lock
// en conteneur).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { Coeur, validerConfiguration, resoudreSecrets, lireEvenements, signataireDepuisConfiguration } from "@noortrace/enregistreur";
import { RACINE, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { REFERENCE, SERVEUR_OUTILS, detruireMutants, configurationDemon, demarrer, arreter, appelerOutil, attendre, sante, enfants, ecoute, tuerAuxiliaireBail } from "./fixtures/enregistreur-adversarial/demon.mjs";
import { HorlogePilotable, libfaketime } from "./fixtures/pannes/outils.mjs";

const VERIFIER_JS = path.join(RACINE, "scripts", "verify", "dossier.mjs");
const VERIFIER_GO = process.env.NOORTRACE_VERIFIER_BIN && fs.existsSync(process.env.NOORTRACE_VERIFIER_BIN) ? process.env.NOORTRACE_VERIFIER_BIN : null;

const enAttente = (ctx, condition) => {
  (ctx.currentTest ?? ctx.test).title += ` — en attente : ${condition}`;
  ctx.skip();
};

/** Horloge réelle décalée de `d` ms (monotone comprise). */
const horlogeDecalee = (d) => ({ murale: () => Date.now() + d, monotone: () => performance.now() + 1e7 + d });
/** Décalage vers l'heure suivante, de moins d'une heure. */
const versHeureSuivante = () => 3600000 - (Date.now() % 3600000) + 3000;
const pause = (ms) => new Promise((r) => setTimeout(r, ms));

/** `chattr` admis sur le répertoire de travail (superutilisateur, ext4 ou équivalent) ? */
function chattrDisponible(dir) {
  if (typeof process.getuid !== "function" || process.getuid() !== 0) return { ok: false, condition: "superutilisateur exigé (chattr +i sur le segment courant)" };
  const f = path.join(dir, "sonde-chattr");
  fs.writeFileSync(f, "x");
  try {
    const a = spawnSync("chattr", ["+i", f]);
    if (a.status !== 0) return { ok: false, condition: `chattr +i refusé ici (${String(a.stderr).trim() || a.error?.code})` };
    let refuse = false;
    try {
      fs.appendFileSync(f, "y");
    } catch {
      refuse = true;
    }
    spawnSync("chattr", ["-i", f]);
    return refuse ? { ok: true, condition: null } : { ok: false, condition: "chattr +i sans effet sur ce système de fichiers" };
  } finally {
    spawnSync("chattr", ["-i", f]);
    fs.rmSync(f, { force: true });
  }
}

/** Segment courant d'un journal (le plus récemment modifié sous segments/). */
function segmentCourant(journal) {
  const d = path.join(journal, "segments");
  const f = fs.readdirSync(d).map((x) => path.join(d, x)).filter((x) => fs.statSync(x).isFile()).sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);
  if (!f.length) throw new Error(`aucun segment sous ${d}`);
  return f[0];
}
const immuable = (f, oui) => execFileSync("chattr", [oui ? "+i" : "-i", f]);

/**
 * Coupe le stockage d'un journal : le segment courant, le répertoire des
 * pièces et ses sous-répertoires deviennent immuables (aucune écriture,
 * aucune création de fichier) ; les intentions et le fichier d'attente
 * restent inscriptibles. Rend la fonction qui rétablit.
 */
function couperStockage(journal) {
  const cibles = [segmentCourant(journal)];
  const parcourir = (d) => {
    if (!fs.existsSync(d)) return;
    cibles.push(d);
    for (const x of fs.readdirSync(d, { withFileTypes: true })) if (x.isDirectory()) parcourir(path.join(d, x.name));
  };
  parcourir(path.join(journal, "pieces"));
  for (const f of cibles) {
    immuables.add(f);
    immuable(f, true);
  }
  return () => {
    for (const f of cibles.reverse()) {
      immuable(f, false);
      immuables.delete(f);
    }
  };
}

let dir;
let service;
let serveurService;
let portService;
const demons = new Set();
const montages = [];
const immuables = new Set();

before(async function () {
  dir = repertoireTemporaire("noortrace-te16-matrice-");
  service = new ServiceApprobationFactice({ org_id: "0x00", journal_id: null });
  serveurService = await service.servir(0);
  portService = serveurService.address().port;
});

after(function () {
  serveurService?.close();
  for (const f of immuables) spawnSync("chattr", ["-i", f]);
  for (const m of montages) spawnSync("umount", ["-l", m]);
  detruireMutants();
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

/** Démons encore vivants (essai en échec) : arrêtés, comme les immuables rendus. */
async function arreterRestants() {
  for (const f of immuables) spawnSync("chattr", ["-i", f]);
  immuables.clear();
  for (const p of demons) await arreter(p);
  demons.clear();
  service.panne = null;
}

let n = 0;
/** Configuration d'un démon réel pour une ligne : journal propre sous dir/<nom>. */
async function configuration(nom, modifier = null) {
  const d = path.join(dir, `${++n}-${nom}`);
  fs.mkdirSync(d, { recursive: true });
  const c = await configurationDemon(d, { approbation: portService, modifier });
  service.org_id = c.config.recorder.org_id;
  service.journal_id = c.config.recorder.journal_id;
  c.fichier = path.join(d, "configuration.json");
  return c;
}

async function lancerDemon(c, etat = "ok") {
  const p = await demarrer(REFERENCE, c, c.fichier, etat);
  demons.add(p);
  return p;
}

async function arreterDemon(p) {
  await arreter(p);
  demons.delete(p);
  return p.fin;
}

const jetonHote = (c) => c.env.NOORTRACE_TEST_JETON_HOTE;
const appel = (c, outil, args) => appelerOutil(c.portHttp, jetonHote(c), `demo__${outil}`, args);
const erreur = (r) => r?.corps?.error ?? null;
const resultat = (r) => r?.corps?.result ?? null;

/**
 * Clôture à l'heure suivante par une instance du cœur, export du dossier du
 * dernier événement d'un appel `demo__*`, et vérification par les deux
 * vérificateurs. Rend { evts, evenement, dossier, js, go }.
 */
async function dossierVerifie(c, nom) {
  const v = validerConfiguration(new TextEncoder().encode(JSON.stringify({ ...c.config, recorder: { ...c.config.recorder, instance_id: "inst-cloture" }, supervision: { ...c.config.supervision, ops_log: { ...c.config.supervision.ops_log, path: path.join(c.dir, "exploitation-cloture.ndjson") } } })));
  expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
  const s = resoudreSecrets(v.config, { env: { ...process.env, ...c.env } });
  const backend = await signataireDepuisConfiguration(v.config, s.secrets, { env: { ...process.env, ...c.env } });
  const C = await Coeur.demarrer({ config: v.config, secrets: s.secrets, signataire: backend, horloge: horlogeDecalee(versHeureSuivante()) });
  const r = {};
  try {
    await C.tic();
    r.evts = await lireEvenements(C.repertoire);
    r.evenement = r.evts.filter((e) => String(e.execution?.tool ?? "").startsWith("demo__")).at(-1);
    expect(r.evenement, "événement d'un appel scellé").to.not.equal(undefined);
    r.dossier = path.join(c.dir, `dossier-${nom}`);
    await C.exporterDossier(r.evenement.seq, r.dossier);
  } finally {
    await C.arreter();
  }
  const js = spawnSync(process.execPath, [VERIFIER_JS, r.dossier, "--json"], { encoding: "utf8", cwd: RACINE });
  r.js = { code: js.status, rapport: JSON.parse(js.stdout || "null"), sortie: js.stdout + js.stderr };
  if (VERIFIER_GO) {
    const go = spawnSync(VERIFIER_GO, [r.dossier, "--json"], { encoding: "utf8" });
    r.go = { code: go.status, rapport: JSON.parse(go.stdout || "null"), sortie: go.stdout + go.stderr };
  }
  return r;
}

/** Assertions communes de fin de ligne : journal valide, séquence continue, dossier valide pour les deux vérificateurs. */
function verifierDossier(ctx, d) {
  d.evts.forEach((e, k) => expect(e.seq, "séquence continue").to.equal(k + 1));
  expect(d.js.code, d.js.sortie.slice(-1500)).to.equal(0);
  expect(d.js.rapport.verdict, d.js.sortie.slice(-1500)).to.equal("valide");
  if (!VERIFIER_GO) enAttente(ctx, "binaire noortrace-verifier absent (NOORTRACE_VERIFIER_BIN)");
  expect(d.go.code, d.go.sortie.slice(-1500)).to.equal(0);
  expect(d.go.rapport.verdict).to.equal("valide");
  expect(d.go.rapport.failed_checks).to.deep.equal([]);
}

const lignes = (p, ev) => p.lignes().filter((l) => l.event === ev);
/** Nombre d'événements scellés d'un outil `demo__<outil>` (les arguments sont des références : on compte). */
const nb = (d, outil) => d.evts.filter((e) => e.execution?.tool === `demo__${outil}`).length;

describe("CT-9 TE-16 : matrice des pannes de CT-2 §14.2 rejouée sur le démon réel, ligne par ligne, chaque ligne finie par un dossier vérifié par les deux vérificateurs (référence et binaire Go)", function () {
  this.timeout(240000);
  afterEach(arreterRestants);

  it("« Stockage indisponible » (segment rendu immuable : écriture en erreur) : écriture bloquée (-31010, stockage) ; lecture passante relayée, événement en attente ; degraded_enter stockage ; rétabli : événement en attente scellé, degraded_exit ; dossier vérifié", async function () {
    const dispo = chattrDisponible(dir);
    if (!dispo.ok) enAttente(this, dispo.condition);
    const c = await configuration("stockage");
    const p = await lancerDemon(c);
    expect(resultat(await appel(c, "lire", { id: "AVANT" }))?.isError).to.equal(false);
    // Les pièces sont écrites avant le relais (4.4) : leur écriture refusée révèle la panne avant tout relais.
    const retablir = couperStockage(c.journal);
    const e1 = await appel(c, "ecrire", { id: "E1", montant: "5" });
    const l1 = await appel(c, "lire", { id: "L1" });
    const santePanne = await sante(c.portSante);
    retablir();
    await attendre(() => lignes(p, "degraded_exit").some((l) => l.data?.reason === "stockage"), 60000);
    await attendre(() => lignes(p, "pending_flushed").length > 0, 60000);
    const apres = await appel(c, "lire", { id: "APRES" });
    await arreterDemon(p);
    const d = await dossierVerifie(c, "stockage");
    expect(erreur(e1)?.code, JSON.stringify(e1.corps)).to.equal(-31010);
    expect(erreur(e1).data).to.deep.equal({ reason: "stockage" });
    expect(resultat(l1)?.isError, JSON.stringify(l1.corps)).to.equal(false);
    expect(santePanne.corps.reasons ?? [], JSON.stringify(santePanne)).to.include("stockage");
    expect(lignes(p, "storage_unavailable").length).to.be.at.least(1);
    expect(lignes(p, "degraded_enter").some((l) => l.data?.reason === "stockage")).to.equal(true);
    expect(resultat(apres)?.isError).to.equal(false);
    // AVANT, L1 (en attente pendant la panne, scellée une fois) et APRES ; E1, bloquée, n'a aucun événement.
    expect(nb(d, "lire")).to.equal(3);
    expect(nb(d, "ecrire")).to.equal(0);
    verifierDossier(this, d);
  });

  it("« Panne après relais » (EX-4.46 ; stockage coupé entre l'envoi de l'écriture et sa durabilité) : -31017, événement complet gardé en attente, call_executed_not_durable ; rétabli : scellé une fois ; dossier vérifié", async function () {
    const dispo = chattrDisponible(dir);
    if (!dispo.ok) enAttente(this, dispo.condition);
    const c = await configuration("apres-relais");
    const p = await lancerDemon(c);
    expect(resultat(await appel(c, "lire", { id: "AVANT" }))?.isError).to.equal(false);
    const enCours = appel(c, "ecrire_lent", { id: "E1", attente_ms: 2500 });
    await pause(1000);
    const retablir = couperStockage(c.journal);
    const e1 = await enCours;
    retablir();
    await attendre(() => lignes(p, "degraded_exit").length > 0, 60000);
    await attendre(() => lignes(p, "pending_flushed").length > 0, 60000);
    const apres = await appel(c, "lire", { id: "APRES" });
    await arreterDemon(p);
    const d = await dossierVerifie(c, "apres-relais");
    expect(erreur(e1)?.code, JSON.stringify(e1.corps)).to.equal(-31017);
    expect(lignes(p, "call_executed_not_durable").length).to.be.at.least(1);
    expect(resultat(apres)?.isError).to.equal(false);
    expect(nb(d, "ecrire_lent"), "l'écriture relayée a son événement, scellé une fois").to.equal(1);
    expect(nb(d, "lire")).to.equal(2);
    verifierDossier(this, d);
  });

  it("« Mémoire » (file d'attente au-delà de pending_max_events = 2, stockage coupé) : la troisième lecture en attente est bloquée (-31010, attente), pending_limit_reached ; rétabli : la lecture en attente est scellée ; dossier vérifié", async function () {
    const dispo = chattrDisponible(dir);
    if (!dispo.ok) enAttente(this, dispo.condition);
    const c = await configuration("memoire", (config) => {
      config.policy.failure.pending_max_events = 2;
    });
    const p = await lancerDemon(c);
    expect(resultat(await appel(c, "lire", { id: "AVANT" }))?.isError).to.equal(false);
    const retablir = couperStockage(c.journal);
    const l0 = await appel(c, "lire", { id: "L0" });
    const l1 = await appel(c, "lire", { id: "L1" });
    const l2 = await appel(c, "lire", { id: "L2" });
    retablir();
    await attendre(() => lignes(p, "pending_flushed").length > 0, 60000);
    await attendre(() => !lignes(p, "degraded_enter").length || lignes(p, "degraded_exit").length >= lignes(p, "degraded_enter").length, 60000);
    const apres = await appel(c, "lire", { id: "APRES" });
    await arreterDemon(p);
    const d = await dossierVerifie(c, "memoire");
    for (const r of [l0, l1]) expect(resultat(r)?.isError, JSON.stringify(r.corps)).to.equal(false);
    expect(erreur(l2)?.code, JSON.stringify(l2.corps)).to.equal(-31010);
    expect(erreur(l2).data).to.deep.equal({ reason: "attente" });
    expect(lignes(p, "pending_limit_reached").length).to.be.at.least(1);
    expect(resultat(apres)?.isError).to.equal(false);
    // AVANT, L0, L1 et APRES ; L2, bloquée, n'a aucun événement.
    expect(nb(d, "lire")).to.equal(4);
    verifierDossier(this, d);
  });

  it("« Pièces d'événements en attente perdues » (EX-14.8 : démon tué pendant le mode dégradé « stockage ») : le démon redémarre ; l'événement relu du fichier d'attente est scellé sans ses pièces, pending_pieces_lost ; dossier vérifié", async function () {
    const dispo = chattrDisponible(dir);
    if (!dispo.ok) enAttente(this, dispo.condition);
    const c = await configuration("pieces-perdues");
    const p = await lancerDemon(c);
    expect(resultat(await appel(c, "lire", { id: "AVANT" }))?.isError).to.equal(false);
    const retablir = couperStockage(c.journal);
    const l0 = await appel(c, "lire", { id: "L0" });
    const l1 = await appel(c, "lire", { id: "L1" });
    // Les deux lignes du fichier d'attente écrites (EX-14.8, « au mieux ») : ce sont elles qui survivent à l'arrêt.
    const attente = path.join(c.journal, "attente");
    const lignesAttente = () => (fs.existsSync(attente) ? fs.readdirSync(attente).flatMap((f) => fs.readFileSync(path.join(attente, f), "utf8").split("\n").filter(Boolean)) : []);
    await attendre(() => lignesAttente().length === 2, 10000);
    p.kill("SIGKILL");
    await p.fin;
    demons.delete(p);
    retablir();
    const p2 = await lancerDemon(c);
    await attendre(() => lignes(p2, "pending_pieces_lost").length > 0, 60000);
    const apres = await appel(c, "lire", { id: "APRES" });
    await arreterDemon(p2);
    const d = await dossierVerifie(c, "pieces-perdues");
    for (const r of [l0, l1]) expect(resultat(r)?.isError, JSON.stringify(r.corps)).to.equal(false);
    expect(resultat(apres)?.isError).to.equal(false);
    const perdues = lignes(p2, "pending_pieces_lost")[0].data;
    expect(perdues.events).to.be.at.least(1);
    expect(perdues.pieces).to.be.at.least(1);
    // AVANT, L0 et L1 (relues du fichier d'attente, sans leurs pièces) et APRES.
    expect(nb(d, "lire")).to.equal(4);
    verifierDossier(this, d);
  });

  it("« Disque presque plein » (racine sur un tmpfs, espace libre sous storage.min_free_bytes) : écriture bloquée (-31010, stockage), disk_low ; lecture passante en attente ; espace rendu : sortie du mode dégradé, attente scellée ; dossier vérifié", async function () {
    if (typeof process.getuid !== "function" || process.getuid() !== 0) enAttente(this, "superutilisateur exigé (montage d'un tmpfs)");
    const racine = path.join(dir, "tmpfs-disque");
    fs.mkdirSync(racine, { recursive: true });
    const m = spawnSync("mount", ["-t", "tmpfs", "-o", "size=32m", "tmpfs", racine]);
    if (m.status !== 0) enAttente(this, `montage tmpfs refusé (${String(m.stderr).trim()})`);
    montages.push(racine);
    try {
      const c = await configuration("disque", (config) => {
        config.storage.root = path.join(racine, "stockage");
        config.storage.min_free_bytes = 8 * 1048576;
      });
      const p = await lancerDemon(c);
      expect(resultat(await appel(c, "lire", { id: "AVANT" }))?.isError).to.equal(false);
      const libre = fs.statfsSync(racine).bavail * fs.statfsSync(racine).bsize;
      const remplissage = path.join(racine, "remplissage");
      fs.writeFileSync(remplissage, Buffer.alloc(libre - 4 * 1048576));
      await attendre(() => lignes(p, "disk_low").length > 0, 30000);
      const e1 = await appel(c, "ecrire", { id: "E1", montant: "5" });
      const l1 = await appel(c, "lire", { id: "L1" });
      fs.rmSync(remplissage);
      await attendre(() => lignes(p, "degraded_exit").some((l) => l.data?.reason === "stockage"), 60000);
      await attendre(() => lignes(p, "pending_flushed").length > 0, 60000);
      const apres = await appel(c, "lire", { id: "APRES" });
      await arreterDemon(p);
      const d = await dossierVerifie(c, "disque");
      expect(erreur(e1)?.code, JSON.stringify(e1.corps)).to.equal(-31010);
      expect(erreur(e1).data).to.deep.equal({ reason: "stockage" });
      expect(resultat(l1)?.isError, JSON.stringify(l1.corps)).to.equal(false);
      expect(lignes(p, "disk_low")[0].data).to.have.property("free_bytes");
      expect(resultat(apres)?.isError).to.equal(false);
      expect(nb(d, "lire")).to.equal(3);
      expect(nb(d, "ecrire")).to.equal(0);
      verifierDossier(this, d);
    } finally {
      await arreterRestants();
      spawnSync("umount", [racine]);
      montages.splice(montages.indexOf(racine), 1);
    }
  });

  it("« Serveur d'outils injoignable » (processus stdio tué pendant l'appel) : écriture rendue -31014, événement is_error ; le serveur est relancé au prochain appel ; dossier vérifié", async function () {
    const c = await configuration("serveur-mort");
    const p = await lancerDemon(c);
    expect(resultat(await appel(c, "lire", { id: "AVANT" }))?.isError).to.equal(false);
    const enCours = appel(c, "ecrire_lent", { id: "E1", attente_ms: 30000 });
    let serveur = null;
    await attendre(() => (serveur = enfants(p.pid).find((e) => e.commande.includes(SERVEUR_OUTILS))) !== undefined, 10000);
    await pause(500);
    process.kill(serveur.pid, "SIGKILL");
    const e1 = await enCours;
    // Relance au prochain appel, après restart.backoff_ms (EX-4.33) ; avant, l'appel est rendu -31014 sans être relayé.
    let apres;
    await attendre(async () => resultat((apres = await appel(c, "lire", { id: "APRES" })))?.isError === false, 60000, 500);
    expect(enfants(p.pid).some((e) => e.commande.includes(SERVEUR_OUTILS) && e.pid !== serveur.pid), "serveur relancé").to.equal(true);
    await arreterDemon(p);
    const d = await dossierVerifie(c, "serveur-mort");
    expect(erreur(e1)?.code, JSON.stringify(e1.corps)).to.equal(-31014);
    const ev = d.evts.find((e) => e.execution.tool === "demo__ecrire_lent");
    expect(ev, "événement de l'écriture perdue après l'envoi").to.not.equal(undefined);
    expect(nb(d, "ecrire_lent")).to.equal(1);
    expect(lignes(p, "upstream_unreachable").length + lignes(p, "child_exited").length).to.be.at.least(1);
    expect(ev.execution.is_error).to.equal(true);
    expect(resultat(apres)?.isError, JSON.stringify(apres.corps)).to.equal(false);
    verifierDossier(this, d);
  });

  it("« Délai du serveur d'outils » (EX-4.22 : timeout_ms de l'outil écoulé) : -31011, événement is_error de durée timeout_ms ; l'appel suivant est répondu ; dossier vérifié", async function () {
    const c = await configuration("delai", (config) => {
      config.policy.servers.demo.tools.ecrire_lent.timeout_ms = 500;
    });
    const p = await lancerDemon(c);
    const e1 = await appel(c, "ecrire_lent", { id: "E1", attente_ms: 5000 });
    const apres = await appel(c, "lire", { id: "APRES" });
    await arreterDemon(p);
    const d = await dossierVerifie(c, "delai");
    expect(erreur(e1)?.code, JSON.stringify(e1.corps)).to.equal(-31011);
    const ev = d.evts.find((e) => e.execution.tool === "demo__ecrire_lent");
    expect(ev.execution.is_error).to.equal(true);
    expect(ev.execution.duration_ms).to.equal(500);
    expect(lignes(p, "upstream_timeout").length).to.be.at.least(1);
    expect(resultat(apres)?.isError).to.equal(false);
    verifierDossier(this, d);
  });

  it("« Service d'approbation (CT-3) indisponible » (le service répond non_pret) : écriture bloquée (-31010, approbation) sans événement ; lecture relayée ; approval_service_unavailable ; rétabli : écriture répondue ; dossier vérifié", async function () {
    const c = await configuration("approbation");
    const p = await lancerDemon(c);
    service.panne = "non_pret";
    const e1 = await appel(c, "ecrire", { id: "E1", montant: "5" });
    const l1 = await appel(c, "lire", { id: "L1" });
    service.panne = null;
    const apres = await appel(c, "ecrire", { id: "APRES", montant: "6" });
    await arreterDemon(p);
    const d = await dossierVerifie(c, "approbation");
    expect(erreur(e1)?.code, JSON.stringify(e1.corps)).to.equal(-31010);
    expect(erreur(e1).data).to.deep.equal({ reason: "approbation" });
    expect(resultat(l1)?.isError, JSON.stringify(l1.corps)).to.equal(false);
    expect(lignes(p, "approval_service_unavailable").length).to.be.at.least(1);
    expect(resultat(apres)?.isError, JSON.stringify(apres.corps)).to.equal(false);
    // E1, bloquée, n'a aucun événement ; APRES et L1 en ont un.
    expect(nb(d, "ecrire")).to.equal(1);
    expect(nb(d, "lire")).to.equal(1);
    verifierDossier(this, d);
  });

  it("« Bail non détenu » (13.4 : seconde instance sur le même journal) : instance passive, -31010 bail_non_detenu, lease_standby ; l'active arrêtée, la passive prend le bail et répond ; dossier vérifié", async function () {
    const c = await configuration("bail-a");
    const b = await configuration("bail-b");
    b.config.recorder.instance_id = "inst-adv-b";
    b.config.storage.root = c.config.storage.root;
    b.config.lease = { ...c.config.lease };
    b.journal = c.journal;
    const pa = await lancerDemon(c);
    expect(resultat(await appel(c, "lire", { id: "AVANT" }))?.isError).to.equal(false);
    const pb = await lancerDemon(b, "standby");
    const e1 = await appel(b, "ecrire", { id: "E1", montant: "5" });
    const l1 = await appel(b, "lire", { id: "L1" });
    await arreterDemon(pa);
    await attendre(async () => (await sante(b.portSante))?.corps?.status === "ok", 60000);
    const apres = await appel(b, "lire", { id: "APRES" });
    await arreterDemon(pb);
    const d = await dossierVerifie(b, "bail");
    for (const r of [e1, l1]) {
      expect(erreur(r)?.code, JSON.stringify(r.corps)).to.equal(-31010);
      expect(erreur(r).data).to.deep.equal({ reason: "bail_non_detenu" });
    }
    expect(lignes(pb, "lease_standby").length).to.be.at.least(1);
    expect(resultat(apres)?.isError, JSON.stringify(apres.corps)).to.equal(false);
    // AVANT (instance active) et APRES (instance devenue active) ; rien de la passive pendant l'attente.
    expect(nb(d, "lire")).to.equal(2);
    expect(nb(d, "ecrire")).to.equal(0);
    verifierDossier(this, d);
  });

  it("« Configuration invalide au démarrage » (15.4) : le démon ne démarre pas (code non nul, rapport sur stderr, rien n'écoute) ; démarré avec la configuration valide, il répond ; dossier vérifié", async function () {
    const c = await configuration("config-demarrage");
    const invalide = path.join(c.dir, "invalide.json");
    fs.writeFileSync(invalide, JSON.stringify({ ...c.config, version: 99 }));
    const r = await new Promise((res) => {
      const x = spawn(process.execPath, [REFERENCE.bin("noortrace"), "--config", invalide], { env: { ...process.env, ...c.env }, stdio: ["ignore", "pipe", "pipe"] });
      let err = "";
      x.stderr.on("data", (k) => (err += k));
      x.on("close", (code) => res({ code, err }));
    });
    const ecoutait = await ecoute(c.portSante);
    const p = await lancerDemon(c);
    const apres = await appel(c, "lire", { id: "APRES" });
    await arreterDemon(p);
    const d = await dossierVerifie(c, "config-demarrage");
    expect(r.code).to.equal(2);
    expect(r.err.length).to.be.greaterThan(0);
    expect(ecoutait).to.equal(false);
    expect(resultat(apres)?.isError).to.equal(false);
    verifierDossier(this, d);
  });

  it("« Configuration invalide au rechargement » (15.5, SIGHUP) : rechargement refusé, config_reload_rejected, l'ancienne configuration reste en vigueur et le relais continue ; dossier vérifié", async function () {
    const c = await configuration("config-rechargement");
    const p = await lancerDemon(c);
    const valide = fs.readFileSync(c.fichier, "utf8");
    fs.writeFileSync(c.fichier, JSON.stringify({ ...c.config, version: 99 }));
    p.kill("SIGHUP");
    await attendre(() => lignes(p, "config_reload_rejected").length > 0, 30000);
    fs.writeFileSync(c.fichier, valide);
    const apres = await appel(c, "ecrire", { id: "APRES", montant: "7" });
    const s = await sante(c.portSante);
    await arreterDemon(p);
    const d = await dossierVerifie(c, "config-rechargement");
    expect(resultat(apres)?.isError, JSON.stringify(apres.corps)).to.equal(false);
    expect(s.corps.status).to.equal("ok");
    expect(nb(d, "ecrire")).to.equal(1);
    verifierDossier(this, d);
  });

  it("« Bail perdu » (EX-13.6 : verrou de l'active rendu, une autre instance prend le bail) : l'ancienne active refuse tout (-31010, bail), lease_lost ; la nouvelle répond ; aucun événement de l'ancienne après la prise ; dossier vérifié", async function () {
    const c = await configuration("bail-perdu-a");
    const b = await configuration("bail-perdu-b");
    b.config.recorder.instance_id = "inst-adv-b";
    b.config.storage.root = c.config.storage.root;
    b.config.lease = { ...c.config.lease };
    b.journal = c.journal;
    const pa = await lancerDemon(c);
    expect(resultat(await appel(c, "lire", { id: "AVANT" }))?.isError).to.equal(false);
    const pb = await lancerDemon(b, "standby");
    tuerAuxiliaireBail(pa);
    await attendre(async () => (await sante(b.portSante))?.corps?.status === "ok", 60000, 100);
    const e1 = await appel(c, "ecrire", { id: "E1", montant: "5" });
    const l1 = await appel(c, "lire", { id: "L1" });
    await attendre(() => lignes(pa, "lease_lost").length > 0, 30000);
    const santeA = await sante(c.portSante);
    const apres = await appel(b, "lire", { id: "APRES" });
    await arreterDemon(pa);
    await arreterDemon(pb);
    const d = await dossierVerifie(b, "bail-perdu");
    for (const r of [e1, l1]) {
      expect(erreur(r)?.code, JSON.stringify(r.corps)).to.equal(-31010);
      expect(erreur(r).data).to.deep.equal({ reason: "bail" });
    }
    expect(santeA.statut).to.equal(503);
    expect(resultat(apres)?.isError, JSON.stringify(apres.corps)).to.equal(false);
    // AVANT (ancienne active) et APRES (nouvelle) ; rien de l'ancienne après la perte.
    expect(nb(d, "lire")).to.equal(2);
    expect(nb(d, "ecrire")).to.equal(0);
    verifierDossier(this, d);
  });

  it("« Horloge qui recule » au-delà de clock.max_backstep_ms (EX-7.9 ; horloge murale du démon reculée de 10 s, libfaketime) : écriture et lecture bloquées (-31010, horloge), clock_backstep ; horloge rendue : sortie du mode dégradé, appel répondu ; dossier vérifié", async function () {
    const lib = libfaketime();
    if (!lib.ok) enAttente(this, lib.condition);
    const h = new HorlogePilotable(path.join(dir, "horloge-recul"), lib.chemin);
    const c = await configuration("horloge-recul");
    Object.assign(c.env, h.env());
    const p = await lancerDemon(c);
    expect(resultat(await appel(c, "lire", { id: "AVANT" }))?.isError).to.equal(false);
    h.placer(-10);
    // Le recul n'est vu qu'à la lecture de ts par l'écrivain : l'appel qui le révèle est déjà relayé
    // (ligne « Panne après relais », -31017, raison horloge, événement gardé en attente).
    const revele = await appel(c, "lire", { id: "REVELE" });
    const e1 = await appel(c, "ecrire", { id: "E1", montant: "5" });
    const l1 = await appel(c, "lire", { id: "L1" });
    h.placer(0);
    await pause(1000);
    let apres;
    await attendre(async () => resultat((apres = await appel(c, "lire", { id: "APRES" })))?.isError === false, 60000, 1000);
    await arreterDemon(p);
    const d = await dossierVerifie(c, "horloge-recul");
    expect(erreur(revele)?.code, JSON.stringify(revele.corps)).to.equal(-31017);
    expect(erreur(revele).data.reason).to.equal("horloge");
    for (const r of [e1, l1]) {
      expect(erreur(r)?.code, JSON.stringify(r.corps)).to.equal(-31010);
      expect(erreur(r).data).to.deep.equal({ reason: "horloge" });
    }
    expect(lignes(p, "clock_backstep").length).to.be.at.least(1);
    expect(lignes(p, "degraded_enter").some((l) => l.data?.reason === "horloge")).to.equal(true);
    // AVANT, REVELE (scellée à la sortie du mode dégradé) et APRES ; E1 et L1, bloquées, n'ont aucun événement.
    expect(nb(d, "ecrire")).to.equal(0);
    expect(nb(d, "lire")).to.equal(3);
    verifierDossier(this, d);
  });

  it("« Horloge qui avance brutalement » au-delà de clock.max_forward_ms (EX-7.13 ; horloge murale avancée de 120 s, libfaketime) : écriture et lecture bloquées (-31010, horloge), clock_forward_jump, aucun ts posé dans le futur ; horloge revenue dans la tolérance : appel répondu ; dossier vérifié", async function () {
    const lib = libfaketime();
    if (!lib.ok) enAttente(this, lib.condition);
    const h = new HorlogePilotable(path.join(dir, "horloge-avance"), lib.chemin);
    const c = await configuration("horloge-avance");
    Object.assign(c.env, h.env());
    const p = await lancerDemon(c);
    expect(resultat(await appel(c, "lire", { id: "AVANT" }))?.isError).to.equal(false);
    h.placer(120);
    await attendre(() => lignes(p, "clock_forward_jump").length > 0, 30000);
    const e1 = await appel(c, "ecrire", { id: "E1", montant: "5" });
    const l1 = await appel(c, "lire", { id: "L1" });
    h.placer(0);
    let apres;
    await attendre(async () => resultat((apres = await appel(c, "lire", { id: "APRES" })))?.isError === false, 60000, 1000);
    await arreterDemon(p);
    const d = await dossierVerifie(c, "horloge-avance");
    for (const r of [e1, l1]) {
      expect(erreur(r)?.code, JSON.stringify(r.corps)).to.equal(-31010);
      expect(erreur(r).data).to.deep.equal({ reason: "horloge" });
    }
    // Aucun ts dans le futur : chaque événement est daté avant la fin de l'essai.
    for (const e of d.evts.filter((x) => String(x.execution?.tool ?? "").startsWith("demo__"))) expect(Date.parse(e.ts)).to.be.below(Date.now() + 1000);
    expect(nb(d, "ecrire")).to.equal(0);
    expect(nb(d, "lire")).to.equal(2);
    verifierDossier(this, d);
  });
});
