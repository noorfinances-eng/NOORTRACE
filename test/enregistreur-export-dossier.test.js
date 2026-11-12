// TE-18 (CT-9, étape 6) : export du dossier par `noortrace-ctl dossier
// exporter` sur le démon réel à horloge réglable (CT-2 révision 0.8, §15.7 :
// EX-15.9 à EX-15.14 ; CT-7 EX-3.16 ; MN-99). Journal de test : une période
// close et une ouverte, un appel approuvé par ticket et sa continuation MRTR,
// des tickets refusé, expiré, approuvé sans relais, non décidé, un ticket dont
// le jeu d'approbateurs est introuvable. Désignations `--seq`, `--dernier`,
// `--ticket` (premier `executee`, jamais la continuation) ; chaque refus
// d'EX-15.12 dans son ordre, avec son message et son code, sans dossier ni
// répertoire partiel ; destination existante, non vide, hors du volume, par
// lien symbolique, lien posé pendant l'écriture (point d'arrêt d'essai) ;
// export interrompu (arrêt brutal avant le renommage) puis reste supprimé à
// l'acquisition du bail ; modes 0750 et 0640, groupe des lecteurs (bit
// setgid) ; en production, droits du répertoire des exports et groupe du
// parent (superutilisateur ; en attente sinon) ; une ligne par demande avec
// son `request_id` ; commande : codes 0, 1, 2 et 4, délai unique, fichier
// occupé, signal impossible (demande retirée), `--option=valeur` refusé. Le
// dossier d'un appel approuvé exporté par ticket passe les deux
// vérificateurs de CT-6 avec `--exiger 7`.
//
// TA-99 (MN-99) : un mutant du démon qui ne vérifie plus le chemin réel du
// parent écrit le dossier hors du volume des exports par un lien symbolique
// (tué) ; sans mutant, `destination_hors_exports` et aucun fichier hors du
// volume. Le mutant est une copie de paquets/enregistreur sous NOORTRACE_TMP
// (ou os.tmpdir()), détruite dans un `after`.

import { expect } from "chai";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import { Coeur, HorlogeReglable, validerConfiguration, resoudreSecrets, pieceJson, principalCtlDemon } from "@noortrace/enregistreur";
import { exporterDemande, cheminReelSous } from "../paquets/enregistreur/src/export-dossier.mjs";
import { messageRefusExport, SuiviJournal } from "../paquets/enregistreur/src/ctl-demon.mjs";
import { configurationDev } from "./fixtures/enregistreur-coeur/outils.mjs";
import { binaireGo, enAttente } from "./fixtures/enregistreur-ancrage/outils.mjs";
import {
  construireJournal, DemonEssai, ctl, repertoireTemporaire, attendre, pause, lignesJournal, demandeDossier, deposerEtSignaler, VERIFICATEUR_JS, RACINE, PAQUET, TMP,
} from "./fixtures/enregistreur-export/outils.mjs";

const ROOT = typeof process.geteuid === "function" && process.geteuid() === 0;
const GROUPE_LECTEURS = 65534;
const GROUPE_AUTRE = 4;
const MEMBRES_EXPORTED = ["selection", "ticket", "seq", "hash", "period_start", "destination", "generated_at", "dossier_sha256", "parts_present", "files", "bitcoin_headers", "checkpoint_rank", "checkpoint_tree_size", "defects"];
const MEMBRES_REFUSED = ["raison", "selection", "seq", "ticket", "destination", "exports_dir", "period_start", "decision", "member", "at", "detail"];

/** Répertoires `.noortrace-partiel-*` sous une racine (sans suivre de lien). */
function partiels(racine) {
  const trouves = [];
  const pile = [racine];
  while (pile.length) {
    const d = pile.pop();
    let e = [];
    try {
      e = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const x of e) {
      if (!x.isDirectory()) continue;
      if (x.name.startsWith(".noortrace-partiel-")) trouves.push(path.join(d, x.name));
      else pile.push(path.join(d, x.name));
    }
  }
  return trouves;
}

/** Vérificateur JavaScript de référence (boîte noire, `npm run verify:dossier` sans npm) et binaire Go de CT-6. */
function verifier(dossier, bin = null) {
  const args = [dossier, "--exiger", "7", "--json"];
  const r = bin ? spawnSync(bin, args, { encoding: "utf8" }) : spawnSync(process.execPath, [VERIFICATEUR_JS, ...args], { cwd: RACINE, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return { code: r.status, rapport: r.stdout ? JSON.parse(r.stdout) : null, stderr: r.stderr };
}

const statut = (rapport, id) => rapport.checks.find((c) => c.id === id);
const controle = (rapport, n) => rapport.controls.find((c) => c.number === n);

describe("TE-18 : noortrace-ctl dossier exporter sur le démon réel à horloge réglable (CT-2 EX-15.9 à EX-15.14, CT-7 EX-3.16)", function () {
  this.timeout(600000);
  let dir;
  let j;
  let demon;
  let arret;
  /** request_id de chaque demande envoyée par la commande (une ligne de réponse chacune). */
  const demandes = [];

  const exporter = async (args, o = {}) => {
    return ctl(["dossier", "exporter", ...args, "--configuration", j.cheminConfig, ...(o.delai !== undefined ? ["--delai-ms", String(o.delai)] : [])], { env: j.env, cwd: o.cwd });
  };
  const ligneDe = (r) => lignesJournal(j.journal).filter((l) => (l.event === "dossier_exported" || l.event === "dossier_export_refused") && JSON.stringify(l.data) === JSON.stringify(r.ligne?.data)).at(-1);
  const refus = async (args, raison, o = {}) => {
    const r = await exporter(args, o);
    expect(r.code, `${args.join(" ")}\n${r.stderr}`).to.equal(1);
    expect(r.ligne.event).to.equal("dossier_export_refused");
    expect(Object.keys(r.ligne.data)).to.deep.equal(MEMBRES_REFUSED);
    expect(r.ligne.data.raison, args.join(" ")).to.equal(raison);
    expect(r.stderr).to.equal(`noortrace-ctl dossier exporter : ${messageRefusExport(r.ligne.data)}\n`);
    expect(partiels(j.exports), "aucun répertoire partiel").to.deep.equal([]);
    const l = ligneDe(r);
    expect(l).to.include({ level: "warning", component: "noyau", event: "dossier_export_refused" });
    expect(l.request_id).to.match(/^[0-9a-f]{32}$/);
    demandes.push(l.request_id);
    return r;
  };
  const reussite = async (args, o = {}) => {
    const r = await exporter(args, o);
    expect(r.code, `${args.join(" ")}\n${r.stderr}${demon.sortie.slice(-1000)}`).to.equal(0);
    expect(r.stderr).to.equal("");
    expect(r.ligne.event).to.equal("dossier_exported");
    expect(Object.keys(r.ligne.data)).to.deep.equal(MEMBRES_EXPORTED);
    const l = ligneDe(r);
    expect(l).to.include({ level: "info", component: "noyau", event: "dossier_exported", seq: r.ligne.data.seq, host: null });
    expect(l.request_id).to.match(/^[0-9a-f]{32}$/);
    demandes.push(l.request_id);
    return r;
  };

  before(async function () {
    dir = repertoireTemporaire("noortrace-te18-");
    arret = path.join(dir, "arret");
    fs.mkdirSync(arret);
    j = await construireJournal(dir);
    demon = new DemonEssai({ cheminConfig: j.cheminConfig, env: j.env, journal: j.journal, horloge: (j.P + 3600 + 600) * 1000 });
    await demon.demarrer();
  });

  after(async function () {
    await demon?.arreter().catch(() => {});
    await j?.fermer();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("--ticket d'un appel approuvé : le premier executee qui porte l'approbation, jamais sa continuation MRTR ; code 0, ligne { pid, configuration, event, data } aux membres d'EX-15.14 ; dossier.json, parties présentes et rien d'autre, 0750 et 0640 ; les deux vérificateurs de CT-6 rendent 0 avec --exiger 7 (contrôle 7 réussi)", async function () {
    const destination = path.join(j.exports, "ticket-approuve");
    const r = await reussite(["--ticket", j.tickets.approuve, "--vers", destination]);
    expect(r.ligne.pid).to.equal(demon.pid);
    expect(r.ligne.configuration).to.equal(fs.realpathSync(j.cheminConfig));
    const d = r.ligne.data;
    expect(d.seq).to.equal(j.seqs.executeApprouve);
    expect(d.seq).to.not.equal(j.seqs.continuation);
    expect(d).to.include({ selection: "ticket", ticket: j.tickets.approuve, period_start: j.P, destination, bitcoin_headers: false, checkpoint_rank: 4, defects: 0 });
    const evenement = JSON.parse(fs.readFileSync(path.join(destination, "evenement.json"), "utf8"));
    expect(evenement.seq).to.equal(d.seq);
    expect(d.hash).to.equal(evenement.hash);
    expect(evenement.execution.status).to.equal("executee");
    expect(evenement.approval).to.include({ ticket: j.tickets.approuve, decision: "approuve" });
    // La continuation suit et porte la même approbation (EX-4.21) : voisine, jamais retenue.
    const voisins = JSON.parse(fs.readFileSync(path.join(destination, "voisins.json"), "utf8"));
    expect(voisins.next.seq).to.equal(j.seqs.continuation);
    expect(voisins.next.approval).to.deep.equal(evenement.approval);
    const octetsIndex = fs.readFileSync(path.join(destination, "dossier.json"));
    expect(d.dossier_sha256).to.equal(N.sha256Hex(new Uint8Array(octetsIndex)));
    const index = JSON.parse(octetsIndex.toString("utf8"));
    expect(d.generated_at).to.equal(index.generated_at);
    expect(d.parts_present).to.equal(index.parts.filter((p) => p.present).length);
    const fichiers = fs.readdirSync(destination).sort();
    expect(fichiers).to.deep.equal([...index.parts.filter((p) => p.present).map((p) => p.file), "dossier.json"].sort());
    expect(d.files).to.equal(fichiers.length);
    expect(fs.statSync(destination).mode & 0o7777).to.equal(0o750);
    for (const f of fichiers) expect(fs.statSync(path.join(destination, f)).mode & 0o7777, f).to.equal(0o640);
    // approbations.json : le jeu d'approbateurs de la décision du ticket (EX-12.23).
    const approbations = JSON.parse(fs.readFileSync(path.join(destination, "approbations.json"), "utf8"));
    expect(approbations.approver_set).to.deep.equal(j.service.jeu);
    expect(approbations.events.map((e) => e.seq)).to.deep.equal([j.seqs.decisionApprouve]);
    // Vérificateur JavaScript de référence (boîte noire).
    const js = verifier(destination);
    expect(js.code, js.stderr).to.equal(0);
    expect(js.rapport.verdict).to.equal("valide");
    expect(controle(js.rapport, 7).status).to.equal("reussi");
    for (const a of ["A-1", "A-2", "A-3"]) expect(statut(js.rapport, a).status, a).to.equal("reussi");
    // A-4 : la demande (retenue) précède la décision, qui précède l'appel : elle n'est jamais voisine de l'appel exécuté ;
    // non exécutée pour une raison admise (événement de demande hors du dossier, CT-1 §11.4), comme au vecteur
    // valide-point-de-controle-complet de CT-6. Le dossier de la décision (--seq) l'exécute (essai suivant).
    expect(statut(js.rapport, "A-4")).to.include({ status: "non_execute", reason: "piece_hors_dossier", admitted: true });
    const bin = binaireGo();
    if (!bin) return enAttente(this, "vérificateur Go de CT-6 (NOORTRACE_VERIFIER_BIN, NOORTRACE_GO_BIN ou verificateur/dist/noortrace-verifier-linux-amd64) : vérification JavaScript faite, vérification Go non faite");
    const go = verifier(destination, bin);
    expect(go.code, go.stderr).to.equal(0);
    expect(go.rapport.verdict).to.equal("valide");
    expect(controle(go.rapport, 7).status).to.equal("reussi");
    expect(Object.fromEntries(go.rapport.checks.map((c) => [c.id, c.status]))).to.deep.equal(Object.fromEntries(js.rapport.checks.map((c) => [c.id, c.status])));
    expect(go.rapport.statement).to.deep.equal(js.rapport.statement);
  });

  it("--seq de la décision du ticket : A-1 à A-4 réussis par les deux vérificateurs (--exiger 7) ; --dernier : le plus grand seq d'une période close ; destination répertoire vide admise (remplacé par rename(2)) ; --vers relatif résolu contre le répertoire de travail ; --seq d'un appel au jeu introuvable : dossier écrit, partie approbations absente (« jeu d'approbateurs introuvable »)", async function () {
    const decision = path.join(j.exports, "decision");
    const r = await reussite(["--seq", String(j.seqs.decisionApprouve), "--vers", decision]);
    expect(r.ligne.data).to.include({ selection: "seq", ticket: null, seq: j.seqs.decisionApprouve });
    const js = verifier(decision);
    expect(js.code, js.stderr).to.equal(0);
    for (const a of ["A-1", "A-2", "A-3", "A-4"]) expect(statut(js.rapport, a).status, a).to.equal("reussi");
    const bin = binaireGo();
    if (bin) {
      const go = verifier(decision, bin);
      expect(go.code, go.stderr).to.equal(0);
      for (const a of ["A-1", "A-2", "A-3", "A-4"]) expect(statut(go.rapport, a).status, a).to.equal("reussi");
    }
    const vide = path.join(j.exports, "vide");
    fs.mkdirSync(vide);
    const r2 = await reussite(["--dernier", "--vers", "vide"], { cwd: j.exports });
    expect(r2.ligne.data).to.include({ selection: "dernier", seq: j.seqs.dernierClos, destination: vide });
    expect(fs.readdirSync(vide)).to.include("dossier.json");
    const r3 = await reussite(["--seq", String(j.seqs.executeSansJeu), "--vers", path.join(j.exports, "sans-jeu-par-seq")]);
    const index = JSON.parse(fs.readFileSync(path.join(j.exports, "sans-jeu-par-seq", "dossier.json"), "utf8"));
    expect(index.parts.find((p) => p.name === "approbations")).to.include({ present: false, reason_if_absent: "jeu d'approbateurs introuvable" });
    expect(r3.ligne.data.parts_present).to.equal(index.parts.filter((p) => p.present).length);
    if (!bin) return enAttente(this, "vérificateur Go de CT-6 : vérification JavaScript faite, vérification Go non faite");
  });

  it("ordres 7 à 9 d'EX-15.12 : evenement_inconnu, ticket_inconnu, ticket_non_decide, ticket_sans_appel_execute (refuse, expire, approuve sans relais), periode_non_close (--seq et --ticket), approbations_introuvables : code 1, message d'EX-15.12, ligne de refus aux membres d'EX-15.14, rien d'écrit", async function () {
    const dest = (n) => path.join(j.exports, n);
    let r = await refus(["--seq", "999999", "--vers", dest("x1")], "evenement_inconnu");
    expect(r.ligne.data).to.include({ selection: "seq", seq: 999999, exports_dir: j.exports, destination: dest("x1") });
    expect(r.stderr).to.include("aucun événement de numéro 999999 dans le journal");
    expect(ligneDe(r).seq).to.equal(null);
    r = await refus(["--ticket", "apr-inconnu-1", "--vers", dest("x2")], "ticket_inconnu");
    expect(r.stderr).to.include("aucun événement du journal ne porte le ticket apr-inconnu-1");
    r = await refus(["--ticket", j.tickets.nonDecide, "--vers", dest("x3")], "ticket_non_decide");
    expect(r.stderr).to.include(`le ticket ${j.tickets.nonDecide} n'est pas décidé`);
    for (const [ticket, decision] of [[j.tickets.refuse, "refuse"], [j.tickets.expire, "expire"], [j.tickets.approuveSansRelais, "approuve"]]) {
      r = await refus(["--ticket", ticket, "--vers", dest(`x-${decision}`)], "ticket_sans_appel_execute");
      expect(r.ligne.data).to.include({ decision, seq: null, ticket });
      expect(r.stderr).to.include(`le ticket ${ticket} est décidé (${decision}) sans appel exécuté ; le dossier de la décision s'exporte par --seq`);
    }
    r = await refus(["--seq", String(j.seqs.echange3), "--vers", dest("x5")], "periode_non_close");
    expect(r.ligne.data).to.include({ seq: j.seqs.echange3, period_start: j.P + 3600 });
    expect(ligneDe(r).seq).to.equal(j.seqs.echange3);
    expect(r.stderr).to.include(`la période ${new Date((j.P + 3600) * 1000).toISOString().replace(".000Z", "Z")} de l'événement ${j.seqs.echange3} n'est pas close`);
    r = await refus(["--ticket", j.tickets.approuveOuvert, "--vers", dest("x6")], "periode_non_close");
    expect(r.ligne.data).to.include({ seq: j.seqs.executeOuvert, ticket: j.tickets.approuveOuvert });
    r = await refus(["--ticket", j.tickets.sansJeu, "--vers", dest("x7")], "approbations_introuvables");
    expect(r.ligne.data.seq).to.equal(j.seqs.executeSansJeu);
    expect(r.stderr).to.include(`jeu d'approbateurs introuvable pour le ticket ${j.tickets.sansJeu} : aucun dossier écrit`);
    for (const n of ["x1", "x2", "x3", "x-refuse", "x-expire", "x-approuve", "x5", "x6", "x7"]) expect(fs.existsSync(dest(n)), n).to.equal(false);
  });

  it("ordres 2 à 6 d'EX-15.12 et leur précédence : exports_indisponible (absent, fichier, lien vers storage.root), destination_hors_exports (lexical, préfixe sans barre, le répertoire lui-même, lien qui sort du volume), parent_absent (absent, fichier), destination_existante (fichier, lien examiné sans être suivi, tube, prise), destination_non_vide ; un lien qui reste dans le volume est admis", async function () {
    const dest = (...n) => path.join(j.exports, ...n);
    const exportsBak = `${j.exports}.bak`;
    // Ordre 2 (et précédence sur l'ordre 3 et l'ordre 7).
    fs.renameSync(j.exports, exportsBak);
    try {
      let r = await refus(["--seq", "999999", "--vers", "/hors/du/volume"], "exports_indisponible");
      expect(r.stderr).to.include(`répertoire des exports indisponible : ${j.exports}`);
      expect(r.ligne.data.detail).to.equal(null);
      fs.writeFileSync(j.exports, "fichier");
      await refus(["--dernier", "--vers", dest("a")], "exports_indisponible");
      fs.rmSync(j.exports);
      fs.symlinkSync(j.config.storage.root, j.exports);
      await refus(["--dernier", "--vers", dest("a")], "exports_indisponible");
      fs.rmSync(j.exports);
      fs.symlinkSync(j.repertoire, j.exports);
      await refus(["--dernier", "--vers", dest("a")], "exports_indisponible");
      fs.rmSync(j.exports);
    } finally {
      if (!fs.existsSync(j.exports)) fs.renameSync(exportsBak, j.exports);
    }
    // Ordre 3, lexical (avant l'ordre 7).
    let r = await refus(["--seq", "999999", "--vers", path.join(dir, "ailleurs", "x")], "destination_hors_exports");
    expect(r.stderr).to.include(`la destination ${path.join(dir, "ailleurs", "x")} n'est pas sous le répertoire des exports ${j.exports}`);
    await refus(["--dernier", "--vers", `${j.exports}-bis/x`], "destination_hors_exports");
    await refus(["--dernier", "--vers", j.exports], "destination_hors_exports");
    // Ordre 3, chemin réel du parent : un lien symbolique qui sort du volume.
    const dehors = path.join(dir, "dehors");
    fs.mkdirSync(dehors);
    fs.symlinkSync(dehors, dest("lien"));
    await refus(["--dernier", "--vers", dest("lien", "d")], "destination_hors_exports");
    expect(fs.readdirSync(dehors)).to.deep.equal([]);
    // Ordre 4 (avant l'ordre 7).
    r = await refus(["--ticket", "apr-inconnu-2", "--vers", dest("absent", "d")], "parent_absent");
    expect(r.stderr).to.include(`le répertoire parent de ${dest("absent", "d")} n'existe pas`);
    expect(fs.existsSync(dest("absent"))).to.equal(false);
    fs.writeFileSync(dest("fichier"), "x");
    await refus(["--dernier", "--vers", dest("fichier", "d")], "parent_absent");
    // Ordre 5 (avant l'ordre 8) : fichier, lien (vers un répertoire vide du volume, sans le suivre), tube, prise.
    fs.writeFileSync(dest("existant"), "x");
    r = await refus(["--seq", String(j.seqs.echange3), "--vers", dest("existant")], "destination_existante");
    expect(r.stderr).to.include(`la destination ${dest("existant")} existe et n'est pas un répertoire`);
    fs.mkdirSync(dest("cible-vide"));
    fs.symlinkSync(dest("cible-vide"), dest("lien-vide"));
    await refus(["--dernier", "--vers", dest("lien-vide")], "destination_existante");
    expect(fs.readdirSync(dest("cible-vide"))).to.deep.equal([]);
    expect(spawnSync("mkfifo", [dest("tube")]).status).to.equal(0);
    await refus(["--dernier", "--vers", dest("tube")], "destination_existante");
    const prise = net.createServer();
    await new Promise((res) => prise.listen(dest("prise"), res));
    try {
      await refus(["--dernier", "--vers", dest("prise")], "destination_existante");
    } finally {
      await new Promise((res) => prise.close(res));
    }
    // Ordre 6 (avant l'ordre 9).
    fs.mkdirSync(dest("plein"));
    fs.writeFileSync(dest("plein", "f"), "x");
    r = await refus(["--ticket", j.tickets.sansJeu, "--vers", dest("plein")], "destination_non_vide");
    expect(r.stderr).to.include(`la destination ${dest("plein")} n'est pas vide : un dossier exporté n'est jamais remplacé`);
    expect(fs.readdirSync(dest("plein"))).to.deep.equal(["f"]);
    // Un lien qui reste dans le volume : chemin réel du parent sous le répertoire des exports, admis.
    fs.mkdirSync(dest("sous"));
    fs.symlinkSync(dest("sous"), dest("interne"));
    const ok = await reussite(["--dernier", "--vers", dest("interne", "d")]);
    expect(ok.ligne.data.destination).to.equal(dest("interne", "d"));
    expect(fs.existsSync(dest("sous", "d", "dossier.json"))).to.equal(true);
    // Aucune réécriture : le même export vers la même destination est refusé.
    await refus(["--dernier", "--vers", dest("interne", "d")], "destination_non_vide");
  });

  it("ordre 10, lecture_impossible (journal.json illisible : code d'erreur et fichier), et ordre 11, ecriture_impossible (destination devenue non vide avant le renommage, point d'arrêt d'essai) : le répertoire temporaire est supprimé, la destination inchangée", async function () {
    const journalJson = path.join(j.repertoire, "journal.json");
    fs.renameSync(journalJson, `${journalJson}.bak`);
    fs.mkdirSync(journalJson);
    try {
      const r = await refus(["--seq", String(j.seqs.decisionApprouve), "--vers", path.join(j.exports, "lecture")], "lecture_impossible");
      expect(r.ligne.data.detail).to.equal(`EISDIR ${journalJson}`);
      expect(r.ligne.data.seq).to.equal(j.seqs.decisionApprouve);
      expect(r.stderr).to.include(`lecture du journal impossible : EISDIR ${journalJson}`);
    } finally {
      fs.rmdirSync(journalJson);
      fs.renameSync(`${journalJson}.bak`, journalJson);
    }
    await demon.commande({ cmd: "point-arret", repertoire: arret });
    try {
      const destination = path.join(j.exports, "ecriture");
      const enCours = exporter(["--seq", String(j.seqs.decisionApprouve), "--vers", destination]);
      const atteint = await attendre(() => fs.readdirSync(arret).find((n) => n.startsWith("atteint-")), 30000, "point d'arrêt");
      const rid = atteint.slice("atteint-".length);
      const temporaire = fs.readFileSync(path.join(arret, atteint), "utf8");
      expect(path.basename(temporaire)).to.equal(`.noortrace-partiel-${rid}`);
      expect(path.dirname(temporaire)).to.equal(j.exports);
      expect(fs.statSync(temporaire).mode & 0o7777).to.equal(0o750);
      fs.mkdirSync(destination);
      fs.writeFileSync(path.join(destination, "intrus"), "x");
      fs.writeFileSync(path.join(arret, `reprendre-${rid}`), "");
      const r = await enCours;
      expect(r.code, r.stderr).to.equal(1);
      expect(r.ligne.data.raison).to.equal("ecriture_impossible");
      expect(r.ligne.data.detail).to.equal(`ENOTEMPTY ${destination}`);
      expect(r.stderr).to.equal(`noortrace-ctl dossier exporter : écriture impossible : ENOTEMPTY ${destination} ; la destination est inchangée\n`);
      expect(fs.existsSync(temporaire)).to.equal(false);
      expect(fs.readdirSync(destination)).to.deep.equal(["intrus"]);
      expect(ligneDe(r).request_id).to.equal(rid);
      demandes.push(rid);
    } finally {
      await demon.commande({ cmd: "point-arret", repertoire: null });
      for (const n of fs.readdirSync(arret)) fs.rmSync(path.join(arret, n));
    }
  });

  it("lien posé pendant l'écriture (point d'arrêt avant la seconde vérification) : le parent remplacé par un lien qui sort du volume → destination_hors_exports ; rien hors du volume, aucun reste, la destination absente", async function () {
    const parent = path.join(j.exports, "parent");
    fs.mkdirSync(parent);
    const dehors = path.join(dir, "dehors-pendant");
    fs.mkdirSync(dehors);
    await demon.commande({ cmd: "point-arret", repertoire: arret });
    try {
      const enCours = exporter(["--seq", String(j.seqs.decisionApprouve), "--vers", path.join(parent, "d")]);
      const atteint = await attendre(() => fs.readdirSync(arret).find((n) => n.startsWith("atteint-")), 30000, "point d'arrêt");
      const rid = atteint.slice("atteint-".length);
      fs.renameSync(parent, `${parent}-deplace`);
      fs.symlinkSync(dehors, parent);
      fs.writeFileSync(path.join(arret, `reprendre-${rid}`), "");
      const r = await enCours;
      expect(r.code, r.stderr).to.equal(1);
      expect(r.ligne.data.raison).to.equal("destination_hors_exports");
      expect(r.ligne.data.seq).to.equal(j.seqs.decisionApprouve);
      expect(fs.readdirSync(dehors)).to.deep.equal([]);
      expect(fs.readdirSync(`${parent}-deplace`)).to.deep.equal([]);
      expect(partiels(j.exports)).to.deep.equal([]);
      demandes.push(rid);
    } finally {
      await demon.commande({ cmd: "point-arret", repertoire: null });
      for (const n of fs.readdirSync(arret)) fs.rmSync(path.join(arret, n));
    }
  });

  it("EX-15.15 (révision 0.9) : erreur imprévue pendant l'écriture (point d'essai qui lève) : ecriture_impossible, détail erreur_interne et nom de l'erreur, jamais son message ; code 1 ; répertoire temporaire supprimé, destination absente", async function () {
    await demon.commande({ cmd: "panne-export" });
    try {
      const destination = path.join(j.exports, "panne");
      const r = await refus(["--seq", String(j.seqs.decisionApprouve), "--vers", destination], "ecriture_impossible");
      expect(r.ligne.data.detail).to.equal("erreur_interne TypeError");
      expect(r.ligne.data.seq).to.equal(j.seqs.decisionApprouve);
      expect(r.stderr).to.equal("noortrace-ctl dossier exporter : écriture impossible : erreur_interne TypeError ; la destination est inchangée\n");
      expect(fs.existsSync(destination)).to.equal(false);
    } finally {
      await demon.commande({ cmd: "panne-export", actif: false });
    }
  });

  it("EX-15.13 point 2 (révision 0.9) : synchronisation du parent en échec après le renommage : ecriture_impossible, détail synchronisation_parent <code> <parent>, message « le dossier est en place … » ; le dossier complet reste sous son nom ; aucune ligne dossier_exported", async function () {
    await demon.commande({ cmd: "panne-synchronisation" });
    const destination = path.join(j.exports, "synchronisation");
    try {
      const r = await refus(["--seq", String(j.seqs.decisionApprouve), "--vers", destination], "ecriture_impossible");
      expect(r.ligne.data.detail).to.equal(`synchronisation_parent EIO ${j.exports}`);
      expect(r.stderr).to.equal(`noortrace-ctl dossier exporter : écriture impossible : synchronisation_parent EIO ${j.exports} ; le dossier est en place sous ${destination}, mais sa durabilité n'est pas assurée : l'exporter de nouveau vers une autre destination\n`);
      expect(fs.statSync(destination).mode & 0o7777).to.equal(0o750);
      expect(fs.readdirSync(destination)).to.include("dossier.json");
      for (const n of fs.readdirSync(destination)) if (fs.statSync(path.join(destination, n)).isFile()) expect(fs.statSync(path.join(destination, n)).mode & 0o7777, n).to.equal(0o640);
      const rid = ligneDe(r).request_id;
      expect(lignesJournal(j.journal).filter((l) => l.request_id === rid).map((l) => l.event)).to.deep.equal(["dossier_export_refused"]);
    } finally {
      await demon.commande({ cmd: "panne-synchronisation", actif: false });
    }
    // jamais remplacé : un nouvel export vers le même nom est refusé
    await refus(["--seq", String(j.seqs.decisionApprouve), "--vers", destination], "destination_non_vide");
  });

  it("étape 6 (relecture) : une destination au nom réservé .noortrace-partiel-… est refusée, par la commande (code 2, aucune demande) comme par le démon (demande_invalide, member destination) ; rien n'est écrit", async function () {
    const rid = "ab".repeat(16);
    const reserve = path.join(j.exports, `.noortrace-partiel-${rid}`);
    const n0 = lignesJournal(j.journal).length;
    const c = await exporter(["--seq", String(j.seqs.decisionApprouve), "--vers", reserve]);
    expect(c.code, c.stderr).to.equal(2);
    expect(c.stdout).to.equal("");
    expect(c.stderr).to.contain(".noortrace-partiel-");
    expect(lignesJournal(j.journal).length).to.equal(n0);
    const { murale } = await demon.commande({ cmd: "demarrage" });
    deposerEtSignaler(j.journal, demon.pid, demandeDossier({ selection: "seq", seq: j.seqs.decisionApprouve, destination: reserve, request_id: rid, at: N.ecrireHorodatage(murale) }));
    const l = await attendre(() => lignesJournal(j.journal).slice(n0).find((x) => x.request_id === rid), 30000, "refus de la destination réservée");
    expect(l.event).to.equal("dossier_export_refused");
    expect(l.data).to.deep.include({ raison: "demande_invalide", member: "destination", destination: null });
    expect(fs.existsSync(reserve)).to.equal(false);
    demandes.push(rid);
  });

  it("ordre 1, bail_non_detenu, sur une instance passive ; demande_invalide et demande_perimee précèdent tous les refus ; deux démons de la même configuration : code 2 (« plusieurs démons ; désigner la configuration (--configuration) »)", async function () {
    const passif = new DemonEssai({ cheminConfig: j.cheminConfig, env: j.env, journal: j.journal, horloge: (j.P + 3600 + 700) * 1000 });
    const avant = lignesJournal(j.journal).length;
    const demarre = passif.demarrer();
    await attendre(() => lignesJournal(j.journal).slice(avant).some((l) => l.event === "lease_standby"), 60000, "instance passive (lease_standby)");
    await demarre.catch(() => {});
    try {
      const r = await exporter(["--dernier", "--vers", path.join(j.exports, "passif")]);
      expect(r.code).to.equal(2);
      expect(r.stderr).to.equal("noortrace-ctl dossier exporter : plusieurs démons ; désigner la configuration (--configuration)\n");
      expect(r.stdout).to.equal("");
      const at = N.ecrireHorodatage(Date.now());
      const d = demandeDossier({ selection: "dernier", destination: "/hors/du/volume", at });
      const n0 = lignesJournal(j.journal).length;
      deposerEtSignaler(j.journal, passif.pid, d);
      const l = await attendre(() => lignesJournal(j.journal).slice(n0).find((x) => x.request_id === d.request_id), 15000, "réponse de l'instance passive");
      expect(l.data.raison).to.equal("bail_non_detenu");
      expect(messageRefusExport(l.data)).to.equal("le démon ne détient pas le bail (instance passive) : exporter depuis l'instance active");
      const inval = demandeDossier({ selection: "dernier", destination: "/hors", at, pid: 0 });
      deposerEtSignaler(j.journal, passif.pid, inval);
      const l2 = await attendre(() => lignesJournal(j.journal).slice(n0).find((x) => x.request_id === inval.request_id), 15000, "demande invalide");
      expect(l2.data).to.include({ raison: "demande_invalide", member: "pid" });
      const perime = demandeDossier({ selection: "dernier", destination: "/hors", at: N.ecrireHorodatage((j.P + 3600) * 1000) });
      deposerEtSignaler(j.journal, passif.pid, perime);
      const l3 = await attendre(() => lignesJournal(j.journal).slice(n0).find((x) => x.request_id === perime.request_id), 15000, "demande périmée");
      expect(l3.data.raison).to.equal("demande_perimee");
      expect(messageRefusExport(l3.data)).to.equal(`demande périmée, écrite à ${perime.at} : lue plus de 600 s après, ou avant le démarrage du démon ; rien n'est exporté`);
    } finally {
      await passif.arreter();
    }
  });

  it("commande : erreurs d'usage code 2 sans demande ni signal (--option=valeur, option répétée, deux désignations, --vers manquant, valeurs hors domaine) ; aucun démon : code 4 ; fichier occupé : code 4 dans le délai unique, fichier intact ; signal impossible : demande retirée, code 4", async function () {
    const f = `${j.journal}.rotation-urgence`;
    const n0 = lignesJournal(j.journal).length;
    const usages = [
      ["--seq=1", "--vers", "/x"], ["--seq", "1", "--seq", "2", "--vers", "/x"], ["--seq", "1", "--dernier", "--vers", "/x"], ["--dernier"], ["--seq", "01", "--vers", "/x"],
      ["--seq", "9007199254740992", "--vers", "/x"], ["--ticket", "APR-1", "--vers", "/x"], ["--dernier", "--vers", ".."], ["--dernier", "--vers", ""], ["--dernier", "--vers", "/x", "--delai-ms", "86400001"],
      ["--dernier", "--vers", "/x", "--delai-ms", "-1"], ["--dernier", "--vers", "/x", "--inconnue", "1"], ["--dernier", "--vers"], ["--dernier", "--vers", "/x", "--dernier"],
    ];
    for (const u of usages) {
      const r = await ctl(["dossier", "exporter", ...u, "--configuration", j.cheminConfig], { env: j.env });
      expect(r.code, u.join(" ")).to.equal(2);
      expect(r.stdout).to.equal("");
      expect(r.stderr.startsWith("noortrace-ctl dossier exporter : ")).to.equal(true);
    }
    expect((await ctl(["dossier", "importer", "--dernier", "--vers", "/x"], { env: j.env })).code).to.equal(2);
    expect(fs.existsSync(f)).to.equal(false);
    expect(lignesJournal(j.journal).slice(n0).filter((l) => l.event.startsWith("dossier_") || l.event === "ctl_request_refused")).to.deep.equal([]);
    // Aucun démon pour cette configuration.
    const autre = path.join(dir, "autre-configuration.json");
    fs.copyFileSync(j.cheminConfig, autre);
    const r4 = await ctl(["dossier", "exporter", "--dernier", "--vers", path.join(j.exports, "z"), "--configuration", autre], { env: j.env });
    expect(r4.code).to.equal(4);
    expect(r4.stderr).to.include("aucun démon noortrace");
    // Fichier occupé : un seul délai, compté depuis l'écriture de la demande.
    fs.writeFileSync(f, "{\"demande\":\"occupant\"}\n", { mode: 0o600 });
    try {
      const t0 = Date.now();
      const r = await exporter(["--dernier", "--vers", path.join(j.exports, "occupe")], { delai: 600 });
      const duree = Date.now() - t0;
      expect(r.code).to.equal(4);
      expect(r.stderr).to.equal(`noortrace-ctl dossier exporter : fichier de demande occupé : ${f} ; une autre commande est en cours, ou une demande n'a pas été lue (à supprimer si aucune commande noortrace-ctl ne tourne)\n`);
      expect(r.ligne).to.deep.equal({ pid: demon.pid, configuration: fs.realpathSync(j.cheminConfig), event: null, data: null });
      expect(duree).to.be.within(550, 5000);
      expect(fs.readFileSync(f, "utf8")).to.equal("{\"demande\":\"occupant\"}\n");
      const r0 = await exporter(["--dernier", "--vers", path.join(j.exports, "occupe")], { delai: 0 });
      expect(r0.code).to.equal(4);
    } finally {
      fs.rmSync(f, { force: true });
    }
    // Signal impossible : démon trouvé (racine /proc d'essai), processus absent ; la demande est retirée.
    const proc = path.join(dir, "proc");
    const pidAbsent = 4194303;
    fs.mkdirSync(path.join(proc, String(pidAbsent)), { recursive: true });
    fs.writeFileSync(path.join(proc, String(pidAbsent), "cmdline"), ["node", "/bin/noortrace", "--config", j.cheminConfig, ""].join("\0"));
    fs.symlinkSync(dir, path.join(proc, String(pidAbsent), "cwd"));
    let out = "";
    let err = "";
    const code = await principalCtlDemon(["dossier", "exporter", "--dernier", "--vers", path.join(j.exports, "signal"), "--configuration", j.cheminConfig], { stdout: { write: (s) => (out += s) }, stderr: { write: (s) => (err += s) }, racineProc: proc });
    expect(code).to.equal(4);
    expect(err).to.match(/^noortrace-ctl dossier exporter : signal impossible vers le démon 4194303 \(ESRCH\) ; demande retirée\n$/);
    expect(JSON.parse(out)).to.deep.equal({ pid: pidAbsent, configuration: fs.realpathSync(j.cheminConfig), event: null, data: null });
    expect(fs.existsSync(f)).to.equal(false);
  });

  it("le journal d'exploitation tourne pendant l'attente : la réponse est lue dans le fichier tourné (EX-17.4) ; SuiviJournal ignore les fichiers tournés présents à la note", function () {
    const d = path.join(dir, "suivi");
    fs.mkdirSync(d);
    const f = path.join(d, "exploitation.ndjson");
    fs.writeFileSync(`${f}.1`, `${JSON.stringify({ event: "ancien", request_id: "r" })}\n`);
    fs.writeFileSync(f, `${JSON.stringify({ event: "avant" })}\n`);
    const s = new SuiviJournal(f);
    expect(s.lire()).to.deep.equal([]);
    fs.appendFileSync(f, `${JSON.stringify({ event: "a" })}\n{"event":"incom`);
    expect(s.lire().map((l) => l.event)).to.deep.equal(["a"]);
    fs.appendFileSync(f, "plete\"}\n");
    // Rotation : <f>.1 → <f>.2, <f> → <f>.1, nouveau <f>.
    fs.renameSync(`${f}.1`, `${f}.2`);
    fs.renameSync(f, `${f}.1`);
    fs.writeFileSync(f, `${JSON.stringify({ event: "b" })}\n`);
    expect(s.lire().map((l) => l.event)).to.deep.equal(["incomplete", "b"]);
    expect(s.lire()).to.deep.equal([]);
  });

  it("modes et groupe des lecteurs : répertoire des exports en 2750 d'un groupe des lecteurs, le dossier en 0750 et ses fichiers en 0640 prennent ce groupe par le bit setgid, quel que soit le masque de création du démon (superutilisateur ; en attente sinon)", async function () {
    if (!ROOT) return enAttente(this, "changement de groupe du répertoire des exports : superutilisateur requis");
    fs.chownSync(j.exports, 0, GROUPE_LECTEURS);
    fs.chmodSync(j.exports, 0o2750);
    try {
      const destination = path.join(j.exports, "groupe");
      await reussite(["--seq", String(j.seqs.decisionApprouve), "--vers", destination]);
      const st = fs.statSync(destination);
      expect(st.gid).to.equal(GROUPE_LECTEURS);
      expect(st.mode & 0o777).to.equal(0o750);
      for (const n of fs.readdirSync(destination)) {
        const s = fs.statSync(path.join(destination, n));
        expect(s.gid, n).to.equal(GROUPE_LECTEURS);
        expect(s.mode & 0o7777, n).to.equal(0o640);
      }
    } finally {
      fs.chmodSync(j.exports, 0o750);
      fs.chownSync(j.exports, 0, 0);
    }
  });

  it("export interrompu par un arrêt brutal avant le renommage : aucun dossier sous le nom demandé, la commande rend 4 (« pas de réponse dans le délai ; lire … de request_id … ») ; au redémarrage, le reste .noortrace-partiel-<request_id> est supprimé à l'acquisition du bail (dossier_export_partial_removed)", async function () {
    const destination = path.join(j.exports, "interrompu");
    await demon.commande({ cmd: "point-arret", repertoire: arret });
    const { murale } = await demon.commande({ cmd: "demarrage" });
    const enCours = exporter(["--seq", String(j.seqs.decisionApprouve), "--vers", destination], { delai: 6000 });
    const atteint = await attendre(() => fs.readdirSync(arret).find((n) => n.startsWith("atteint-")), 30000, "point d'arrêt");
    const rid = atteint.slice("atteint-".length);
    const temporaire = fs.readFileSync(path.join(arret, atteint), "utf8");
    expect(fs.readdirSync(temporaire)).to.include("dossier.json");
    await demon.tuer();
    const r = await enCours;
    expect(r.code).to.equal(4);
    expect(r.ligne).to.include({ event: null, data: null });
    expect(r.stderr).to.equal(`noortrace-ctl dossier exporter : pas de réponse dans le délai ; lire dossier_exported ou dossier_export_refused de request_id ${rid} au journal d'exploitation\n`);
    expect(fs.existsSync(destination)).to.equal(false);
    expect(fs.existsSync(temporaire)).to.equal(true);
    // Un reste qui n'a pas la forme exacte (31 chiffres) n'est pas touché.
    const autre = path.join(j.exports, `.noortrace-partiel-${"0".repeat(31)}`);
    fs.mkdirSync(autre);
    for (const n of fs.readdirSync(arret)) fs.rmSync(path.join(arret, n));
    const n0 = lignesJournal(j.journal).length;
    demon = new DemonEssai({ cheminConfig: j.cheminConfig, env: j.env, journal: j.journal, horloge: murale + 30000 });
    await demon.demarrer();
    const l = lignesJournal(j.journal).slice(n0).filter((x) => x.event === "dossier_export_partial_removed");
    expect(l).to.have.lengthOf(1);
    expect(l[0]).to.include({ level: "warning", component: "noyau", seq: null, request_id: null });
    expect(l[0].data).to.deep.equal({ path: temporaire });
    const ordre = lignesJournal(j.journal).slice(n0).map((x) => x.event);
    expect(ordre.indexOf("dossier_export_partial_removed")).to.be.above(ordre.indexOf("lease_acquired"));
    expect(fs.existsSync(temporaire)).to.equal(false);
    expect(fs.existsSync(autre)).to.equal(true);
    fs.rmdirSync(autre);
    expect(lignesJournal(j.journal).filter((x) => x.request_id === rid)).to.deep.equal([]);
    // Le démon relancé exporte de nouveau.
    await reussite(["--seq", String(j.seqs.decisionApprouve), "--vers", destination]);
  });

  it("une ligne de réponse par demande, avec son request_id (EX-15.10 pas 6, EX-15.14) ; les lignes de réponse ne portent aucune pièce", function () {
    const reponses = lignesJournal(j.journal).filter((l) => l.event === "dossier_exported" || l.event === "dossier_export_refused");
    const parId = new Map();
    for (const l of reponses) parId.set(l.request_id, (parId.get(l.request_id) ?? 0) + 1);
    for (const rid of new Set(demandes)) expect(parId.get(rid), rid).to.equal(1);
    for (const [rid, n] of parId) if (rid !== null) expect(n, rid).to.equal(1);
    expect(demandes.length).to.be.at.least(25);
    for (const l of reponses) expect(JSON.stringify(l)).to.not.match(/requete [0-9]|reponse [0-9]|2026-[A-G]"/);
  });
});

describe("export en cours de processus (exporterDemande) : aucune période close ; en production, droits du répertoire des exports et groupe du parent (CT-2 EX-15.12 ordre 2, EX-15.13 point 2, CT-7 EX-3.16)", function () {
  this.timeout(120000);
  let dir;
  let coeur;
  let config;
  let horloge;
  const RID = () => N.octetsVersHex(N.sha256(N.utf8(String(Math.random())))).slice(2, 34);
  const demande = (destination, o = {}) => ({ demande: "dossier", selection: "dernier", seq: null, ticket: null, destination, request_id: RID(), pid: process.pid, at: N.ecrireHorodatage(horloge.murale()), ...o });

  before(async function () {
    dir = repertoireTemporaire("noortrace-export-prod-");
    const x = configurationDev(dir);
    x.config.exports_dir = path.join(dir, "exports");
    fs.mkdirSync(x.config.exports_dir, { mode: 0o750 });
    const octets = N.utf8(JSON.stringify(x.config));
    config = validerConfiguration(octets).config;
    const s = resoudreSecrets(config, { env: x.env });
    horloge = new HorlogeReglable(Date.UTC(2026, 10, 10, 10, 0, 5));
    coeur = await Coeur.demarrer({ config, secrets: s.secrets, horloge });
  });

  after(async function () {
    await coeur?.arreter();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("--dernier sans période close : aucune_periode_close (ordre 7), message d'EX-15.12", async function () {
    const l = await exporterDemande(coeur, demande(path.join(config.exports_dir, "d")));
    expect(l).to.include({ event: "dossier_export_refused", component: "noyau", seq: null });
    expect(l.data).to.include({ raison: "aucune_periode_close", selection: "dernier", seq: null, exports_dir: config.exports_dir });
    expect(messageRefusExport(l.data)).to.equal("aucune période close dans le journal");
  });

  it("production (superutilisateur ; en attente sinon) : répertoire conforme (propriétaire du démon, 2750, groupe des lecteurs) exporté ; autre propriétaire, droit aux autres, écriture du groupe, sans bit setgid → exports_indisponible détail droits ; parent d'un autre groupe ou sans bit setgid → ecriture_impossible détail groupe, aucun reste", async function () {
    if (!ROOT) return enAttente(this, "propriétaire et groupe du répertoire des exports : superutilisateur requis");
    const pieceA = pieceJson({ n: 1 });
    await coeur.ecrirePiece(pieceA);
    await coeur.scellerEchange({ delegation: { launched_by: "agent-sinistres", on_behalf_of: null, scope: "s", run_id: null }, code: { model: "m", prompt_version: null }, intent: null, requete: pieceA.reference, reponse: pieceA.reference, duration_ms: 1, is_error: false });
    horloge.aller(Date.UTC(2026, 10, 10, 11, 0, 1));
    await coeur.tic();
    const ex = config.exports_dir;
    coeur.config.recorder.environment = "production";
    try {
      fs.chownSync(ex, 0, GROUPE_LECTEURS);
      fs.chmodSync(ex, 0o2750);
      const ok = await exporterDemande(coeur, demande(path.join(ex, "conforme")));
      expect(ok.event, JSON.stringify(ok.data)).to.equal("dossier_exported");
      expect(fs.statSync(path.join(ex, "conforme")).gid).to.equal(GROUPE_LECTEURS);
      const droits = async (preparer) => {
        preparer();
        const l = await exporterDemande(coeur, demande(path.join(ex, "refus")));
        expect(l.data).to.include({ raison: "exports_indisponible", detail: "droits" });
        fs.chownSync(ex, 0, GROUPE_LECTEURS);
        fs.chmodSync(ex, 0o2750);
      };
      await droits(() => fs.chownSync(ex, 65534, GROUPE_LECTEURS));
      await droits(() => fs.chmodSync(ex, 0o2754));
      await droits(() => fs.chmodSync(ex, 0o2751));
      await droits(() => fs.chmodSync(ex, 0o2770));
      await droits(() => fs.chmodSync(ex, 0o0750));
      expect(fs.existsSync(path.join(ex, "refus"))).to.equal(false);
      // Parent d'un autre groupe (bit setgid hérité, groupe changé) ; parent sans bit setgid.
      const autreGroupe = path.join(ex, "autre-groupe");
      fs.mkdirSync(autreGroupe);
      fs.chownSync(autreGroupe, 0, GROUPE_AUTRE);
      const sansSetgid = path.join(ex, "sans-setgid");
      fs.mkdirSync(sansSetgid);
      fs.chmodSync(sansSetgid, 0o750);
      expect(fs.statSync(sansSetgid).mode & 0o2000).to.equal(0);
      for (const parent of [autreGroupe, sansSetgid]) {
        const l = await exporterDemande(coeur, demande(path.join(parent, "d")));
        expect(l.data, parent).to.include({ raison: "ecriture_impossible", detail: "groupe" });
        expect(messageRefusExport(l.data)).to.equal("écriture impossible : groupe ; la destination est inchangée");
        expect(fs.readdirSync(parent)).to.deep.equal([]);
      }
      // Hors production, les droits ne sont pas vérifiés.
      coeur.config.recorder.environment = "developpement";
      fs.chmodSync(ex, 0o0755);
      expect((await exporterDemande(coeur, demande(path.join(ex, "dev")))).event).to.equal("dossier_exported");
    } finally {
      coeur.config.recorder.environment = "developpement";
      fs.chmodSync(ex, 0o750);
      fs.chownSync(ex, 0, 0);
    }
  });

  it("contrôle des chemins réels : cheminReelSous admet la racine elle-même et ce qui est dessous, jamais un préfixe sans barre oblique", function () {
    expect(cheminReelSous("/a/b", "/a/b")).to.equal(true);
    expect(cheminReelSous("/a/b/c", "/a/b")).to.equal(true);
    expect(cheminReelSous("/a/bc", "/a/b")).to.equal(false);
    expect(cheminReelSous("/a", "/a/b")).to.equal(false);
    expect(cheminReelSous("/x", "/")).to.equal(true);
  });
});

describe("TA-99 (MN-99) : mutant du démon qui ne vérifie plus le chemin réel du parent", function () {
  this.timeout(300000);
  let dir;
  let j;
  let mutant;
  let demon;

  before(async function () {
    dir = repertoireTemporaire("noortrace-ta99-");
    j = await construireJournal(dir);
    // Mutant : copie de paquets/enregistreur sous NOORTRACE_TMP, node_modules du dépôt par un lien.
    mutant = fs.mkdtempSync(path.join(TMP, "noortrace-mutant-ta99-"));
    const paquet = path.join(mutant, "paquets", "enregistreur");
    fs.mkdirSync(paquet, { recursive: true });
    for (const d of ["src", "bin", "schemas"]) fs.cpSync(path.join(PAQUET, d), path.join(paquet, d), { recursive: true });
    fs.copyFileSync(path.join(PAQUET, "package.json"), path.join(paquet, "package.json"));
    fs.symlinkSync(path.join(RACINE, "node_modules"), path.join(mutant, "node_modules"));
    const f = path.join(paquet, "src", "export-dossier.mjs");
    const texte = fs.readFileSync(f, "utf8");
    const ancien = "return reel === racine || reel.startsWith(racine === \"/\" ? \"/\" : `${racine}/`);";
    expect(texte.split(ancien).length - 1, "le contrôle des chemins réels, une fois").to.equal(1);
    fs.writeFileSync(f, texte.replace(ancien, "return true;"));
  });

  after(async function () {
    await demon?.arreter().catch(() => {});
    await j?.fermer();
    if (mutant) fs.rmSync(mutant, { recursive: true, force: true });
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("TA-99 : destination par un lien symbolique qui sort du répertoire des exports : sans mutant, destination_hors_exports et aucun fichier hors du volume ; le mutant écrit le dossier hors du volume (tué)", async function () {
    const dehors = path.join(dir, "dehors");
    fs.mkdirSync(dehors);
    fs.symlinkSync(dehors, path.join(j.exports, "lien"));
    const args = (n) => ["dossier", "exporter", "--seq", String(j.seqs.decisionApprouve), "--vers", path.join(j.exports, "lien", n), "--configuration", j.cheminConfig];
    // Démon du dépôt, horloge du système.
    demon = new DemonEssai({ cheminConfig: j.cheminConfig, env: j.env, journal: j.journal });
    await demon.demarrer();
    const r = await ctl(args("reference"), { env: j.env });
    await demon.arreter();
    expect(r.code, r.stderr).to.equal(1);
    expect(r.ligne.data.raison).to.equal("destination_hors_exports");
    expect(fs.readdirSync(dehors)).to.deep.equal([]);
    // Démon du mutant, même journal.
    demon = new DemonEssai({ cheminConfig: j.cheminConfig, env: j.env, journal: j.journal, paquet: path.join(mutant, "paquets", "enregistreur") });
    await demon.demarrer();
    const m = await ctl(args("mutant"), { env: j.env });
    await demon.arreter();
    // L'oracle de TA-99 (aucun fichier hors du volume, refus destination_hors_exports) échoue sur le mutant : tué.
    expect(m.code, m.stderr).to.equal(0);
    expect(m.ligne.event).to.equal("dossier_exported");
    expect(fs.existsSync(path.join(dehors, "mutant", "dossier.json")), "dossier écrit hors du volume par le mutant").to.equal(true);
  });
});
