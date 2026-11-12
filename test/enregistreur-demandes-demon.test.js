// Demandes adressées au démon par le fichier de demande et SIGURG (CT-2
// révision 0.8, EX-15.10 pas 5 ; EX-15.14 ; table de §22, ligne
// `cli.mjs`) : le démon exécute l'action que nomme `demande`, et elle seule ;
// il refuse sans rien exécuter, dans cet ordre, une demande illisible
// (`demande_illisible`), inconnue (`demande_inconnue`, valeur tronquée à 64
// caractères), une demande `dossier` hors de son domaine (`demande_invalide`,
// `member` = premier membre fautif) et une demande périmée (`demande_perimee` :
// 600 s, ou antérieure au démarrage ; `at` absent ou hors forme pour
// `rotation-urgence` et `ancrage`). Un SIGURG sans fichier donne
// `key_rotation_emergency_ignored` ; un fichier resté au démarrage est
// supprimé sans être exécuté (`ctl_request_refused`, `demande_perimee`). Les
// lignes `ctl_request_refused` et `dossier_export_refused` sont écrites avec
// `supervision.ops_log.level` `error`.
//
// Révision 0.9 (EX-15.15) : une demande que le démon ne peut pas supprimer
// n'est jamais exécutée (`ctl_request_not_removed`) ; une erreur imprévue
// d'un export donne sa ligne de réponse (`dossier_export_refused`,
// `ecriture_impossible`, détail `erreur_interne`, répertoire temporaire
// supprimé), d'une autre demande `ctl_request_failed` (`demande`, `detail`),
// qui porte le `request_id` de la demande quand il est lisible : la commande
// la reconnaît et rend le code 1 sans attendre la fin de son délai.
// Étape 6 (relecture) : un composant au nom réservé `.noortrace-partiel-…`
// n'est pas une destination.
//
// Défaut corrigé (étape 6) : le démon faisait tourner la clé de
// l'enregistreur pour toute demande qui n'était pas `ancrage` (une demande
// `dossier`, illisible ou inconnue comprise). L'essai « aucune demande n'est
// prise pour une autre action » le reproduit sur le démon réel.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { ecrireHorodatage } from "@noortrace/noyau";
import { lireEvenements } from "@noortrace/enregistreur";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import {
  lireDemande, membreFautif, normaliserVers, destinationValide, texteSeqValide, texteDelaiValide, ticketValide, tronquer64,
  requestIdLisible, PEREMPTION_MS, MEMBRES_DEMANDE_DOSSIER,
} from "../paquets/enregistreur/src/demandes-demon.mjs";
import { traiterDemande } from "../paquets/enregistreur/src/cli.mjs";
import { configurationDev } from "./fixtures/enregistreur-coeur/outils.mjs";
import { DemonEssai, ctl, repertoireTemporaire, attendre, pause, lignesJournal, demandeDossier, deposerEtSignaler } from "./fixtures/enregistreur-export/outils.mjs";

const T = Date.UTC(2026, 10, 11, 9, 0, 0);
const AT = ecrireHorodatage(T);
const EXPORTS = "/var/lib/noortrace-exports";
const RID = "0123456789abcdef0123456789abcdef";
const octets = (x) => new TextEncoder().encode(typeof x === "string" ? x : JSON.stringify(x));
const lire = (x, o = {}) => lireDemande(x === null ? null : octets(x), { maintenant: T, demarrage: T - 3600000, exports_dir: EXPORTS, ...o });
const dossier = (extra = {}) => ({ demande: "dossier", selection: "seq", seq: 7, ticket: null, destination: `${EXPORTS}/d`, request_id: RID, pid: 4242, at: AT, ...extra });

describe("demandes du démon (CT-2 EX-15.10 pas 5) : lecture et refus, sans rien exécuter", function () {
  it("demande illisible : pas un objet JSON (texte, tableau, null, nombre, UTF-8 invalide, clé en double, fichier non lu) → ctl_request_refused demande_illisible, demande et at null", function () {
    for (const x of ["pas du json", "[1,2]", "null", "42", "\"dossier\"", "{\"demande\":\"rotation-urgence\",\"demande\":\"dossier\"}", "{"]) {
      const r = lire(x);
      expect(r.refus, x).to.deep.equal({ event: "ctl_request_refused", component: "noyau", seq: null, request_id: null, data: { raison: "demande_illisible", demande: null, at: null } });
    }
    expect(lireDemande(new Uint8Array([0x7b, 0xff, 0x7d]), { maintenant: T, demarrage: 0, exports_dir: EXPORTS }).refus.data.raison).to.equal("demande_illisible");
    expect(lire(null).refus.data.raison).to.equal("demande_illisible");
  });

  it("demande inconnue : toute valeur hors des trois (absente, autre chaîne, non-chaîne, casse différente) → ctl_request_refused demande_inconnue, valeur tronquée à 64 caractères (null si ce n'est pas une chaîne), at repris s'il est un horodatage", function () {
    const longue = "é".repeat(100);
    expect(lire({ demande: longue, at: AT }).refus).to.deep.equal({ event: "ctl_request_refused", component: "noyau", seq: null, request_id: null, data: { raison: "demande_inconnue", demande: "é".repeat(64), at: AT } });
    expect(lire({ demande: "Dossier", at: AT }).refus.data).to.deep.equal({ raison: "demande_inconnue", demande: "Dossier", at: AT });
    expect(lire({ demande: 42, at: "hier" }).refus.data).to.deep.equal({ raison: "demande_inconnue", demande: null, at: null });
    expect(lire({ at: AT }).refus.data).to.deep.equal({ raison: "demande_inconnue", demande: null, at: AT });
    expect(lire({ demande: "cle", at: AT }).refus.data.raison).to.equal("demande_inconnue");
    expect(tronquer64("a".repeat(64))).to.equal("a".repeat(64));
    // Un caractère hors du plan de base compte pour un.
    expect(tronquer64("😀".repeat(70))).to.equal("😀".repeat(64));
  });

  it("demande dossier hors de son domaine : member = premier membre fautif dans l'ordre du pas 3 (un cas par membre, absent puis hors domaine), puis les autres membres par octets croissants ; membres de data nuls quand hors domaine", function () {
    const casParMembre = {
      selection: [undefined, "tout", null],
      seq: [undefined, 0, -1, 1.5, "7", Number.MAX_SAFE_INTEGER + 1, null],
      ticket: [undefined, "apr-x"],
      destination: [undefined, "relatif/d", `${EXPORTS}//d`, `${EXPORTS}/d/`, `${EXPORTS}/./d`, `${EXPORTS}/../d`, "/", `${EXPORTS}/${"a".repeat(256)}`, `/${"a/".repeat(2048)}b`, `${EXPORTS}/d\u0000`, 7],
      request_id: [undefined, RID.toUpperCase(), RID.slice(1), 7],
      pid: [undefined, 0, 4194305, "4242", 1.5],
      at: [undefined, "2026-02-30T09:00:00.000Z", "2026-11-11T09:00:00Z", 1],
    };
    for (const [membre, valeurs] of Object.entries(casParMembre)) {
      for (const v of valeurs) {
        const o = dossier();
        if (v === undefined) delete o[membre];
        else o[membre] = v;
        const r = lire(o);
        expect(r.refus?.event, `${membre}=${String(v)}`).to.equal("dossier_export_refused");
        expect(r.refus.data.raison).to.equal("demande_invalide");
        expect(r.refus.data.member, `${membre}=${String(v)}`).to.equal(membre);
        expect(r.refus.request_id).to.equal(membre === "request_id" ? null : RID);
      }
    }
    // `seq` nul hors de --seq ; `ticket` nul hors de --ticket.
    expect(lire(dossier({ selection: "dernier" })).refus.data.member).to.equal("seq");
    expect(lire(dossier({ selection: "ticket", seq: null, ticket: null })).refus.data.member).to.equal("ticket");
    expect(lire(dossier({ ticket: "apr-1" })).refus.data.member).to.equal("ticket");
    expect(lire(dossier({ selection: "ticket", seq: null, ticket: "apr-" })).refus.data.member).to.equal("ticket");
    expect(lire(dossier({ selection: "ticket", seq: null, ticket: `apr-${"a".repeat(125)}` })).refus.data.member).to.equal("ticket");
    expect(lire(dossier({ selection: "ticket", seq: null, ticket: "apr-A1" })).refus.data.member).to.equal("ticket");
    // Plusieurs fautes : la première dans l'ordre du pas 3.
    expect(membreFautif(dossier({ pid: 0, selection: "x", at: "x" }))).to.equal("selection");
    // Membres de plus : par ordre croissant de leurs octets ("Z" 0x5a < "a" 0x61 < "é" 0xc3).
    expect(lire(dossier({ "é": 1, a: 1, Z: 1 })).refus.data.member).to.equal("Z");
    expect(membreFautif(dossier({ "é": 1, a: 1 }))).to.equal("a");
    // Un membre du pas 3 fautif passe avant un membre de plus.
    expect(membreFautif(dossier({ A: 1, at: "x" }))).to.equal("at");
    // data : chaque membre repris de la demande vaut null quand il manque ou sort de son domaine.
    const r = lire(dossier({ selection: "x", destination: "rel", at: AT }));
    expect(r.refus.data).to.deep.equal({ raison: "demande_invalide", selection: null, seq: null, ticket: null, destination: null, exports_dir: EXPORTS, period_start: null, decision: null, member: "selection", at: null, detail: null });
    const r2 = lire(dossier({ pid: 0 }));
    expect(r2.refus.data).to.deep.equal({ raison: "demande_invalide", selection: "seq", seq: 7, ticket: null, destination: `${EXPORTS}/d`, exports_dir: EXPORTS, period_start: null, decision: null, member: "pid", at: null, detail: null });
    expect(MEMBRES_DEMANDE_DOSSIER).to.deep.equal(["demande", "selection", "seq", "ticket", "destination", "request_id", "pid", "at"]);
  });

  it("demande périmée, quelle que soit `demande` : at plus de 600 s avant la lecture (600 s admises), ou avant le démarrage ; at absent ou hors forme pour rotation-urgence et ancrage ; dossier → dossier_export_refused avec at et request_id ; sinon ctl_request_refused", function () {
    expect(PEREMPTION_MS).to.equal(600000);
    const dem = T - 3600000;
    for (const demande of ["rotation-urgence", "ancrage"]) {
      const base = demande === "ancrage" ? { demande, commande: "etat", id: null, pid: 1 } : { demande, pid: 1 };
      expect(lire({ ...base, at: ecrireHorodatage(T - 600000) })).to.deep.equal({ action: demande, demande: { ...base, at: ecrireHorodatage(T - 600000) } });
      expect(lire({ ...base, at: ecrireHorodatage(T - 600001) }).refus.data).to.deep.equal({ raison: "demande_perimee", demande, at: ecrireHorodatage(T - 600001) });
      expect(lire({ ...base, at: ecrireHorodatage(dem - 1) }).refus.data).to.deep.equal({ raison: "demande_perimee", demande, at: ecrireHorodatage(dem - 1) });
      expect(lire({ ...base, at: ecrireHorodatage(dem) }, { maintenant: dem }).action).to.equal(demande);
      expect(lire(base).refus.data).to.deep.equal({ raison: "demande_perimee", demande, at: null });
      expect(lire({ ...base, at: "2026-11-11 09:00:00" }).refus.data).to.deep.equal({ raison: "demande_perimee", demande, at: null });
    }
    const vieux = ecrireHorodatage(T - 601000);
    const r = lire(dossier({ at: vieux }));
    expect(r.refus).to.deep.equal({
      event: "dossier_export_refused", component: "noyau", seq: null, request_id: RID,
      data: { raison: "demande_perimee", selection: "seq", seq: 7, ticket: null, destination: `${EXPORTS}/d`, exports_dir: EXPORTS, period_start: null, decision: null, member: null, at: vieux, detail: null },
    });
    expect(lire(dossier({ at: ecrireHorodatage(dem - 1) })).refus.data.raison).to.equal("demande_perimee");
    // Ordre : une demande hors domaine ET périmée est hors domaine.
    expect(lire(dossier({ at: vieux, pid: 0 })).refus.data.raison).to.equal("demande_invalide");
    // Admise : l'action que nomme `demande`, avec la demande lue.
    expect(lire(dossier()).action).to.equal("dossier");
  });

  it("domaines d'EX-15.9 de la commande : --seq, --ticket, --delai-ms, --vers (chemin rendu absolu normalisé, dernier composant donné ni . ni ..)", function () {
    for (const s of ["1", "7", String(Number.MAX_SAFE_INTEGER)]) expect(texteSeqValide(s), s).to.equal(true);
    for (const s of ["0", "01", "+1", "-1", "1.0", "1e3", "", " 1", String(Number.MAX_SAFE_INTEGER + 1), "9007199254740992"]) expect(texteSeqValide(s), s).to.equal(false);
    for (const s of ["0", "1", "86400000", "120000"]) expect(texteDelaiValide(s), s).to.equal(true);
    for (const s of ["00", "-1", "86400001", "1.5", ""]) expect(texteDelaiValide(s), s).to.equal(false);
    for (const s of ["apr-1", "apr-2201", "apr-a-b-c", `apr-${"z".repeat(124)}`]) expect(ticketValide(s), s).to.equal(true);
    for (const s of ["apr-", "apr--1", "apr-1-", "APR-1", "apr-É", `apr-${"z".repeat(125)}`, "ticket-1"]) expect(ticketValide(s), s).to.equal(false);
    expect(normaliserVers("d", "/var/lib/noortrace-exports")).to.equal("/var/lib/noortrace-exports/d");
    expect(normaliserVers("../x/./d/", "/var/lib/noortrace-exports/a")).to.equal("/var/lib/noortrace-exports/x/d");
    expect(normaliserVers("/a//b/", "/")).to.equal("/a/b");
    for (const v of ["", ".", "..", "a/..", "a/.", "a/../", "/", "///", "a\u0000b"]) expect(normaliserVers(v, "/srv"), JSON.stringify(v)).to.equal(null);
    expect(normaliserVers(`${"a".repeat(255)}`, "/srv")).to.equal(`/srv/${"a".repeat(255)}`);
    expect(normaliserVers(`${"a".repeat(256)}`, "/srv")).to.equal(null);
    expect(destinationValide(`/${"a/".repeat(2047)}a`)).to.equal(true);
    expect(destinationValide(`/${"a/".repeat(2048)}a`)).to.equal(false);
    expect(destinationValide(`/${"é".repeat(128)}`)).to.equal(false);
    expect(destinationValide(`/${"é".repeat(127)}`)).to.equal(true);
  });

  it("étape 6 : un composant au nom réservé .noortrace-partiel-… n'est pas une destination (le démon l'effacerait au démarrage suivant, EX-15.13 point 4) : commande hors domaine, demande_invalide au démon", function () {
    for (const v of [`.noortrace-partiel-${RID}`, ".noortrace-partiel-x", `.noortrace-partiel-${RID}/d`]) {
      expect(normaliserVers(v, EXPORTS), v).to.equal(null);
      expect(destinationValide(`${EXPORTS}/${v}`), v).to.equal(false);
      const r = lire(dossier({ destination: `${EXPORTS}/${v}` }));
      expect(r.refus.data, v).to.deep.include({ raison: "demande_invalide", member: "destination", destination: null });
      expect(r.refus.request_id).to.equal(RID);
    }
    // un nom voisin reste admis
    for (const v of ["noortrace-partiel-x", ".noortrace-partiel", "a.noortrace-partiel-x"]) expect(normaliserVers(v, EXPORTS), v).to.equal(`${EXPORTS}/${v}`);
  });
});

describe("EX-15.15 (révision 0.9) : erreur imprévue pendant une demande (traiterDemande sur un cœur d'essai)", function () {
  let dir;
  before(function () {
    dir = repertoireTemporaire("noortrace-demande-panne-");
    fs.mkdirSync(path.join(dir, "exports"));
  });
  after(function () {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });
  /** Cœur d'essai : journal en mémoire ; `pannes` remplace des méthodes par des erreurs imprévues. */
  const coeurEssai = (pannes = {}) => {
    const lignes = [];
    return {
      lignes,
      config: { exports_dir: path.join(dir, "exports"), storage: { root: path.join(dir, "stockage") }, supervision: { ops_log: { path: path.join(dir, "ops.ndjson") } } },
      instantDemarrage: T - 3600000,
      bailDetenu: true,
      passif: false,
      bail: { valide: () => { if (pannes.bail) throw new TypeError("panne d'essai : 7400.00 CHF"); return true; } },
      async rotationUrgence() { throw new TypeError("panne d'essai de la rotation"); },
      async commandeAncrage() { throw Object.assign(new RangeError("panne d'essai de l'ancrage"), { code: "ERR_ESSAI" }); },
      journal: { consigner: (level, component, event, data, o = {}) => lignes.push({ level, component, event, data, seq: o.seq ?? null, request_id: o.request_id ?? null }) },
    };
  };

  it("demande dossier dont l'export lève : une seule ligne de réponse, dossier_export_refused ecriture_impossible, detail erreur_interne (nom de l'erreur, jamais son message), request_id de la demande ; répertoire temporaire supprimé", async function () {
    const c = coeurEssai({ bail: true });
    const temp = path.join(dir, "exports", `.noortrace-partiel-${RID}`);
    fs.mkdirSync(temp);
    fs.writeFileSync(path.join(temp, "dossier.json"), "{}");
    const d = dossier({ destination: path.join(dir, "exports", "d") });
    const l = await traiterDemande(c, octets(d), T);
    expect(l).to.deep.include({ event: "dossier_export_refused", component: "noyau", seq: null, request_id: RID });
    expect(l.data).to.deep.include({ raison: "ecriture_impossible", selection: "seq", seq: 7, destination: d.destination, exports_dir: path.join(dir, "exports"), detail: "erreur_interne TypeError" });
    expect(c.lignes).to.have.length(1);
    expect(c.lignes[0]).to.deep.include({ level: "warning", event: "dossier_export_refused", request_id: RID });
    expect(JSON.stringify(c.lignes)).to.not.contain("7400.00");
    expect(fs.existsSync(temp), "répertoire temporaire supprimé").to.equal(false);
    expect(fs.existsSync(d.destination)).to.equal(false);
  });

  it("demandes rotation-urgence et ancrage dont l'action lève hors de ses refus : ctl_request_failed (error, noyau, seq et request_id nuls ; data { demande, detail })", async function () {
    const c = coeurEssai();
    await traiterDemande(c, octets({ demande: "rotation-urgence", pid: 1, at: AT }), T);
    await traiterDemande(c, octets({ demande: "ancrage", commande: "etat", id: null, pid: 1, at: AT }), T);
    expect(c.lignes).to.deep.equal([
      { level: "error", component: "noyau", event: "ctl_request_failed", data: { demande: "rotation-urgence", detail: "erreur_interne TypeError" }, seq: null, request_id: null },
      { level: "error", component: "noyau", event: "ctl_request_failed", data: { demande: "ancrage", detail: "erreur_interne RangeError ERR_ESSAI" }, seq: null, request_id: null },
    ]);
  });

  it("révision 0.9 (EX-15.15) : ctl_request_failed porte le request_id de la demande quand il est lisible (32 chiffres hexadécimaux minuscules), null sinon ; aussi avant que l'action soit connue", async function () {
    const c = coeurEssai();
    await traiterDemande(c, octets({ demande: "rotation-urgence", request_id: RID, pid: 1, at: AT }), T);
    await traiterDemande(c, octets({ demande: "ancrage", commande: "etat", id: null, request_id: "ee".repeat(16), pid: 1, at: AT }), T);
    await traiterDemande(c, octets({ demande: "ancrage", commande: "etat", id: null, request_id: RID.toUpperCase(), pid: 1, at: AT }), T);
    expect(c.lignes.map((l) => [l.event, l.data.demande, l.request_id])).to.deep.equal([
      ["ctl_request_failed", "rotation-urgence", RID],
      ["ctl_request_failed", "ancrage", "ee".repeat(16)],
      ["ctl_request_failed", "ancrage", null],
    ]);
    expect(requestIdLisible(octets({ demande: "dossier", request_id: RID }))).to.equal(RID);
    for (const x of ["pas du json", "[1]", JSON.stringify({ request_id: 7 }), JSON.stringify({ request_id: RID.slice(1) })]) expect(requestIdLisible(octets(x)), x).to.equal(null);
  });
});

describe("demandes du démon sur le démon réel à horloge réglable (journal d'exploitation de niveau error)", function () {
  this.timeout(240000);
  let dir;
  let demon;
  let config;
  let serveur;
  let cheminConfig;
  let journal;
  let env;
  const demandeFichier = () => `${journal}.rotation-urgence`;

  /** Horloge murale du démon (commande `demarrage`). */
  async function maintenant() {
    return (await demon.commande({ cmd: "demarrage" })).murale;
  }

  async function rotations() {
    return (await lireEvenements(path.join(config.storage.root, config.recorder.org_id.slice(2), config.recorder.journal_id.slice(2)))).filter((e) => e.execution.tool === "noortrace.journal.rotation-cle");
  }

  /** Dépose une demande, signale, attend la ligne `event` du fichier (écrite malgré le niveau error). */
  async function refusAttendu(contenu, event, avant = demon.lignes().length) {
    deposerEtSignaler(journal, demon.pid, contenu);
    const l = await attendre(() => demon.lignes().slice(avant).find((x) => x.event === event), 15000, event);
    expect(fs.existsSync(demandeFichier()), "fichier de demande supprimé").to.equal(false);
    return l;
  }

  before(async function () {
    dir = repertoireTemporaire("noortrace-demandes-");
    const x = configurationDev(dir);
    config = x.config;
    const service = new ServiceApprobationFactice({ org_id: config.recorder.org_id, journal_id: config.recorder.journal_id });
    serveur = await service.servir(0);
    config.policy.approval.service = { url: `http://127.0.0.1:${serveur.address().port}`, socket: null, token: { env: "NOORTRACE_TEST_JETON_APPROBATION" }, peer_user: null };
    config.supervision.ops_log.level = "error";
    config.exports_dir = path.join(dir, "exports");
    fs.mkdirSync(config.exports_dir);
    env = { ...x.env, NOORTRACE_TEST_JETON_APPROBATION: "jeton-approbation-de-test" };
    cheminConfig = path.join(dir, "configuration.json");
    fs.writeFileSync(cheminConfig, JSON.stringify(config, null, 2));
    journal = config.supervision.ops_log.path;
    // Fichier de demande resté en place avant le démarrage : une rotation d'urgence valide, à l'heure.
    fs.mkdirSync(path.dirname(journal), { recursive: true });
    fs.writeFileSync(demandeFichier(), `${JSON.stringify({ demande: "rotation-urgence", pid: 1, at: ecrireHorodatage(Date.now()) })}\n`, { mode: 0o600 });
    // Horloge du démon une heure en deçà de l'heure réelle : une demande écrite par noortrace-ctl n'est pas périmée.
    demon = new DemonEssai({ cheminConfig, env, journal, horloge: Date.now() - 3600000 });
    await demon.demarrer();
  });

  after(async function () {
    await demon?.arreter().catch(() => {});
    await new Promise((r) => (serveur ? serveur.close(() => r()) : r()));
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("fichier de demande resté au démarrage : supprimé sans être exécuté, ctl_request_refused demande_perimee (écrite au niveau error) ; aucune rotation de clé", async function () {
    expect(fs.existsSync(demandeFichier())).to.equal(false);
    const l = demon.de("ctl_request_refused");
    expect(l).to.have.lengthOf(1);
    expect(l[0]).to.include({ level: "warning", component: "noyau", seq: null, request_id: null });
    expect(l[0].data).to.deep.include({ raison: "demande_perimee", demande: "rotation-urgence" });
    expect(await rotations()).to.deep.equal([]);
    // Le niveau error retient les autres lignes de niveau inférieur (startup est en info).
    expect(demon.de("startup")).to.deep.equal([]);
  });

  it("SIGURG sans fichier de demande : rien n'est exécuté, key_rotation_emergency_ignored (sans_demande)", async function () {
    process.kill(demon.pid, "SIGURG");
    await attendre(async () => (await demon.commande({ cmd: "journal", event: "key_rotation_emergency_ignored" })).lignes.length === 1, 10000, "key_rotation_emergency_ignored");
    const [l] = (await demon.commande({ cmd: "journal", event: "key_rotation_emergency_ignored" })).lignes;
    expect(l.data).to.deep.equal({ raison: "sans_demande" });
    expect(await rotations()).to.deep.equal([]);
  });

  it("défaut corrigé : aucune demande n'est prise pour une autre action — demandes illisible, inconnue, dossier hors domaine et dossier admise ne font jamais tourner la clé (avant l'étape 6, chacune déclenchait la rotation d'urgence)", async function () {
    const at = ecrireHorodatage(await maintenant());
    const illisible = await refusAttendu("ceci n'est pas une demande\n", "ctl_request_refused");
    expect(illisible.data).to.deep.equal({ raison: "demande_illisible", demande: null, at: null });
    const inconnue = await refusAttendu({ demande: "x".repeat(100), pid: 1, at }, "ctl_request_refused");
    expect(inconnue.data).to.deep.equal({ raison: "demande_inconnue", demande: "x".repeat(64), at });
    expect(inconnue).to.include({ level: "warning", component: "noyau", seq: null, request_id: null });
    const rid = "aa".repeat(16);
    const avant = demon.lignes().length;
    deposerEtSignaler(journal, demon.pid, demandeDossier({ selection: "seq", seq: 1, destination: path.join(config.exports_dir, "premier"), request_id: rid, at }));
    const l = await attendre(() => demon.lignes().slice(avant).find((x) => x.request_id === rid), 15000, "réponse de la demande dossier");
    expect(l.event).to.equal("dossier_export_refused");
    expect(l.data.raison).to.equal("periode_non_close");
    expect(await rotations(), "aucune rotation de clé").to.deep.equal([]);
    expect((await demon.commande({ cmd: "journal", event: "key_rotation_emergency" })).lignes).to.deep.equal([]);
  });

  it("noortrace-ctl dossier exporter avec un journal d'exploitation de niveau error : la réponse est écrite malgré le niveau et lue par la commande ; --dernier sans période close : aucune_periode_close, code 1, message d'EX-15.12", async function () {
    const r = await ctl(["dossier", "exporter", "--dernier", "--vers", path.join(config.exports_dir, "dernier"), "--configuration", cheminConfig], { env });
    expect(r.code, r.stderr).to.equal(1);
    expect(r.ligne).to.deep.include({ pid: demon.pid, event: "dossier_export_refused" });
    expect(r.ligne.data).to.include({ raison: "aucune_periode_close", selection: "dernier", seq: null, exports_dir: config.exports_dir });
    expect(r.stderr).to.equal("noortrace-ctl dossier exporter : aucune période close dans le journal\n");
    expect(fs.readdirSync(config.exports_dir)).to.deep.equal([]);
  });

  it("demande dossier hors de son domaine, un cas par membre du pas 3 et un membre de plus : dossier_export_refused demande_invalide, member nommé, request_id de la demande s'il est du domaine ; rien n'est exporté", async function () {
    const at = ecrireHorodatage(await maintenant());
    const base = demandeDossier({ selection: "seq", seq: 1, destination: path.join(config.exports_dir, "invalide"), request_id: "bb".repeat(16), at });
    const cas = [
      ["selection", (o) => { o.selection = "tout"; }],
      ["seq", (o) => { delete o.seq; }],
      ["ticket", (o) => { o.ticket = "apr-1"; }],
      ["destination", (o) => { o.destination = "relatif"; }],
      ["request_id", (o) => { o.request_id = "B".repeat(32); }],
      ["pid", (o) => { o.pid = 0; }],
      ["at", (o) => { o.at = "maintenant"; }],
      ["supplement", (o) => { o.supplement = true; }],
    ];
    for (const [membre, modifier] of cas) {
      const o = structuredClone(base);
      modifier(o);
      const l = await refusAttendu(o, "dossier_export_refused");
      expect(l.data.raison, membre).to.equal("demande_invalide");
      expect(l.data.member).to.equal(membre);
      expect(l.request_id).to.equal(membre === "request_id" ? null : base.request_id);
      expect(l).to.include({ level: "warning", component: "noyau", seq: null });
    }
    expect(fs.readdirSync(config.exports_dir)).to.deep.equal([]);
  });

  it("rotation-urgence et ancrage exécutées : la rotation d'urgence est scellée (signée par l'ancienne clé) ; la demande ancrage va au composant (non configuré ici : anchoring_ctl_refused ancrage_non_configure), sans rotation", async function () {
    const at = ecrireHorodatage(await maintenant());
    deposerEtSignaler(journal, demon.pid, { demande: "ancrage", commande: "etat", id: null, pid: 1, at });
    await attendre(async () => (await demon.commande({ cmd: "journal", event: "anchoring_ctl_refused" })).lignes.length === 1, 10000, "anchoring_ctl_refused");
    expect((await demon.commande({ cmd: "journal", event: "anchoring_ctl_refused" })).lignes[0].data).to.deep.equal({ command: "etat", raison: "ancrage_non_configure" });
    expect(await rotations()).to.deep.equal([]);
    deposerEtSignaler(journal, demon.pid, { demande: "rotation-urgence", pid: 1, at: ecrireHorodatage(await maintenant()) });
    await attendre(async () => (await rotations()).length === 1, 15000, "événement de rotation");
    const [rot] = await rotations();
    expect(rot.recorder_key_id).to.equal("rec-test-01");
    expect((await demon.commande({ cmd: "journal", event: "key_rotation_emergency" })).lignes[0].data).to.deep.include({ old_key_id: "rec-test-01", new_key_id: "rec-test-02" });
  });

  it("EX-15.15 sur le démon réel : demande ancrage dont le composant lève → ctl_request_failed (demande ancrage, détail sans message), sans rotation ; fichier de demande que le démon ne peut supprimer (un répertoire) → ctl_request_not_removed (path, code), jamais exécuté, et la commande suivante le trouve occupé", async function () {
    const nRot = (await rotations()).length;
    await demon.commande({ cmd: "panne-ancrage" });
    try {
      const avant = demon.lignes().length;
      deposerEtSignaler(journal, demon.pid, { demande: "ancrage", commande: "etat", id: null, pid: 1, at: ecrireHorodatage(await maintenant()) });
      const l = await attendre(() => demon.lignes().slice(avant).find((x) => x.event === "ctl_request_failed"), 15000, "ctl_request_failed");
      expect(l).to.deep.include({ level: "error", component: "noyau", seq: null, request_id: null, data: { demande: "ancrage", detail: "erreur_interne TypeError" } });
      expect(demon.lignes().slice(avant).filter((x) => x.event === "anchoring_ctl_refused")).to.deep.equal([]);
    } finally {
      await demon.commande({ cmd: "panne-ancrage", actif: false });
    }
    // un répertoire non vide à la place du fichier de demande : ni lu comme demande, ni supprimable
    fs.mkdirSync(demandeFichier());
    fs.writeFileSync(path.join(demandeFichier(), "x"), `${JSON.stringify({ demande: "rotation-urgence", pid: 1, at: ecrireHorodatage(await maintenant()) })}\n`);
    try {
      const avant = demon.lignes().length;
      process.kill(demon.pid, "SIGURG");
      const l = await attendre(() => demon.lignes().slice(avant).find((x) => x.event === "ctl_request_not_removed"), 15000, "ctl_request_not_removed");
      expect(l).to.deep.include({ level: "error", component: "noyau", seq: null, request_id: null, data: { path: demandeFichier(), code: "EISDIR" } });
      const r = await ctl(["dossier", "exporter", "--dernier", "--vers", path.join(config.exports_dir, "occupe"), "--configuration", cheminConfig, "--delai-ms", "300"], { env });
      expect(r.code, r.stderr).to.equal(4);
      expect(r.stderr).to.contain("fichier de demande occupé");
    } finally {
      fs.rmSync(demandeFichier(), { recursive: true, force: true });
    }
    expect((await rotations()).length).to.equal(nRot);
  });

  it("révision 0.9 (EX-15.15) : noortrace-ctl ancrage etat dont le composant lève reconnaît ctl_request_failed à son request_id et rend aussitôt le code 1, sans attendre la fin de son délai", async function () {
    await demon.commande({ cmd: "panne-ancrage" });
    try {
      const avant = demon.lignes().length;
      const t0 = Date.now();
      const r = await ctl(["ancrage", "etat", "--configuration", cheminConfig, "--delai-ms", "30000"], { env });
      const duree = Date.now() - t0;
      expect(r.code, r.stderr).to.equal(1);
      expect(duree, "réponse avant la fin du délai").to.be.below(15000);
      expect(r.ligne).to.deep.include({ pid: demon.pid, event: "ctl_request_failed", data: { demande: "ancrage", detail: "erreur_interne TypeError" } });
      expect(r.stderr).to.contain("erreur imprévue du démon (erreur_interne TypeError)");
      const l = demon.lignes().slice(avant).find((x) => x.event === "ctl_request_failed");
      expect(l.request_id).to.match(/^[0-9a-f]{32}$/);
    } finally {
      await demon.commande({ cmd: "panne-ancrage", actif: false });
    }
  });

  it("demandes périmées, sans effet : rotation-urgence et ancrage sans at ou à at hors forme ; antérieures au démarrage (rotation-urgence, dossier) ; 601 s avant la lecture (dossier, ancrage) ; ctl_request_refused ou dossier_export_refused demande_perimee", async function () {
    const nRot = (await rotations()).length;
    for (const o of [{ demande: "rotation-urgence", pid: 1 }, { demande: "ancrage", commande: "etat", id: null, pid: 1, at: "2026-11-11T09:00:00Z" }]) {
      const l = await refusAttendu(o, "ctl_request_refused");
      expect(l.data).to.deep.equal({ raison: "demande_perimee", demande: o.demande, at: null });
    }
    const { demarrage } = await demon.commande({ cmd: "demarrage" });
    const avantDemarrage = ecrireHorodatage(demarrage - 1000);
    const l1 = await refusAttendu({ demande: "rotation-urgence", pid: 1, at: avantDemarrage }, "ctl_request_refused");
    expect(l1.data).to.deep.equal({ raison: "demande_perimee", demande: "rotation-urgence", at: avantDemarrage });
    const d1 = demandeDossier({ selection: "dernier", destination: path.join(config.exports_dir, "perime"), request_id: "cc".repeat(16), at: avantDemarrage });
    const l2 = await refusAttendu(d1, "dossier_export_refused");
    expect(l2.data).to.deep.include({ raison: "demande_perimee", at: avantDemarrage, selection: "dernier", destination: d1.destination });
    expect(l2.request_id).to.equal(d1.request_id);
    // 601 s après une demande écrite après le démarrage : l'horloge du démon avance de 700 s.
    const t0 = await maintenant();
    await demon.commande({ cmd: "avancer", ms: 700000 });
    const vieux = ecrireHorodatage(t0 + 1000);
    expect((await maintenant()) - (t0 + 1000)).to.be.above(600000);
    const d2 = demandeDossier({ selection: "dernier", destination: path.join(config.exports_dir, "perime-601"), request_id: "dd".repeat(16), at: vieux });
    const l3 = await refusAttendu(d2, "dossier_export_refused");
    expect(l3.data).to.deep.include({ raison: "demande_perimee", at: vieux });
    const l4 = await refusAttendu({ demande: "ancrage", commande: "etat", id: null, pid: 1, at: vieux }, "ctl_request_refused");
    expect(l4.data).to.deep.equal({ raison: "demande_perimee", demande: "ancrage", at: vieux });
    expect((await rotations()).length).to.equal(nRot);
    expect(fs.readdirSync(config.exports_dir)).to.deep.equal([]);
    // Toutes les réponses de ce démon sont dans le fichier malgré le niveau error ; aucune autre ligne de niveau inférieur n'y est.
    expect(lignesJournal(journal).every((x) => x.level === "error" || ["ctl_request_refused", "dossier_export_refused", "dossier_exported"].includes(x.event))).to.equal(true);
  });
});

describe("noortrace-ctl cle rotation-urgence et ancrage : demande par création exclusive (CT-2 EX-15.10 pas 3 et 4, table de §22)", function () {
  this.timeout(240000);
  let dir;
  let demon;
  let serveur;
  let cheminConfig;
  let journal;
  let env;

  before(async function () {
    dir = repertoireTemporaire("noortrace-demandes-ctl-");
    const x = configurationDev(dir);
    const config = x.config;
    const service = new ServiceApprobationFactice({ org_id: config.recorder.org_id, journal_id: config.recorder.journal_id });
    serveur = await service.servir(0);
    config.policy.approval.service = { url: `http://127.0.0.1:${serveur.address().port}`, socket: null, token: { env: "NOORTRACE_TEST_JETON_APPROBATION" }, peer_user: null };
    config.exports_dir = path.join(dir, "exports");
    env = { ...x.env, NOORTRACE_TEST_JETON_APPROBATION: "jeton-approbation-de-test" };
    cheminConfig = path.join(dir, "configuration.json");
    fs.writeFileSync(cheminConfig, JSON.stringify(config, null, 2));
    journal = config.supervision.ops_log.path;
    demon = new DemonEssai({ cheminConfig, env, journal, horloge: Date.now() - 3600000 });
    await demon.demarrer();
  });

  after(async function () {
    await demon?.arreter().catch(() => {});
    await new Promise((r) => (serveur ? serveur.close(() => r()) : r()));
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("fichier de demande occupé : la commande attend dans son délai, ne touche pas au fichier présent, puis code 4 avec le message d'EX-15.10 ; libéré, la commande passe : ancrage etat (anchoring_ctl_refused, code 1), cle rotation-urgence (key_rotation_emergency, code 0)", async function () {
    const f = `${journal}.rotation-urgence`;
    const occupant = `${JSON.stringify({ demande: "autre", pid: 1, at: ecrireHorodatage(Date.now()) })}\n`;
    fs.writeFileSync(f, occupant, { mode: 0o600 });
    const t0 = Date.now();
    const r = await ctl(["cle", "rotation-urgence", "--configuration", cheminConfig, "--delai-ms", "700"], { env });
    const duree = Date.now() - t0;
    expect(r.code, r.stderr).to.equal(4);
    expect(r.stderr).to.include(`fichier de demande occupé : ${f} ; une autre commande est en cours, ou une demande n'a pas été lue (à supprimer si aucune commande noortrace-ctl ne tourne)`);
    expect(duree).to.be.at.least(650);
    expect(fs.readFileSync(f, "utf8")).to.equal(occupant);
    // Libéré pendant l'attente d'une autre commande : elle écrit sa demande et reçoit sa réponse.
    const enCours = ctl(["ancrage", "etat", "--configuration", cheminConfig, "--delai-ms", "10000"], { env });
    await pause(300);
    fs.rmSync(f);
    const a = await enCours;
    expect(a.code, a.stderr).to.equal(1);
    expect(a.ligne).to.deep.include({ event: "anchoring_ctl_refused", data: { command: "etat", raison: "ancrage_non_configure" } });
    const c = await ctl(["cle", "rotation-urgence", "--configuration", cheminConfig], { env });
    expect(c.code, c.stderr).to.equal(0);
    expect(c.ligne.event).to.equal("key_rotation_emergency");
    expect(fs.existsSync(f)).to.equal(false);
    // La demande occupante (« autre ») n'a jamais été lue par le démon.
    expect(demon.de("ctl_request_refused")).to.deep.equal([]);
    expect(demon.de("key_rotation_emergency")).to.have.lengthOf(1);
  });
});
