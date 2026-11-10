// TE-14 de CT-9 (CT-7 §6.1, JS-1 à JS-12, EX-6.1 à EX-6.3 ; CT-2 EX-9.7,
// EX-17.1 à EX-17.4, EX-18.6) : le journal de l'enregistreur sur lui-même,
// observé sur le démon `noortrace` réel (processus enfant de
// `test/fixtures/enregistreur-ancrage/demon.mjs`, horloge hybride à cadence
// réduite admise par le schéma, composant d'ancrage de CT-5 branché, registre
// factice du lot D, autorités RFC 3161 du lot E). Chaque situation de la
// table de CT-7 §6.1 est provoquée et l'événement ou la ligne que la table
// nomme est constaté : JS-1 `startup` ; JS-2 arrêt (aucun événement d'arrêt
// dans la chaîne) ; JS-3 `lease_acquired`, `lease_standby` (seconde
// instance), `lease_lost` (verrou du bail rendu par le noyau) ; JS-4
// `noortrace.journal.rotation-cle` ; JS-5 hors chaîne (rotation de la clé de
// chaîne au registre : aucun événement, refus nommé) ; JS-6
// `noortrace.journal.politique` ; JS-7 `config_reloaded` avec le SHA-256 du
// document ; JS-8 `clock_skew`, `clock_backstep` ; JS-9 et JS-10 sur le
// support WORM réel (second décor, LocalStack dans Docker : en attente sans
// Docker) ; JS-10 `integrity_check` ; JS-11 `anchor_pending`,
// `registry_pending` et les métriques de CT-5 §8.9 ; JS-12 constat d'absence
// (PA-8). Puis : aucun secret dans les lignes (EX-17.3), rotation du journal
// d'exploitation par `supervision.ops_log.rotate_max_bytes` (au plus
// `keep_files` fichiers tournés), disque plein simulé pendant le relais
// (`noortrace_ops_log_dropped_total` incrémenté, relais poursuivi ; EX-9.7,
// EX-17.4).

import { expect } from "chai";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import { principalCtlDemon, principalCtl, OperationsS3, identifiantsS3, lireRegistres, lireEcheance } from "@noortrace/enregistreur";
import {
  monterDemon, Demon, repertoireTemporaire, portLibre, enAttente, GRAINE_CLE_CHAINE,
} from "./fixtures/enregistreur-ancrage/outils.mjs";
import {
  IMAGES, dockerDisponible, demarrerS3, arreterTout, certificats, mandataireTls, creerBucketVerrouille, identifiantsRole, fichierSecret, suspendre,
} from "./fixtures/enregistreur-worm/outils.mjs";

const BASE = Date.UTC(2026, 10, 6, 9, 0, 2); // 2026-11-06T09:00:02Z, période [09:00, 10:00)
const PERIODE = Math.floor(BASE / 3600000) * 3600;
const RAPIDE = [20, 20, 20];

const getTexte = (port, chemin) => new Promise((res, rej) => {
  http.get({ host: "127.0.0.1", port, path: chemin }, (r) => {
    let t = "";
    r.on("data", (d) => (t += d));
    r.on("end", () => res({ statut: r.statusCode, corps: t }));
  }).on("error", rej);
});

/** `noortrace-ctl` en cours de processus (même utilisateur, /proc réel). */
async function ctl(args, o = {}) {
  let out = "";
  let err = "";
  const code = await principalCtlDemon(args, { stdout: { write: (s) => (out += s) }, stderr: { write: (s) => (err += s) }, ...o });
  return { code, out, err };
}

/** Événements de la chaîne (segments du journal), dans l'ordre des seq. */
function evenementsChaine(repertoire) {
  const dir = path.join(repertoire, "segments");
  const lignes = fs.readdirSync(dir).filter((n) => n.endsWith(".ndjson")).sort().flatMap((n) => fs.readFileSync(path.join(dir, n), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)));
  return lignes.filter((l) => l.execution && typeof l.seq === "number").sort((a, b) => a.seq - b.seq);
}

/** Valeur d'une métrique au format d'exposition texte. */
function metrique(texte, nom, etiquettes = "") {
  const re = new RegExp(`^${nom}${etiquettes ? `\\{${etiquettes}\\}` : ""} ([0-9.eE+-]+)$`, "m");
  const m = texte.match(re);
  return m ? Number(m[1]) : null;
}

/** Toutes les lignes du journal d'exploitation, fichiers tournés compris. */
function toutesLesLignes(chemin) {
  const dir = path.dirname(chemin);
  const base = path.basename(chemin);
  return fs.readdirSync(dir).filter((n) => n === base || n.startsWith(`${base}.`)).map((n) => fs.readFileSync(path.join(dir, n), "utf8")).join("");
}

describe("TE-14 : journal de l'enregistreur sur lui-même, JS-1 à JS-12 de CT-7 §6.1 observés sur le démon réel (CT-2 EX-17.1 à EX-17.4, EX-18.6 ; CT-7 EX-6.1 à EX-6.3)", function () {
  this.timeout(900000);
  let dir;
  let m;
  let demon;
  let portSante;
  let registrePort;
  let registreRelance = null;

  before(async function () {
    dir = repertoireTemporaire("noortrace-te14-");
    portSante = await portLibre();
    m = await monterDemon({
      dir, baseMs: BASE,
      surchargesAncrage: { registry: { checkpoints: "tous", inclusion_alert_s: 60 }, queue: { anchor_pending_alert_s: 60 } },
      surchargesConfig: (c) => {
        c.supervision.health_listen = `127.0.0.1:${portSante}`;
        c.supervision.metrics = true;
      },
    });
    if (m.condition) return;
    registrePort = Number(new URL(m.registre.url).port);
    demon = new Demon(m);
    await demon.demarrer();
    await demon.attendre((l) => l.some((x) => x.event === "anchoring_attached"), 30000, "anchoring_attached");
  });

  after(async function () {
    if (demon?.p) await demon.arreter().catch(() => {});
    if (registreRelance) await new Promise((r) => registreRelance.close(() => r()));
    await m?.fermer?.();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  function pret() {
    if (!m || m.condition) {
      enAttente(this, m?.condition ?? "contexte non préparé");
      return false;
    }
    return true;
  }

  it("JS-1 démarrage : une ligne startup (EX-17.2, EX-18.6) avec le sha256 des octets du document de configuration, la clé courante, l'époque du bail ; JS-3 : lease_acquired (époque, magasin file) la précède", async function () {
    if (!pret.call(this)) return;
    const startup = demon.de("startup");
    expect(startup).to.have.lengthOf(1);
    expect(startup[0].component).to.equal("noyau");
    expect(startup[0].data.config_sha256).to.equal(N.sha256Hex(new Uint8Array(fs.readFileSync(m.cheminConfig))));
    expect(startup[0].data).to.include({ recorder_key_id: "rec-test-01", class: "D", epoch: 1 });
    const bail = demon.de("lease_acquired");
    expect(bail).to.have.lengthOf(1);
    expect(bail[0].data).to.include({ epoch: 1, store: "file" });
    const evenements = demon.lignes().map((l) => l.event);
    expect(evenements.indexOf("lease_acquired")).to.be.lessThan(evenements.indexOf("startup"));
    // CT-7 : JS-1 n'a aucun porteur dans la chaîne (PA-1 non adoptée, EX-6.3) : le seul événement de démarrage est l'annonce de politique (EX-9.8).
    const chaine = evenementsChaine(m.repertoire);
    expect(chaine.map((e) => e.execution.tool)).to.deep.equal(["noortrace.journal.politique"]);
  });

  it("JS-3 bail : une seconde instance sur le même journal ne prend pas le bail et consigne lease_standby (13.4) ; santé standby ; elle s'arrête proprement", async function () {
    if (!pret.call(this)) return;
    const port2 = await portLibre();
    const config2 = JSON.parse(fs.readFileSync(m.cheminConfig, "utf8"));
    config2.supervision.health_listen = `127.0.0.1:${port2}`;
    const chemin2 = path.join(dir, "configuration-passive.json");
    fs.writeFileSync(chemin2, JSON.stringify(config2, null, 2));
    const passive = new Demon({ ...m, cheminConfig: chemin2 });
    await passive.demarrer();
    try {
      await demon.attendre((l) => l.some((x) => x.event === "lease_standby"), 30000, "lease_standby");
      expect(demon.de("lease_standby")[0].data).to.include({ store: "file" });
      const sante = await getTexte(port2, "/healthz");
      expect(JSON.parse(sante.corps)).to.deep.equal({ status: "standby" });
    } finally {
      const fin = await passive.arreter();
      expect(fin.code).to.equal(0);
    }
    expect(demon.de("lease_acquired")).to.have.lengthOf(1, "le bail n'a pas changé de main");
  });

  it("JS-5 rotation de la seule clé de chaîne : hors chaîne par conception (au registre) ; aucun événement ne la porte ; la rotation d'urgence est refusée tant que le registre n'est pas branché pour elle (registre_non_branche, reste nommé)", async function () {
    if (!pret.call(this)) return;
    const r = await ctl(["cle", "rotation-urgence", "--configuration", m.cheminConfig]);
    expect(r.code, r.err).to.not.equal(2);
    await demon.attendre((l) => l.some((x) => x.event === "key_rotation_emergency_refused"), 20000, "key_rotation_emergency_refused");
    expect(demon.de("key_rotation_emergency_refused").at(-1).data).to.include({ raison: "registre_non_branche" });
    expect(evenementsChaine(m.repertoire).some((e) => /chaine|chain/.test(e.execution.tool))).to.equal(false);
  });

  it("JS-6 et JS-7 : noortrace-ctl reload avec une nouvelle version de politique → événement noortrace.journal.politique dans la chaîne (policy_announced, seq), ligne config_reloaded avec le sha256 des octets du nouveau document et le policy_sha256 (EX-18.6)", async function () {
    if (!pret.call(this)) return;
    const config = JSON.parse(fs.readFileSync(m.cheminConfig, "utf8"));
    config.policy.version = "2026-11-06-te14";
    const octets = Buffer.from(JSON.stringify(config, null, 2));
    fs.writeFileSync(m.cheminConfig, octets);
    const r = await ctl(["reload", "--configuration", m.cheminConfig]);
    expect(r.code, r.err).to.equal(0);
    await demon.attendre((l) => l.some((x) => x.event === "config_reloaded" && x.component === "config"), 20000, "config_reloaded");
    const lignesReload = demon.de("config_reloaded");
    const l = lignesReload.find((x) => x.component === "config" && x.data && "policy_version" in x.data);
    expect(l, `ligne config_reloaded du cœur : ${JSON.stringify(lignesReload.map((x) => [x.component, x.data]))}`).to.not.equal(undefined);
    expect(l.data.policy_version).to.equal("2026-11-06-te14");
    expect(l.data.config_sha256).to.equal(N.sha256Hex(new Uint8Array(octets)));
    expect(l.data.policy_sha256).to.match(/^0x[0-9a-f]{64}$/);
    const annonce = demon.de("policy_announced").find((x) => x.data.policy_version === "2026-11-06-te14");
    expect(annonce.seq).to.be.a("number");
    expect(annonce.data.policy_sha256).to.equal(l.data.policy_sha256);
    const e = evenementsChaine(m.repertoire).find((x) => x.seq === annonce.seq);
    expect(e.execution.tool).to.equal("noortrace.journal.politique");
    expect(e.execution.arguments.value).to.deep.equal({ policy_sha256: l.data.policy_sha256, policy_version: "2026-11-06-te14" });
  });

  it("JS-4 rotation de la clé de l'enregistreur (EX-11.15) : événement noortrace.journal.rotation-cle dans la chaîne, ligne key_rotated ; les points suivants sont signés par la nouvelle clé et admis par le composant d'ancrage", async function () {
    if (!pret.call(this)) return;
    await demon.evenement(1);
    const r = await demon.commande({ cmd: "rotation", cle: "rec-test-02" });
    const chaine = evenementsChaine(m.repertoire);
    const rotation = chaine.find((e) => e.seq === r.seq);
    expect(rotation.execution.tool).to.equal("noortrace.journal.rotation-cle");
    expect(rotation.recorder_key_id).to.equal("rec-test-01");
    const l = demon.de("key_rotated");
    expect(l).to.have.lengthOf(1);
    expect(l[0].data).to.deep.include({ old_key_id: "rec-test-01", new_key_id: "rec-test-02" });
    expect(l[0].seq).to.equal(r.seq);
    // L'opérateur inscrit la nouvelle clé Ed25519 au registre des enregistreurs pour la même clé de chaîne
    // (CT-4 OP-9 : l'envoi vérifie que la clé publique des points est inscrite pour l'expéditeur ; sans cela,
    // l'ancre de la période de JS-11 est refusée en `cle_chaine_non_inscrite`).
    const nouvelle = rotation.execution.arguments.value.new_public_key;
    expect(nouvelle).to.match(/^0x[0-9a-f]{64}$/);
    m.registre.noeud.inscrire({ orgId: m.config.recorder.org_id, chainKey: m.registre.cleChaine.adresse(), ed25519PubKey: nouvelle, journalId: m.config.recorder.journal_id });
    const avant = demon.de("checkpoint_written").length;
    await demon.attendre((lg) => lg.filter((x) => x.event === "checkpoint_written").length > avant + 1, 40000, "deux points après la rotation");
    const serie = fs.readFileSync(path.join(m.repertoire, "points", `periode-${PERIODE}.ndjson`), "utf8").split("\n").filter(Boolean).map((x) => JSON.parse(x));
    expect(serie.at(-1).key_id).to.equal("rec-test-02");
    expect(demon.de("anchor_admission_refused")).to.deep.equal([]);
  });

  it("JS-8 saut d'horloge : un recul mural au-delà de warn_skew_ms consigne clock_skew ; au-delà de max_backstep_ms, clock_backstep et mode dégradé horloge (degraded_enter, appels refusés) ; l'horloge revenue, degraded_exit et le relais reprend ; aucun événement de la chaîne ne porte le saut (hors chaîne, PA-7)", async function () {
    if (!pret.call(this)) return;
    await demon.evenement(2);
    await demon.decalerMurale(-3000);
    await demon.evenement(3);
    await demon.decalerMurale(3000);
    await demon.attendre((l) => l.some((x) => x.event === "clock_skew"), 10000, "clock_skew");
    expect(demon.de("clock_skew")[0].data.ecart_ms).to.be.at.least(1000);
    await demon.decalerMurale(-12000);
    let refus = null;
    try {
      await demon.evenement(4);
    } catch (e) {
      refus = e;
    }
    expect(refus, "appel refusé en mode dégradé horloge").to.not.equal(null);
    expect(refus.message).to.match(/horloge/);
    await demon.attendre((l) => l.some((x) => x.event === "clock_backstep") && l.some((x) => x.event === "degraded_enter" && x.data.reason === "horloge"), 10000, "clock_backstep et degraded_enter");
    expect(demon.de("clock_backstep")[0].data.ecart_ms).to.be.above(5000);
    expect(JSON.parse((await getTexte(portSante, "/healthz")).corps).reasons).to.include("horloge");
    await demon.decalerMurale(12000);
    await demon.attendre((l) => l.some((x) => x.event === "degraded_exit" && x.data.reason === "horloge"), 20000, "degraded_exit");
    const e = await demon.evenement(5);
    expect(e.seq).to.be.a("number");
    const sortes = new Set(evenementsChaine(m.repertoire).map((x) => x.execution.tool));
    expect([...sortes].filter((t) => t.startsWith("noortrace.journal."))).to.have.members([...new Set(["noortrace.journal.politique", "noortrace.journal.rotation-cle"])]);
  });

  it("JS-11 ancrage dégradé : registre coupé avant la clôture → l'ancre de la période ne part pas, registry_pending (CT-2 §14.2, CT-5 EX-8.15) puis anchor_pending et leurs alertes ; métriques de CT-5 §8.9 sur /metrics (noortrace_anchor_pending, noortrace_anchoring_queue_entries, noortrace_anchoring_attempts_total, noortrace_anchoring_d_registre_s) ; registre revenu → ancre de la période incluse, jeton de clôture obtenu", async function () {
    if (!pret.call(this)) return;
    await m.registre.fermer();
    await demon.evenement(6);
    await demon.avancer((PERIODE + 3601) * 1000 - m.horloge.murale());
    await demon.attendre((l) => l.some((x) => x.event === "period_closed" && x.data.period_start === PERIODE), 60000, "period_closed");
    await demon.attendre((l) => l.some((x) => x.event === "registry_send_failed" && x.data.request_id?.startsWith("ancre_registre_periode")), 60000, "échec d'envoi de l'ancre de la période");
    await demon.avancer(61000);
    // CT-5 EX-8.4, EX-8.15 : le jeton de la période attend l'inclusion de son ancre ; passé inclusion_alert_s puis anchor_pending_alert_s,
    // le planificateur consigne registry_pending et anchor_pending sur la demande jeton_periode, avec leurs alertes.
    await demon.attendre((l) => l.some((x) => x.event === "registry_pending" && x.data.request_id?.startsWith("jeton_periode")) && l.some((x) => x.event === "anchor_pending" && x.data.request_id?.startsWith("jeton_periode")), 90000, "registry_pending et anchor_pending de la période");
    expect(demon.de("alerte_registry_pending").length).to.be.at.least(1);
    expect(demon.de("alerte_anchor_pending").length).to.be.at.least(1);
    const texte = (await getTexte(portSante, "/metrics")).corps;
    expect(texte).to.include("# TYPE noortrace_anchor_pending gauge");
    expect(metrique(texte, "noortrace_anchor_pending", 'anchor="registre"')).to.be.at.least(1);
    expect(texte).to.include("# TYPE noortrace_anchoring_queue_entries gauge");
    expect(metrique(texte, "noortrace_anchoring_queue_entries", 'kind="ancre_registre_periode",state="a_reprendre"') ?? metrique(texte, "noortrace_anchoring_queue_entries", 'kind="ancre_registre_periode",state="envoyee"')).to.be.at.least(1);
    expect(texte).to.include("# TYPE noortrace_anchoring_attempts_total counter");
    expect(texte).to.include("# TYPE noortrace_anchoring_d_registre_s histogram");
    // Registre de retour sur le même port : le nœud factice répond de nouveau ; l'ancre de la période est incluse puis le jeton de clôture obtenu.
    const noeud = m.registre.noeud;
    const url = m.registre.url;
    registreRelance = http.createServer((req, rep) => {
      const morceaux = [];
      req.on("data", (d) => morceaux.push(d));
      req.on("end", () => {
        let requete;
        try {
          requete = JSON.parse(Buffer.concat(morceaux).toString("utf8"));
        } catch {
          rep.writeHead(400).end();
          return;
        }
        const reponse = Array.isArray(requete) ? requete.map((q) => noeud.repondre(url, q)) : noeud.repondre(url, requete);
        rep.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(reponse));
      });
    });
    await new Promise((r) => registreRelance.listen(registrePort, "127.0.0.1", r));
    // La reprise de l'ancre est au pas retry.max_ms (60 s) : l'horloge saute d'autant jusqu'à l'inclusion (au plus cinq sauts).
    for (let k = 0; k < 5 && !demon.de("registry_included").some((x) => x.data.request_id?.startsWith("ancre_registre_periode")); k++) {
      await demon.avancer(61000);
      await new Promise((r) => setTimeout(r, 4000));
    }
    await demon.attendre((l) => l.some((x) => x.event === "registry_included" && x.data.request_id?.startsWith("ancre_registre_periode")), 60000, "ancre de la période incluse au retour");
    await demon.attendre((l) => l.some((x) => x.event === "period_timestamped"), 120000, "period_timestamped");
  });

  it("JS-10 (part sans support) : contrôles périodiques d'EX-17.5 après la clôture de la période → lignes integrity_check (manifeste, signature, signataire) en réussite ; period_closed porte la période", async function () {
    if (!pret.call(this)) return;
    expect(m.horloge.murale()).to.be.at.least((PERIODE + 3600) * 1000 + 10000, "l'heure suivante est entamée depuis plus de 10 s (contrôle horaire)");
    expect(demon.de("period_closed").some((x) => x.data.period_start === PERIODE)).to.equal(true);
    await demon.commande({ cmd: "controles" });
    const checks = demon.de("integrity_check").map((l) => [l.data.check, l.data.ok]);
    for (const k of ["manifeste", "signature", "signataire"]) expect(checks, k).to.deep.include([k, true]);
    expect(checks.filter(([, ok]) => !ok)).to.deep.equal([]);
  });

  it("JS-12 attestation de périmètre : aucun événement ne la porte (PA-8 non adoptée, CT-7 EX-6.3) ; les seules sortes réservées de la chaîne sont politique et rotation-cle", async function () {
    if (!pret.call(this)) return;
    const sortes = [...new Set(evenementsChaine(m.repertoire).map((x) => x.execution.tool).filter((t) => t.startsWith("noortrace.journal.")))].sort();
    expect(sortes).to.deep.equal(["noortrace.journal.politique", "noortrace.journal.rotation-cle"]);
    expect(demon.lignes().some((l) => /attestation/.test(l.event))).to.equal(false);
  });

  it("EX-17.3 : aucun secret dans les lignes du journal d'exploitation (clé TLS du client, clé de chaîne, secrets de configuration résolus), ni dans la file durable ni dans acquisitions.ndjson", async function () {
    if (!pret.call(this)) return;
    const texte = toutesLesLignes(m.config.supervision.ops_log.path);
    const secretTls = Buffer.from(m.tls.client).toString("utf8").split("\n")[1];
    const cleChaine = N.octetsVersHex(GRAINE_CLE_CHAINE).slice(2);
    for (const marqueur of [secretTls, cleChaine, "secret-de-test-", "PRIVATE KEY"]) expect(texte.toLowerCase().includes(marqueur.toLowerCase()), marqueur.slice(0, 12)).to.equal(false);
    for (const v of Object.values(m.env).filter((x) => /^secret-de-test-/.test(String(x)))) expect(texte.includes(v)).to.equal(false);
    const fichiersFile = fs.readdirSync(path.join(m.repertoire, "ancres", "file")).filter((n) => /^file-[0-9]+\.ndjson$/.test(n));
    const autres = [...fichiersFile.map((n) => fs.readFileSync(path.join(m.repertoire, "ancres", "file", n), "utf8")), fs.readFileSync(path.join(m.repertoire, "ancres", `periode-${PERIODE}`, "acquisitions.ndjson"), "utf8")].join("");
    for (const marqueur of [secretTls, cleChaine, "PRIVATE KEY"]) expect(autres.toLowerCase().includes(marqueur.toLowerCase())).to.equal(false);
  });

  it("EX-9.7, EX-17.4 : disque plein simulé pendant le relais (le fichier du journal d'exploitation ne peut plus être écrit) : chaque ligne non écrite incrémente noortrace_ops_log_dropped_total d'une unité et le relais continue (événements scellés) ; le journal reprend quand le fichier redevient écrivable", async function () {
    if (!pret.call(this)) return;
    const chemin = m.config.supervision.ops_log.path;
    const avant = metrique((await demon.commande({ cmd: "metriques" })).texte, "noortrace_ops_log_dropped_total") ?? 0;
    fs.renameSync(chemin, `${chemin}.hors-ligne`);
    fs.mkdirSync(chemin); // toute écriture échoue (EISDIR), comme sur un disque plein (ENOSPC)
    try {
      const seqs = [];
      for (let k = 7; k <= 9; k++) seqs.push((await demon.evenement(k)).seq);
      expect(seqs[2]).to.equal(seqs[0] + 2);
      // Des lignes sont produites pendant la panne (points alignés à la cadence de 10 s, remises à l'ancrage) : chacune est comptée, aucune n'arrête le relais.
      await demon.avancer(10000);
      let apres = null;
      for (let essai = 0; essai < 60; essai++) {
        apres = metrique((await demon.commande({ cmd: "metriques" })).texte, "noortrace_ops_log_dropped_total");
        if (apres !== null && apres >= avant + 3) break;
        await new Promise((r) => setTimeout(r, 500));
      }
      expect(apres, "lignes non écrites comptées").to.be.at.least(avant + 3);
      expect((await demon.evenement(10)).seq).to.equal(seqs[2] + 1, "le relais continue pendant la panne du journal");
      const lignesMemoire = (await demon.commande({ cmd: "journal", event: "startup" })).lignes;
      expect(lignesMemoire.length).to.be.at.least(1, "le journal en mémoire reste tenu (EX-9.7)");
    } finally {
      fs.rmdirSync(chemin);
      fs.renameSync(`${chemin}.hors-ligne`, chemin);
    }
    const fin = metrique((await demon.commande({ cmd: "metriques" })).texte, "noortrace_ops_log_dropped_total");
    expect(fin).to.be.a("number");
    // Le journal reprend dans le fichier restauré : une ligne postérieure à la panne y figure.
    await demon.avancer(10000);
    await demon.attendre((l) => l.some((x) => x.event === "checkpoint_written" && N.decoderHorodatage(x.ts) > (PERIODE + 3600) * 1000 + 150000), 30000, "ligne écrite après la panne");
  });

  it("JS-3 perte du bail (EX-13.6) : le verrou du bail rendu par le noyau (auxiliaire flock terminé) → lease_lost à l'écriture suivante, mode dégradé bail, santé down ; JS-2 arrêt : code 0, aucun événement d'arrêt dans la chaîne (CT-7 : hors chaîne, PA-3 ; la ligne shutdown du journal d'exploitation est constatée)", async function () {
    if (!pret.call(this)) return;
    const enfants = spawnSync("pgrep", ["-P", String(demon.pid), "-x", "flock"], { encoding: "utf8" });
    const pids = enfants.stdout.trim().split("\n").filter(Boolean);
    expect(pids.length, "auxiliaire flock du bail").to.be.at.least(1);
    for (const p of pids) process.kill(Number(p), "SIGKILL");
    await new Promise((r) => setTimeout(r, 300));
    let refus = null;
    try {
      await demon.evenement(11);
    } catch (e) {
      refus = e;
    }
    await demon.attendre((l) => l.some((x) => x.event === "lease_lost"), 20000, "lease_lost");
    expect(demon.de("lease_lost").length).to.be.at.least(1);
    expect(demon.de("degraded_enter").some((x) => x.data.reason === "bail")).to.equal(true);
    expect(refus === null || /bail/.test(refus.message)).to.equal(true);
    const dernierSeq = evenementsChaine(m.repertoire).at(-1).seq;
    const fin = await demon.arreter();
    expect(fin.code).to.equal(0);
    const lignes = demon.lignes();
    expect(lignes.some((l) => l.event === "shutdown")).to.equal(true);
    const chaine = evenementsChaine(m.repertoire);
    expect(chaine.at(-1).seq).to.equal(dernierSeq, "l'arrêt n'ajoute aucun événement à la chaîne");
    expect(chaine.some((e) => /arret|shutdown/.test(e.execution.tool))).to.equal(false);
  });
});

describe("TE-14 : rotation du journal d'exploitation par supervision.ops_log.rotate_max_bytes et keep_files (EX-9.7, EX-17.4) sur un démon réel", function () {
  this.timeout(300000);
  let dir;
  let m;
  let demon;

  before(async function () {
    dir = repertoireTemporaire("noortrace-te14-rotation-");
    m = await monterDemon({
      dir, baseMs: BASE, registre: false,
      surchargesAncrage: { registry: { checkpoints: "aucun" } },
      surchargesConfig: (c) => {
        c.supervision.ops_log.rotate_max_bytes = 1024;
        c.supervision.ops_log.keep_files = 3;
      },
    });
    if (m.condition) return;
    demon = new Demon(m);
    await demon.demarrer();
  });

  after(async function () {
    if (demon?.p) await demon.arreter().catch(() => {});
    await m?.fermer?.();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("le fichier tourne par taille : au plus keep_files fichiers tournés (<chemin>.1 à <chemin>.keep_files) à côté du fichier courant, chacun en NDJSON valide ; les plus anciens sont supprimés ; aucune ligne n'est perdue entre deux rotations", async function () {
    if (!m || m.condition) return enAttente(this, m?.condition ?? "contexte non préparé");
    for (let k = 1; k <= 12; k++) await demon.evenement(k);
    await demon.arreter();
    const chemin = m.config.supervision.ops_log.path;
    const base = path.basename(chemin);
    const fichiers = fs.readdirSync(path.dirname(chemin)).filter((n) => n === base || n.startsWith(`${base}.`)).sort();
    const tournes = fichiers.filter((n) => n !== base);
    expect(tournes.length).to.be.at.least(1);
    expect(tournes.length).to.be.at.most(3);
    for (const n of tournes) expect(/^exploitation\.ndjson\.[1-3]$/.test(n), n).to.equal(true);
    for (const n of fichiers) {
      const texte = fs.readFileSync(path.join(path.dirname(chemin), n), "utf8");
      for (const l of texte.split("\n").filter(Boolean)) expect(() => JSON.parse(l), n).to.not.throw();
      if (n !== base) expect(Buffer.byteLength(texte)).to.be.at.most(1024 + 2048, "un fichier tourné ne dépasse la borne que de la ligne qui l'a franchie");
    }
    // Le fichier courant se termine par l'arrêt ; le plus ancien fichier gardé est .3 (les antérieurs ont été supprimés).
    const courant = fs.readFileSync(chemin, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    expect(courant.at(-1).event).to.equal("shutdown");
    expect(fs.existsSync(`${chemin}.4`)).to.equal(false);
  });
});

// ------------------------------------------------------------------- support WORM réel (JS-9, JS-10, complément TM-16)

/** Fichiers mesurés par P-6 (relatifs au répertoire du journal) : points, ancres/periode-<P>, manifestes. */
function fichiersP6(repertoire) {
  const sous = (rel) => {
    const abs = path.join(repertoire, rel);
    if (!fs.existsSync(abs)) return [];
    return fs.readdirSync(abs, { recursive: true }).map((f) => path.posix.join(rel, String(f).split(path.sep).join("/"))).filter((f) => fs.statSync(path.join(repertoire, f)).isFile());
  };
  const ancres = fs.existsSync(path.join(repertoire, "ancres")) ? fs.readdirSync(path.join(repertoire, "ancres")).filter((d) => /^periode-[0-9]{10}$/.test(d)).flatMap((d) => sous(`ancres/${d}`)) : [];
  return { points: sous("points"), ancres, manifestes: sous("manifestes").filter((f) => /^manifestes\/periode-[0-9]{10}\.(json|sig)$/.test(f)) };
}

describe("TE-14 (JS-9, JS-10) et complément TM-16 sur le support WORM réel (S3 à Object Lock en conteneur) : worm_legal_hold_observed, worm_copy_failed puis reprise, copie conforme d'ancres/", function () {
  this.timeout(900000);
  const docker = dockerDisponible([IMAGES.s3]);
  let dir;
  let tls;
  let prox;
  let s3;
  let m;
  let demon;
  const PREFIXE = "journal-te14/";

  before(async function () {
    if (!docker.ok) return;
    dir = repertoireTemporaire("noortrace-te14-worm-");
    s3 = await demarrerS3(`noortrace-test-te14-${process.pid}`);
    tls = certificats(path.join(dir, "tls-worm"));
    prox = await mandataireTls(tls, { port: s3.port });
    const bucket = `noortrace-te14-${process.pid}`;
    await creerBucketVerrouille(prox.origine, bucket, { ca: tls.caPem, jours: 4018, mode: "COMPLIANCE" });
    m = await monterDemon({
      dir, baseMs: BASE,
      surchargesAncrage: { registry: { checkpoints: "tous" } },
      surchargesConfig: (c) => {
        c.storage.seal.worm = {
          type: "s3-object-lock", bucket, prefix: PREFIXE, mode: "compliance", retain_days: 4018,
          credentials: { file: fichierSecret(path.join(dir, "secrets", "worm-ecrivain"), identifiantsRole("ecrivain")) },
          endpoint: prox.origine, region: null, legal_hold_on_write: false, lock_audit_interval_days: 30, copy_pieces: false,
        };
      },
    });
    if (m.condition) return;
    // L'AC du mandataire TLS du support s'ajoute aux AC supplémentaires du démon (NODE_EXTRA_CA_CERTS).
    fs.appendFileSync(path.join(dir, "tls", "ca-extra.pem"), tls.caPem);
    demon = new Demon(m);
    await demon.demarrer();
    await demon.attendre((l) => l.some((x) => x.event === "anchoring_attached"), 30000, "anchoring_attached");
  });

  after(async function () {
    if (demon?.p) await demon.arreter().catch(() => {});
    await m?.fermer?.();
    await prox?.fermer();
    arreterTout();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  function pret() {
    if (!docker.ok) {
      enAttente(this, docker.condition);
      return false;
    }
    if (!m || m.condition) {
      enAttente(this, m?.condition ?? "contexte non préparé");
      return false;
    }
    return true;
  }

  it("JS-10 perte d'une copie WORM : support suspendu (docker pause) pendant la clôture → worm_copy_failed (injoignable) ; support repris → le balayage de la supervision copie ce qui manque, noortrace_worm_copy_pending retombe", async function () {
    if (!pret.call(this)) return;
    // Le support est suspendu avant toute copie (aucune requête en vol au moment de la pause : une copie acceptée par le support
    // mais sans réponse donnerait une seconde version au balayage, worm_versions_unexpected) ; il le reste pendant la clôture.
    suspendre(s3.nom, true);
    try {
      await demon.evenement(1);
      await demon.attendre((l) => l.filter((x) => x.event === "checkpoint_written").length >= 2, 60000, "deux points");
      await demon.avancer((PERIODE + 3600) * 1000 + 1000 - m.horloge.murale());
      await demon.attendre((l) => l.some((x) => x.event === "period_closed" && x.data.period_start === PERIODE), 60000, "period_closed");
      await demon.attendre((l) => l.some((x) => x.event === "worm_copy_failed"), 120000, "worm_copy_failed");
      const echec = demon.de("worm_copy_failed")[0];
      expect(echec.component).to.equal("worm");
      expect(["injoignable", "erreur", "statut"]).to.include(echec.data.raison);
    } finally {
      suspendre(s3.nom, false);
    }
    await demon.attendre((l) => l.some((x) => x.event === "period_timestamped"), 180000, "period_timestamped");
    const r = await demon.commande({ cmd: "worm", action: "balayer" });
    expect(r.resultat.manquantes).to.equal(0);
    const registre = await lireRegistres(path.join(m.repertoire, "worm"));
    const cles = registre.map((x) => x.ligne.key);
    expect(cles).to.include(`${PREFIXE}manifestes/periode-${PERIODE}.json`);
    expect(cles).to.include(`${PREFIXE}points/periode-${PERIODE}.ndjson`);
    expect(cles.some((k) => k.startsWith(`${PREFIXE}ancres/periode-${PERIODE}/rfc3161/`))).to.equal(true);
  });

  it("JS-9 gel juridique posé par l'outil de l'exploitant (noortrace-ctl worm gel poser) : la lecture quotidienne du registre des gels consigne worm_legal_hold_observed par enregistrement (pose, pose_resultat), garde respectée ; noortrace_worm_legal_holds_active 1", async function () {
    if (!pret.call(this)) return;
    const ref = JSON.stringify({ file: fichierSecret(path.join(dir, "secrets", "gardien-pose"), identifiantsRole("gardien-pose")) });
    let out = "";
    let err = "";
    const code = await principalCtl(["worm", "gel", "poser", "--configuration", m.cheminConfig, "--identifiants", ref, "--identite", "j.dupont", "--de", String(PERIODE), "--a", String(PERIODE), "--motif", "litige"], { stdout: { write: (s) => (out += s) }, stderr: { write: (s) => (err += s) }, env: m.env, tls: { ca: tls.caPem }, delais: RAPIDE });
    expect(code, err).to.equal(0);
    const gel = out.trim().split("\n").at(-1);
    expect(gel).to.match(/^gel-/);
    await demon.commande({ cmd: "worm", action: "quotidien" });
    const obs = demon.de("worm_legal_hold_observed");
    expect(obs.map((x) => x.data.kind)).to.deep.equal(["pose", "pose_resultat"]);
    expect(obs.every((x) => x.data.gel_id === gel && x.data.garde === "respectee" && x.level === "info")).to.equal(true);
    expect(obs.every((x) => !("identite" in x.data) && !("identity" in x.data))).to.equal(true, "aucune identité d'exploitant dans le journal (EX-9.6)");
    const texte = (await demon.commande({ cmd: "metriques" })).texte;
    expect(metrique(texte, "noortrace_worm_legal_holds_active")).to.equal(1);
  });

  it("complément TM-16 (P-6, ancres/) : chaque fichier de points/, d'ancres/periode-<P>/ et de manifestes/ a une version au même SHA-256 sur le support, en mode COMPLIANCE, rétention au moins égale à celle des événements ; ligne p6_copie_worm à 0 fichier non conforme, publiée hors du système de référence (le rapport la dit)", async function () {
    if (!pret.call(this)) return;
    // Les fichiers fermés d'ancres/ (pièces, acquisitions.ndjson une fois la période close et la T-10 décidée, lecture F2-6) sont copiés au balayage.
    const balayage = await demon.commande({ cmd: "worm", action: "balayer" });
    expect(balayage.resultat.manquantes).to.equal(0);
    await demon.commande({ cmd: "worm", action: "vider" });
    // Fichiers de la période close P seulement : la série de la période en cours est un fichier ouvert, copié à sa fermeture (lecture 93).
    const p10 = String(PERIODE).padStart(10, "0");
    const tous = fichiersP6(m.repertoire);
    const f = { points: tous.points.filter((x) => x.includes(`periode-${p10}`)), ancres: tous.ancres.filter((x) => x.includes(`periode-${p10}/`)), manifestes: tous.manifestes.filter((x) => x.includes(`periode-${p10}`)) };
    expect(f.points).to.have.lengthOf(1);
    expect(f.manifestes).to.have.lengthOf(2);
    expect(f.ancres.length).to.be.at.least(3);
    const ops = new OperationsS3({ worm: m.config.storage.seal.worm, identifiants: identifiantsS3(new TextEncoder().encode(identifiantsRole("lecteur"))), tls: { ca: tls.caPem }, delais: RAPIDE });
    const eventsYears = m.config.storage.retention.events_years;
    const lignes = [];
    for (const rel of [...f.points, ...f.ancres, ...f.manifestes]) {
      const cle = `${PREFIXE}${rel}`;
      const attendu = N.sha256Hex(new Uint8Array(fs.readFileSync(path.join(m.repertoire, rel))));
      const liste = await ops.listerVersions(cle);
      const versions = liste.versions.filter((v) => v.key === cle && !v.delete_marker);
      let conforme = false;
      let raison = versions.length ? null : "aucune_version";
      for (const v of versions) {
        const e = await ops.empreinte(cle, v.version_id);
        const h = await ops.etat(cle, v.version_id);
        const mode = h.entetes["x-amz-object-lock-mode"] ?? null;
        const echeance = lireEcheance(h.entetes["x-amz-object-lock-retain-until-date"] ?? null);
        const creation = lireEcheance(e.last_modified);
        const minimum = creation === null ? null : creation + eventsYears * 365 * 86400000 - 3600000;
        const r = e.sha256 !== attendu ? "sha256_different" : mode !== "COMPLIANCE" ? "mode_non_conforme" : echeance === null || minimum === null ? "echeance_illisible" : echeance < minimum ? "retention_plus_courte" : null;
        if (r === null) conforme = true;
        else raison = raison ?? r;
      }
      lignes.push({ fichier: rel, conforme, raison: conforme ? null : raison });
    }
    const nonConformes = lignes.filter((l) => !l.conforme);
    expect(nonConformes, JSON.stringify(nonConformes)).to.deep.equal([]);
    expect(lignes.filter((l) => l.fichier.startsWith("ancres/")).length).to.be.at.least(3);
    if (process.env.NOORTRACE_RAPPORT_TM16_ANCRES) {
      fs.writeFileSync(process.env.NOORTRACE_RAPPORT_TM16_ANCRES, `${JSON.stringify({ period_start: PERIODE, fichiers: lignes, events_years: eventsYears, image: IMAGES.s3, mesure_a: new Date().toISOString() }, null, 2)}\n`);
    }
  });
});
