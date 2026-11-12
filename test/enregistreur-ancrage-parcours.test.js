// TE-12 de CT-9 (CT-5 §9, §10 ; CT-6 §13.4 ; CT-2 §12.10, §14.2, §15) : un
// démon `noortrace` réel (processus enfant, assemblage de src/cli.mjs) dont
// `anchoring.ancrage` désigne un document `ancrage-v0` : serveur RFC 3161
// interne du lot E pour les points (HTTP local), un second serveur interne
// comme `principal` en TLS mutuel avec un `qualified` d'exemple, calendriers
// OpenTimestamps factices en TLS, nœud noorcore factice du lot D en JSON-RPC
// (variante hors réseau public) ; horloge hybride à cadence réduite admise par
// le schéma (`checkpoint_interval_s` 10, `interval_s` 60). Des échanges
// factices produisent des événements, des points de contrôle, des échéances et
// la clôture ; le dossier d'un événement est exporté par l'exportateur du
// composant (CT-5 §10) puis vérifié hors ligne par le vérificateur JavaScript
// de référence (`node scripts/verify/dossier.mjs`, boîte noire) et par le
// binaire Go de CT-6 avec le même fichier d'ancres écrit sous os.tmpdir()
// (autorités internes non qualifiées, `bitcoin` regtest des calendriers
// factices, `registry` du nœud factice) : trois ancres sur la racine (jeton du
// manifeste, preuve `.ots`, ancre au registre), point couvrant contresigné et
// ancré, K-1 à K-9, contrôles 1 à 8 réussis ou non exécutés pour une raison
// admise (le contrôle 5 est non exécuté tant que la preuve est en attente,
// réussi quand les calendriers rendent le chemin complet), même verdict et
// même énoncé entre les deux vérificateurs ; `noortrace-ctl ancrage` et
// `noortrace-ctl reload` ; arrêt propre. La variante sur le réseau de
// développement réel (quatre validateurs noorcore, client inscrit par le
// parcours de référence `npm run e2e:registre`, boîte noire) est en attente,
// condition nommée dans le titre, quand le réseau n'est pas debout.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import { spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";
import { DepotAncres, lireJeton } from "@noortrace/ancrage/rfc3161";
import { DepotOts, etatPreuve } from "@noortrace/ancrage/ots";
import { lireFiles, ETATS_FINAUX } from "@noortrace/ancrage/planificateur";
import { principalCtlDemon } from "@noortrace/enregistreur";
import {
  monterDemon, Demon, repertoireTemporaire, fichierAncres, pointDeControleBitcoin, verifierJs, verifierGo, binaireGo, statuts, demandeCloture, fichierTemporaire,
  portLibre, enAttente, RACINE, lireParcours, inscrireJournal, monterDemonReseauReel, demandeClotureParcours, sansReseau, POINTS_RESEAU_DEV, EVM_RESEAU_DEV,
} from "./fixtures/enregistreur-ancrage/outils.mjs";

const BASE = Date.UTC(2026, 10, 5, 7, 0, 2); // 2026-11-05T07:00:02Z, période [07:00, 08:00)
const PERIODE = Math.floor(BASE / 3600000) * 3600;

const getJson = (port, chemin) => new Promise((res, rej) => {
  http.get({ host: "127.0.0.1", port, path: chemin }, (r) => {
    let t = "";
    r.on("data", (d) => (t += d));
    r.on("end", () => res({ statut: r.statusCode, corps: t }));
  }).on("error", rej);
});

/** Exécute `noortrace-ctl` en cours de processus (même utilisateur, /proc réel) ; rend le code et la sortie. */
async function ctl(args) {
  let out = "";
  let err = "";
  const code = await principalCtlDemon(args, { stdout: { write: (s) => (out += s) }, stderr: { write: (s) => (err += s) } });
  return { code, out, err };
}

describe("enregistreur + ancrage (lot F2), TE-12 hors réseau public : démon réel, trois ancres sur la racine, dossier vérifié hors ligne par les deux vérificateurs", function () {
  this.timeout(900000);
  let dir;
  let m;
  let demon;
  let portSante;
  const seqs = [];
  const exports = {};
  let ancres;
  let entetes;

  before(async function () {
    dir = repertoireTemporaire("noortrace-f2-te12-");
    portSante = await portLibre();
    m = await monterDemon({
      dir, baseMs: BASE,
      surchargesAncrage: { registry: { checkpoints: "tous" } },
      surchargesConfig: (c) => {
        c.supervision.health_listen = `127.0.0.1:${portSante}`;
        c.supervision.metrics = true;
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

  function pret() {
    if (!m || m.condition) {
      enAttente(this, m?.condition ?? "contexte non préparé");
      return false;
    }
    return true;
  }

  it("le démon démarre avec anchoring.ancrage : document validé (AN-1), secrets résolus (CT-2 §15.2), clé de chaîne de classe D, composant attaché (anchoring_attached, file sous le répertoire du journal), /healthz ok, métriques d'EX-8.15 exposées avec celles du cœur", async function () {
    if (!pret.call(this)) return;
    await demon.attendre((l) => l.some((x) => x.event === "anchoring_attached"), 30000, "anchoring_attached");
    const a = demon.de("anchoring_attached")[0];
    expect(a.component).to.equal("ancrage");
    expect(a.data).to.include({ profile: "developpement", registry: true, providers: 2, queue_in_journal: true });
    expect(demon.de("anchoring_started")).to.have.lengthOf(1);
    expect(demon.de("anchoring_queue_rebuilt")[0].data).to.include({ recreated: 0 });
    expect(demon.de("startup")).to.have.lengthOf(1);
    const sante = await getJson(portSante, "/healthz");
    expect(sante.statut).to.equal(200);
    expect(JSON.parse(sante.corps)).to.deep.equal({ status: "ok" });
    const metriques = await getJson(portSante, "/metrics");
    expect(metriques.corps).to.include("# TYPE noortrace_events_total counter");
    expect(metriques.corps).to.include("# TYPE noortrace_anchoring_queue_entries gauge");
    expect(metriques.corps).to.match(/noortrace_anchor_pending\{anchor="registre"\} 0/);
  });

  it("événements et points à la cadence de 10 s : chaque point est écrit dans la série, remis au composant et ancré au registre (registry.checkpoints tous) ; la remise ne retarde pas la production des points (EX-4.12)", async function () {
    if (!pret.call(this)) return;
    const e1 = await demon.evenement(1);
    seqs.push(e1.seq);
    await demon.attendre((l) => l.filter((x) => x.event === "checkpoint_written").length >= 2 && l.filter((x) => x.event === "registry_included").length >= 1, 60000, "deux points écrits et une ancre incluse");
    const points = demon.de("checkpoint_written");
    expect(points.every((p) => p.component === "cloture" && p.data.period_start === PERIODE)).to.equal(true);
    expect(demon.de("anchor_pending")).to.deep.equal([]);
    expect(demon.de("anchor_admission_refused")).to.deep.equal([]);
    // La série sur disque porte les mêmes points que le journal en compte, chaînés.
    const serie = fs.readFileSync(path.join(m.repertoire, "points", `periode-${PERIODE}.ndjson`), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    expect(serie.length).to.be.at.least(2);
    for (let k = 1; k < serie.length; k++) expect(serie[k].prev_checkpoint_hash).to.equal(N.hacherPoint(serie[k - 1]));
  });

  it("saut à 07:29:51 : un événement juste avant l'échéance médiane D_30 ; le point de 07:30:00 l'engage (premier point après lui, EX-4.3), est ancré au registre, contresigné par le serveur interne (jeton_point, checkpoint_countersigned) et soumis aux calendriers (ots_point, mi_periode)", async function () {
    if (!pret.call(this)) return;
    // Après le saut, l'instant aligné de 07:29:50 est manqué (tolérance de 1 s, EX-12.24) : le point suivant est celui de 07:30:00,
    // premier point de checkpoint_ts ≥ D_29 et ≥ D_30 ; il porte le jeton, la preuve de mi-période et l'ancre au registre.
    const cible = Date.UTC(2026, 10, 5, 7, 29, 51, 300);
    await demon.avancer(cible - m.horloge.murale());
    const e2 = await demon.evenement(2);
    seqs.push(e2.seq);
    expect(N.decoderHorodatage(e2.ts)).to.be.at.least(cible - 2000);
    // seq 1 est l'événement de politique du démarrage (EX-9.8) : le point de 07:30:00 engage trois feuilles.
    await demon.attendre((l) => l.some((x) => x.event === "checkpoint_countersigned" && x.data.tree_size === 3), 90000, "point de taille 3 contresigné");
    const c = demon.de("checkpoint_countersigned").find((x) => x.data.tree_size === 3);
    expect(c.data.provider).to.equal("tsa-interne");
    expect(c.data.d_point_s + c.data.d_attente_s + c.data.d_releve_s + c.data.d_tsa_s).to.equal(c.data.d_jeton_s);
    await demon.attendre((l) => l.some((x) => x.event === "ots_submitted" && x.data.request_id?.startsWith("ots_point")), 60000, "ots_point soumis");
    expect(demon.de("ots_submitted").find((x) => x.data.request_id.startsWith("ots_point")).data).to.include({ calendars_answered: 2, attestation: "en_attente" });
  });

  it("clôture de la période : manifeste et signature écrits, trois ancres sur la racine (ancre au registre incluse et capturée, jeton qualifié du principal en TLS mutuel, preuve OpenTimestamps soumise) ; la clôture submitPeriod attend la demande signée des approbateurs (period_close_delegated) puis est relayée dès qu'elle est déposée (period_submitted)", async function () {
    if (!pret.call(this)) return;
    await demon.avancer(Date.UTC(2026, 10, 5, 8, 0, 1) - m.horloge.murale());
    await demon.attendre((l) => l.some((x) => x.event === "period_closed"), 60000, "period_closed");
    await demon.attendre((l) => l.some((x) => x.event === "period_timestamped") && l.some((x) => x.event === "period_close_delegated") && l.filter((x) => x.event === "ots_submitted").length >= 2, 120000, "ancres de la période");
    expect(demon.de("period_timestamped")[0].data.provider).to.equal("qtsa-principal");
    expect(demon.de("period_close_delegated").at(-1).data.reason).to.equal("signatures_en_attente");
    const manifestes = fs.readdirSync(path.join(m.repertoire, "manifestes"));
    expect(manifestes).to.include.members([`periode-${PERIODE}.json`, `periode-${PERIODE}.sig`]);
    const manifeste = JSON.parse(fs.readFileSync(path.join(m.repertoire, "manifestes", `periode-${PERIODE}.json`), "utf8"));
    expect(manifeste.count).to.equal(3);
    expect(manifeste.first_seq).to.equal(1);
    // Demande de clôture signée au seuil par les approbateurs d'essai (CT-4 §8.2 pas 4), déposée dans le répertoire du registre du journal.
    const demande = demandeCloture({ manifeste, registre: m.registre, preparedAt: "2026-11-05T08:00:30.000Z" });
    expect(R.verifierDemande(demande, { complete: true }).resultat).to.equal("valide");
    fs.writeFileSync(path.join(m.repertoire, "registre", `demande-cloture-${N.hacherManifeste(manifeste)}.json`), JSON.stringify(demande, null, 2));
    await demon.avancer(61000);
    await demon.attendre((l) => l.some((x) => x.event === "period_submitted"), 90000, "period_submitted");
    const captures = fs.readdirSync(path.join(m.repertoire, "registre")).filter((n) => n.startsWith("capture-"));
    expect(captures.some((n) => n.endsWith("-cloture.json"))).to.equal(true);
    expect(captures.filter((n) => n.endsWith("-ancre.json")).length).to.be.at.least(3);
    // Les captures passent CP-2 à CP-6 hors ligne.
    for (const nom of captures) {
      const index = JSON.parse(fs.readFileSync(path.join(m.repertoire, "registre", nom), "utf8"));
      expect(R.verifierCapture({ fichiers: path.join(m.repertoire, "registre"), index, jeux: m.registre.manifeste.validator_sets[0], bftChainId: m.registre.bftChainId }).premierEchec, nom).to.equal(null);
    }
    // L'ancre de la période est connue du registre sous la clé de chaîne.
    const empreinte = N.empreinteAncre(manifeste.org_id, manifeste.journal_id, N.hacherManifeste(manifeste));
    expect(m.registre.noeud.ancres.get(empreinte)?.issuer).to.equal(m.registre.cleChaine.adresse());
    // EX-5.14 : jeton promu du manifeste par le principal, qualifié ; jeton du point par l'interne.
    const depot = DepotAncres.ouvrir({ racine: m.config.storage.root, orgId: m.config.recorder.org_id, journalId: m.config.recorder.journal_id });
    const promuManifeste = depot.promu("manifeste", PERIODE);
    expect(promuManifeste.provider_id).to.equal("qtsa-principal");
    expect(promuManifeste.qualified).to.not.equal(null);
    expect(promuManifeste.promoted).to.equal(true);
  });

  it("export du dossier de l'événement avant la mise à niveau : treize parties, point couvrant de 07:30:00 contresigné et ancré, trois ancres embarquées, parties du registre avec ancre_point_de_controle ; vérificateur JavaScript : valide, K-1 à K-8 réussies, K-9 et contrôle 5 non exécutés (preuve en attente), même verdict et même énoncé par le binaire Go", async function () {
    if (!pret.call(this)) return;
    const seq = seqs[1];
    const destination = path.join(dir, "dossier-avant");
    const r = await demon.exporter(seq, destination);
    const parts = Object.fromEntries(r.parts.map((p) => [p.name, p]));
    for (const nom of ["evenement", "voisins", "chemin", "manifeste", "manifeste_sig", "cles", "jeton_rfc3161", "preuve_ots", "registre", "certificat_commit", "validateurs", "points_de_controle"]) expect(parts[nom].present, nom).to.equal(true);
    expect(parts.approbations.reason).to.equal("aucune approbation liée");
    const partie = JSON.parse(fs.readFileSync(path.join(destination, "points-de-controle.json"), "utf8"));
    expect(partie.checkpoint.checkpoint_ts.startsWith("2026-11-05T07:30:00."), partie.checkpoint.checkpoint_ts).to.equal(true);
    expect(partie.checkpoint.tree_size).to.equal(3);
    expect(JSON.parse(fs.readFileSync(path.join(destination, "chemin.json"), "utf8")).leaf_index).to.equal(2);
    expect(partie.anchors.rfc3161).to.not.equal(null);
    expect(partie.anchors.registry).to.include({ chain_id: 2124, contract: m.registre.contrats.attestation_registry, doc_type: R.DOC_TYPE_POINT_DE_CONTROLE });
    expect(partie.anchors.ots).to.not.equal(null);
    expect(etatPreuve(N.decoderBase64Canonique(partie.anchors.ots.proof))).to.equal("en_attente");
    const registre = JSON.parse(fs.readFileSync(path.join(destination, "registre.json"), "utf8"));
    expect(registre.entries.map((e) => e.role).sort()).to.deep.equal(["ancre", "ancre_point_de_controle", "cloture"]);
    // EX-6.8 : entetes-bitcoin.json n'est écrit qu'une fois toutes les preuves de la période complètes ; avant, rien à côté du dossier.
    expect(fs.existsSync(path.join(destination, "entetes-bitcoin.json"))).to.equal(false);
    // AN-50 : jeton-rfc3161.der et preuve.ots sont les pièces promues du dépôt, octet pour octet.
    const depot = DepotAncres.ouvrir({ racine: m.config.storage.root, orgId: m.config.recorder.org_id, journalId: m.config.recorder.journal_id });
    const depotOts = DepotOts.ouvrir({ racine: m.config.storage.root, orgId: m.config.recorder.org_id, journalId: m.config.recorder.journal_id });
    const promu = depot.promu("manifeste", PERIODE);
    expect(N.sha256Hex(new Uint8Array(fs.readFileSync(path.join(destination, "jeton-rfc3161.der"))))).to.equal(promu.token_sha256);
    expect(Buffer.compare(fs.readFileSync(path.join(destination, "preuve.ots")), Buffer.from(depotOts.derniere({ periodStart: PERIODE, objet: "manifeste" }).octets))).to.equal(0);
    // Fichier d'ancres du réviseur (os.tmpdir()) : autorité interne non qualifiée, bitcoin regtest, registre du décor.
    ancres = fichierTemporaire("ancres-essai.json");
    entetes = null;
    fichierAncres({ chemin: ancres, montage: m, bitcoin: pointDeControleBitcoin(m, 1000) });
    const js = verifierJs(destination, { ancres, entetes });
    expect(js.code, js.stderr).to.equal(0);
    expect(js.rapport.verdict).to.equal("valide");
    const s = statuts(js.rapport);
    for (const k of ["K-1", "K-2", "K-3", "K-4", "K-5", "K-6", "K-7", "K-8"]) expect(s[k], k).to.equal("reussi");
    expect(s["K-9"]).to.equal("non_execute");
    expect(js.rapport.checks.find((c) => c.id === "K-9").reason).to.equal("partie_absente");
    const controles = Object.fromEntries(js.rapport.controls.map((c) => [c.number, c]));
    for (const n of [1, 2, 3, 4, 6, 8]) expect(controles[n].status, `contrôle ${n}`).to.equal("reussi");
    expect(controles[5].status).to.equal("non_execute");
    expect(controles[5].reason).to.equal("partie_absente");
    expect(controles[7].status).to.equal("non_execute");
    expect(js.rapport.statement.fr).to.include("ancré au registre noortrace-2124-dev");
    expect(js.rapport.blocking_unexecuted).to.deep.equal([]);
    // Étape 6 : chaque autorité d'essai a son propre nom d'émetteur ; les CRL du fichier d'ancres sont valides et aucune n'est écartée (AV-T-3).
    expect(js.rapport.warnings.filter((w) => w.id === "AV-T-3"), JSON.stringify(js.rapport.warnings)).to.deep.equal([]);
    exports.avant = { destination, js };
    const bin = binaireGo();
    if (!bin) return enAttente(this, "vérificateur Go de CT-6 (NOORTRACE_VERIFIER_BIN, NOORTRACE_GO_BIN ou verificateur/dist/noortrace-verifier-linux-amd64) : vérification JavaScript faite, vérification Go non faite");
    const go = verifierGo(destination, { ancres, entetes, bin });
    expect(go.code).to.equal(0);
    expect(go.rapport.verdict).to.equal("valide");
    expect(statuts(go.rapport)).to.deep.equal(s);
    expect(go.rapport.statement.fr).to.equal(js.rapport.statement.fr);
    expect(go.rapport.statement.en).to.equal(js.rapport.statement.en);
    expect(go.rapport.warnings.filter((w) => w.id === "AV-T-3"), JSON.stringify(go.rapport.warnings)).to.deep.equal([]);
  });

  it("mise à niveau OpenTimestamps (EX-6.6, EX-6.8) : chemin complet et en-têtes regtest, ots_complete pour la période et le point, entetes-bitcoin.json écrit ; réexport dû (EX-10.5, AN-53) ; nouveau dossier à generated_at postérieur : K-9 et contrôle 5 réussis, même verdict et même énoncé par les deux vérificateurs ; le dossier antérieur est inchangé", async function () {
    if (!pret.call(this)) return;
    const avant = fs.readFileSync(path.join(exports.avant.destination, "dossier.json"));
    m.calendriers.completer(1010);
    await demon.avancer(61000);
    await demon.attendre((l) => l.filter((x) => x.event === "ots_complete").length >= 2 && l.some((x) => x.event === "bitcoin_headers_written"), 120000, "ots_complete et entetes-bitcoin.json");
    expect(demon.de("ots_complete").every((l) => l.data.reexport === true)).to.equal(true);
    const dus = (await demon.commande({ cmd: "reexports" })).dus;
    expect(dus).to.have.lengthOf(1);
    expect(dus[0].seq).to.equal(seqs[1]);
    expect(dus[0].raisons).to.include.members(["ots_periode", "ots_point", "entetes_bitcoin"]);
    const destination = path.join(dir, "dossier-apres");
    await demon.exporter(seqs[1], destination);
    const apres = JSON.parse(fs.readFileSync(path.join(destination, "dossier.json"), "utf8"));
    expect(N.decoderHorodatage(apres.generated_at)).to.be.greaterThan(N.decoderHorodatage(JSON.parse(avant.toString()).generated_at));
    expect(Buffer.compare(fs.readFileSync(path.join(exports.avant.destination, "dossier.json")), avant)).to.equal(0);
    expect((await demon.commande({ cmd: "reexports" })).dus).to.deep.equal([]);
    entetes = path.join(destination, "entetes-bitcoin.json");
    const js = verifierJs(destination, { ancres, entetes });
    expect(js.code, js.stderr).to.equal(0);
    const s = statuts(js.rapport);
    for (const k of ["K-1", "K-2", "K-3", "K-4", "K-5", "K-6", "K-7", "K-8", "K-9"]) expect(s[k], k).to.equal("reussi");
    const controles = Object.fromEntries(js.rapport.controls.map((c) => [c.number, c]));
    for (const n of [1, 2, 3, 4, 5, 6, 8]) expect(controles[n].status, `contrôle ${n}`).to.equal("reussi");
    expect(controles[7].status).to.equal("non_execute");
    expect(js.rapport.statement.fr).to.include("antérieur à la création du bloc Bitcoin");
    expect(js.rapport.facts.checkpoint.registry.inclusion).to.equal("prouvee");
    exports.apres = { destination, js };
    // Lignes du journal : aucune ne porte un jeton, une pièce ni un secret (AN-43) ; le secret TLS n'est ni dans la file ni dans acquisitions.ndjson.
    const secret = fs.readFileSync(path.join(dir, "secrets", "client-tls.pem"), "utf8").split("\n")[1];
    const fichiersFile = fs.readdirSync(path.join(m.repertoire, "ancres", "file")).filter((n) => /^file-[0-9]+\.ndjson$/.test(n));
    expect(fichiersFile).to.have.lengthOf(1);
    const textes = [JSON.stringify(demon.lignes()), fs.readFileSync(path.join(m.repertoire, "ancres", "file", fichiersFile[0]), "utf8"), fs.readFileSync(path.join(m.repertoire, "ancres", `periode-${PERIODE}`, "acquisitions.ndjson"), "utf8")];
    for (const t of textes) {
      expect(t.includes(secret)).to.equal(false);
      expect(t.toLowerCase()).to.not.include("private key");
    }
    const bin = binaireGo();
    if (!bin) return enAttente(this, "vérificateur Go de CT-6 (NOORTRACE_VERIFIER_BIN, NOORTRACE_GO_BIN ou verificateur/dist/noortrace-verifier-linux-amd64) : vérification JavaScript faite, vérification Go non faite");
    const go = verifierGo(destination, { ancres, entetes, bin });
    expect(go.code).to.equal(0);
    expect(statuts(go.rapport)).to.deep.equal(s);
    expect(go.rapport.statement.fr).to.equal(js.rapport.statement.fr);
    expect(go.rapport.statement.en).to.equal(js.rapport.statement.en);
  });

  it("TI-17 sur les jetons reçus du serveur interne : AN-22 (T-8), AN-24 (accuracy ≤ 1 s, TM-19), AN-25 (nonce recopié), AN-26 (numéros de série strictement croissants, TM-18 : 0 paire non croissante), AN-29 (politique privée), AN-30 (certificat de l'unité inclus) ; AN-28 : une ligne d'acquisition par jeton reçu", async function () {
    if (!pret.call(this)) return;
    const depot = DepotAncres.ouvrir({ racine: m.config.storage.root, orgId: m.config.recorder.org_id, journalId: m.config.recorder.journal_id });
    const lues = depot.dernieresAcquisitions(PERIODE).enregistrements.filter((e) => e.outcome === "obtenue");
    expect(lues.length).to.be.at.least(2);
    const series = [];
    for (const e of lues.sort((a, b) => (a.received_at < b.received_at ? -1 : 1))) {
      const jeton = lireJeton(new Uint8Array(fs.readFileSync(path.join(depot.repertoire(PERIODE), e.files.token))));
      expect(jeton.tstInfo.accuracy, e.attempt_id).to.not.equal(null);
      expect(Number(jeton.tstInfo.accuracy.seconds ?? 0n) + (jeton.tstInfo.accuracy.millis || jeton.tstInfo.accuracy.micros ? 1 : 0)).to.be.at.most(1);
      expect(Date.parse(e.upper_bound) - Date.parse(e.gen_time)).to.be.at.most(1000);
      expect(jeton.tstInfo.policy).to.equal(m.documentAncrage.rfc3161.providers.find((p) => p.id === e.provider_id).policy_oid);
      expect(jeton.certificatsPresents).to.equal(true);
      expect(e.checks["T-8"]).to.equal("reussi");
      expect(e.checks["T-4"]).to.equal("reussi");
      expect(e.nonce_in_response).to.equal(e.nonce);
      expect(e.imprint_matches).to.equal(true);
      expect(jeton.tstInfo.nonce === null ? null : `0x${jeton.tstInfo.nonce.toString(16).padStart(16, "0")}`).to.equal(e.nonce);
      if (e.provider_id === "tsa-interne") series.push(BigInt(jeton.tstInfo.serialNumber));
    }
    let nonCroissantes = 0;
    for (let k = 1; k < series.length; k++) if (!(series[k] > series[k - 1])) nonCroissantes += 1;
    expect(series.length).to.be.at.least(1);
    expect(nonCroissantes).to.equal(0);
  });

  it("noortrace-ctl ancrage etat | metriques | retirer-qualification <id> (SIGURG et demande écrite, réponse au journal) ; noortrace-ctl reload recharge le document ancrage-v0 avec la politique (EX-4.9) ; un rechargement d'un document invalide est refusé sans changer l'ancien", async function () {
    if (!pret.call(this)) return;
    const etat = await ctl(["ancrage", "etat", "--configuration", m.cheminConfig]);
    expect(etat.code, etat.err).to.equal(0);
    const l1 = JSON.parse(etat.out.trim().split("\n")[0]);
    expect(l1.event).to.equal("anchoring_state");
    expect(l1.data).to.include({ demarre: true, attached: true, registry: true });
    const met = await ctl(["ancrage", "metriques", "--configuration", m.cheminConfig]);
    expect(met.code, met.err).to.equal(0);
    expect(met.out).to.include('"event":"anchoring_metrics"');
    expect(met.out).to.include("noortrace_anchoring_attempts_total");
    const retrait = await ctl(["ancrage", "retirer-qualification", "qtsa-principal", "--configuration", m.cheminConfig]);
    expect(retrait.code, retrait.err).to.equal(0);
    expect(JSON.parse(retrait.out.trim().split("\n")[0]).event).to.equal("provider_qualification_withdrawn");
    expect((await demon.etat()).etat.qualifications_retirees).to.deep.equal(["qtsa-principal"]);
    const inconnu = await ctl(["ancrage", "retirer-qualification", "inconnu", "--configuration", m.cheminConfig]);
    expect(inconnu.code).to.equal(1);
    expect(JSON.parse(inconnu.out.trim().split("\n")[0]).data.raison).to.equal("prestataire_inconnu");
    expect((await ctl(["ancrage", "rien", "--configuration", m.cheminConfig])).code).to.equal(2);
    // Rechargement : nouvelle version de politique et document ancrage-v0 modifié (max_pending) ; le retrait de qualification est levé par le rechargement (EX-5.9).
    const config = JSON.parse(fs.readFileSync(m.cheminConfig, "utf8"));
    config.policy.version = "2026-11-05-f2";
    fs.writeFileSync(m.cheminConfig, JSON.stringify(config, null, 2));
    const doc = JSON.parse(fs.readFileSync(m.cheminAncrage, "utf8"));
    doc.queue.max_pending = 200;
    fs.writeFileSync(m.cheminAncrage, JSON.stringify(doc, null, 2));
    const reload = await ctl(["reload", "--configuration", m.cheminConfig]);
    expect(reload.code, reload.err).to.equal(0);
    await demon.attendre((l) => l.some((x) => x.event === "config_reloaded" && x.component === "ancrage"), 20000, "config_reloaded du composant");
    expect((await demon.etat()).etat.qualifications_retirees).to.deep.equal([]);
    // Document invalide (deux principaux) : refusé, l'ancienne configuration reste en vigueur.
    doc.rfc3161.providers.push({ ...doc.rfc3161.providers[0], id: "second-principal" });
    fs.writeFileSync(m.cheminAncrage, JSON.stringify(doc, null, 2));
    config.policy.version = "2026-11-05-f2-b";
    fs.writeFileSync(m.cheminConfig, JSON.stringify(config, null, 2));
    expect((await ctl(["reload", "--configuration", m.cheminConfig])).code).to.equal(0);
    await demon.attendre((l) => l.some((x) => x.event === "config_reload_rejected" && x.component === "ancrage"), 20000, "config_reload_rejected du composant");
    expect(demon.de("config_reload_rejected").at(-1).data.rules).to.include("2");
    expect((await demon.etat()).etat.demarre).to.equal(true);
  });

  it("arrêt propre : anchoring_stopped puis shutdown, code 0 ; la file durable porte des demandes à états finaux, une ligne envoyee a précédé chaque envoi (AN-32)", async function () {
    if (!pret.call(this)) return;
    const fin = await demon.arreter();
    expect(fin.code).to.equal(0);
    const lignes = demon.lignes();
    const evenements = lignes.map((l) => l.event);
    expect(evenements).to.include("anchoring_stopped");
    expect(evenements.indexOf("anchoring_stopped")).to.be.lessThan(evenements.lastIndexOf("shutdown"));
    const relue = lireFiles(m.documentAncrage.queue.path);
    expect(relue.tronquees).to.deep.equal([]);
    const par = (kind) => relue.demandes.filter((d) => d.kind === kind);
    expect(par("jeton_periode").map((d) => d.state)).to.deep.equal(["obtenue"]);
    expect(par("ancre_registre_periode").map((d) => d.state)).to.deep.equal(["obtenue"]);
    expect(par("ots_periode").map((d) => d.state)).to.deep.equal(["complete"]);
    expect(par("ots_point").map((d) => d.state)).to.deep.equal(["complete"]);
    expect(par("jeton_point").filter((d) => d.state === "obtenue").length).to.be.at.least(1);
    expect(par("ancre_registre_point").filter((d) => d.state === "obtenue").length).to.be.at.least(3);
    // Les ancres des points sont `obtenue` ou `remplacee` ; seules celles des tout derniers points peuvent être encore en vol à l'arrêt.
    const enVol = par("ancre_registre_point").filter((d) => !ETATS_FINAUX.includes(d.state));
    expect(enVol.length).to.be.at.most(2);
    // Chaque requête RFC 3161 partie a d'abord sa ligne `envoyee` dans la file (AN-32).
    const lignesFile = fs.readFileSync(path.join(m.documentAncrage.queue.path, relue.fichiers[0]), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    // Révision 0.6 de CT-5 (EX-8.5 règle 5, EX-8.14) : la file a été compactée à la clôture (les lignes `envoyee`
    // remplacées ne sont plus conservées) ; chaque tentative garde dans la dernière ligne de sa demande le nonce
    // que sa ligne `envoyee` a consigné avant l'envoi (AN-32, éprouvé ligne à ligne par les traces).
    const nonces = new Set(lignesFile.flatMap((l) => l.attempts.map((a) => a.nonce)).filter(Boolean));
    const depot = DepotAncres.ouvrir({ racine: m.config.storage.root, orgId: m.config.recorder.org_id, journalId: m.config.recorder.journal_id });
    for (const e of depot.lireAcquisitions(PERIODE).enregistrements) expect(nonces.has(e.nonce), e.attempt_id).to.equal(true);
  });
});

// ------------------------------------------------------------------- variante réelle

const POINTS = POINTS_RESEAU_DEV;
const VERIFICATEUR_JS_REF = path.join(RACINE, "scripts", "verify", "dossier.mjs");
/** Agrégateurs OpenTimestamps publics d'EX-6.2 et calendriers de la liste blanche (lot B). */
const AGREGATEURS_PUBLICS = ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org", "https://a.pool.eternitywall.com", "https://ots.btc.catallaxy.com"];
const CALENDRIERS_PUBLICS = ["https://alice.btc.calendar.opentimestamps.org", "https://bob.btc.calendar.opentimestamps.org", "https://finney.calendar.eternitywall.com", "https://ots.btc.catallaxy.com"];

async function reseauDebout() {
  const rpc = new R.ClientRpc({ points: POINTS, delaiMs: 3000, identifiants: Object.fromEntries(POINTS.map((p, k) => [p, `v${k + 1}`])) });
  try {
    for (const p of POINTS) {
      const c = await rpc.appeler("eth_chainId", [], { point: p });
      if (c.erreur || c.resultat !== "0x84c") return { ok: false, condition: `le validateur ${p} ne répond pas eth_chainId 0x84c (bash chain/scripts/dev-net.sh start)` };
    }
    return { ok: true, rpc };
  } catch (e) {
    return { ok: false, condition: `le réseau de développement n'est pas debout (${e.message}) : bash chain/scripts/dev-net.sh start` };
  }
}

function parcours(travail) {
  const donne = process.env.NOORTRACE_PARCOURS_REGISTRE ?? null;
  if (donne && fs.existsSync(path.join(donne, "cles", "cle-chaine-rec-demo-01.cle"))) return { ok: true, repertoire: donne };
  const go = binaireGo();
  if (!go) return { ok: false, condition: "aucun parcours d'inscription (NOORTRACE_PARCOURS_REGISTRE) et vérificateur Go de CT-6 absent pour exécuter npm run e2e:registre" };
  const sortie = path.join(travail, "parcours");
  const r = spawnSync("npm", ["run", "e2e:registre", "--", "--garder-reseau", "--sortie", sortie, "--verificateur-go", go], { cwd: RACINE, encoding: "utf8", timeout: 600000 });
  if (r.status !== 0) return { ok: false, condition: `le parcours npm run e2e:registre a échoué (code ${r.status})` };
  return { ok: true, repertoire: sortie };
}

/**
 * Vérification d'un dossier SANS RÉSEAU (CT-5 P-5, TE-12 : `unshare -n`) par
 * le vérificateur JavaScript de référence ou le binaire Go ; rend le rapport
 * JSON et la méthode employée. Quand `unshare` est refusé dans le conteneur,
 * la vérification est faite sans espace de noms réseau et la méthode le dit.
 */
function verifierHorsLigne(bin, repertoire, { ancres, entetes }) {
  const args = bin === "js" ? [VERIFICATEUR_JS_REF, repertoire, "--json", "--ancres", ancres, ...(entetes ? ["--entetes-bitcoin", entetes] : [])] : [repertoire, "--json", "--ancres", ancres, ...(entetes ? ["--entetes-bitcoin", entetes] : [])];
  const programme = bin === "js" ? process.execPath : bin;
  const r = sansReseau(programme, args);
  if (r.disponible) return { methode: "unshare -n (espace de noms réseau vide, sans route)", code: r.code, rapport: r.stdout ? JSON.parse(r.stdout) : null, stderr: r.stderr };
  const direct = spawnSync(programme, args, { cwd: RACINE, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return { methode: "unshare refusé dans ce conteneur : vérification faite sans espace de noms réseau", code: direct.status, rapport: direct.stdout ? JSON.parse(direct.stdout) : null, stderr: direct.stderr };
}

/** Le fragment FK de CT-6 EX-6.16 (point de contrôle daté) dans l'énoncé du vérificateur (CT-6 §7.9). */
function enonceConformeFK(statement) {
  return statement.includes("couvert par le point de contrôle") && statement.includes("horodaté au plus tard le") && statement.includes("réécriture postérieure à cet instant serait détectée");
}

describe("enregistreur + ancrage (lot F2), TE-12 sur le réseau de développement réel : démon réel, ancres des points et de la période incluses sur noorcore, clôture submitPeriod relayée, dossier vérifié sans réseau par les deux vérificateurs (CT-4 §7.4, §8.2, §8.6, §9.4 ; CT-5 P-5 ; CT-6 §7.9)", function () {
  this.timeout(1200000);
  let travail;
  let ctx = null;
  let demon;
  const exports = {};

  before(async function () {
    travail = repertoireTemporaire("noortrace-f2-te12-reseau-");
    const reseau = await reseauDebout();
    if (!reseau.ok) {
      ctx = { condition: reseau.condition };
      return;
    }
    const p = parcours(travail);
    if (!p.ok) {
      ctx = { condition: p.condition };
      return;
    }
    // Journal neuf inscrit sous l'organisation du parcours par l'outil de référence (boîte noire) : clé de chaîne propre à
    // l'essai, aucune période au registre, donc une première clôture sans continuité à tenir (CT-4 OP-10) et aucun nonce
    // partagé avec un autre démon qui emploierait la clé du parcours.
    const base = lireParcours(p.repertoire);
    const journal = inscrireJournal({ parcours: base, travail, etiquette: `te12-${Date.now()}` });
    if (journal.condition) {
      ctx = { condition: journal.condition };
      return;
    }
    // Période simulée : l'heure courante, le démon démarré 2 s après son début (horloge hybride, sauts entre les étapes).
    const periodStart = Math.floor(Date.now() / 3600000) * 3600;
    const m = await monterDemonReseauReel({ travail, parcours: journal, baseMs: periodStart * 1000 + 2000, cK: 10, surchargesAncrage: { registry: { checkpoints: "tous", inclusion_alert_s: 120 } } });
    if (m.condition) {
      ctx = { condition: m.condition };
      return;
    }
    demon = new Demon(m);
    await demon.demarrer();
    ctx = { montage: m, rpc: reseau.rpc, journal, periodStart };
  });

  after(async function () {
    if (demon?.p) await demon.arreter().catch(() => {});
    await ctx?.montage?.fermer?.();
    if (travail) fs.rmSync(travail, { recursive: true, force: true });
  });

  function pret() {
    if (!ctx || ctx.condition) {
      enAttente(this, ctx?.condition ?? "contexte non préparé");
      return false;
    }
    return true;
  }

  it("points et période ancrés sur noorcore par la clé de chaîne inscrite (AN-44 à AN-48, CP-1 à CP-6), jeton qualifié du principal et preuve OpenTimestamps sur la racine ; la clôture submitPeriod attend la demande signée (period_close_delegated) puis est relayée (period_submitted) dès que la demande signée au seuil par les approbateurs du parcours est déposée (CT-4 §8.2 pas 3 à 5) ; la période est lue au registre avec son periodHash", async function () {
    if (!pret.call(this)) return;
    const { montage: m, periodStart, journal } = ctx;
    await demon.attendre((l) => l.some((x) => x.event === "anchoring_attached"), 30000, "anchoring_attached");
    expect(demon.de("anchoring_attached")[0].data).to.include({ registry: true, providers: 2 });
    const e1 = await demon.evenement(1);
    exports.seqs = [e1.seq];
    await demon.attendre((l) => l.some((x) => x.event === "registry_included"), 120000, "première ancre incluse");
    // L'événement juste avant l'échéance médiane D_30 (07:29:51.3 de la période) : le point suivant (xx:30:00) l'engage, est
    // contresigné (EX-4.3) et ancré ; c'est le point couvrant du dossier.
    await demon.avancer(periodStart * 1000 + 1791300 - m.horloge.murale());
    const e2 = await demon.evenement(2);
    exports.seqs.push(e2.seq);
    await demon.attendre((l) => l.some((x) => x.event === "checkpoint_countersigned" && x.data.tree_size === 3), 120000, "point de taille 3 contresigné");
    await demon.attendre((l) => l.some((x) => x.event === "ots_submitted" && x.data.request_id?.startsWith("ots_point")), 60000, "ots_point soumis");
    await demon.avancer((periodStart + 3601) * 1000 - m.horloge.murale());
    await demon.attendre((l) => l.some((x) => x.event === "period_closed" && x.data.period_start === periodStart), 60000, "period_closed");
    await demon.attendre((l) => l.some((x) => x.event === "period_timestamped") && l.some((x) => x.event === "period_close_delegated" && x.data.period_start === periodStart) && l.filter((x) => x.event === "ots_submitted").length >= 2, 240000, "ancres de la période");
    expect(demon.de("period_timestamped")[0].data.provider).to.equal("qtsa-principal");
    expect(demon.de("period_close_delegated").at(-1).data.reason).to.equal("signatures_en_attente");
    const manifeste = JSON.parse(fs.readFileSync(path.join(m.repertoire, "manifestes", `periode-${periodStart}.json`), "utf8"));
    const periodHash = N.hacherManifeste(manifeste);
    // EX-8.4 : l'ancre de la période est incluse et capturée sous la clé de chaîne inscrite avant que la clôture ne parte.
    const empreinte = N.empreinteAncre(journal.orgId, journal.journalId, periodHash);
    const l = await R.lookup({ rpc: ctx.rpc, contrat: journal.contrats.attestation_registry, fingerprint: empreinte });
    expect(l.anchored).to.equal(true);
    expect(l.issuer).to.equal(journal.cleChaine.adresse());
    expect(l.docType).to.equal(R.DOC_TYPE_PERIODE);
    const avant = await R.latestPeriodOf({ rpc: ctx.rpc, contrat: journal.contrats.period_registry, orgId: journal.orgId, journalId: journal.journalId });
    expect(avant).to.equal(0n, "journal neuf : aucune période au registre avant la clôture");
    // Pas 3 et 4 de CT-4 §8.2 : la demande de clôture, signée au seuil par les approbateurs du parcours (clés publiées de
    // l'essai), déposée là où le démon la lit (lecture F2-3) ; pas 5 : le démon relaie submitPeriod au tic suivant.
    const demande = demandeClotureParcours({ manifeste, parcours: journal, preparedAt: N.ecrireHorodatage(m.horloge.murale()) });
    expect(R.verifierDemande(demande, { membres: journal.membres, complete: true }).resultat).to.equal("valide");
    fs.writeFileSync(path.join(m.repertoire, "registre", `demande-cloture-${periodHash}.json`), JSON.stringify(demande, null, 2));
    await demon.avancer(61000);
    await demon.attendre((lg) => lg.some((x) => x.event === "period_submitted" && x.data.period_start === periodStart), 180000, "period_submitted");
    // `latestPeriodOf` rend l'identifiant de la dernière période du journal dans la suite du contrat (compteur global), non un rang par journal.
    const apres = await R.latestPeriodOf({ rpc: ctx.rpc, contrat: journal.contrats.period_registry, orgId: journal.orgId, journalId: journal.journalId });
    expect(apres > 0n).to.equal(true, "une période enregistrée pour le journal neuf");
    const lue = await R.getPeriod({ rpc: ctx.rpc, contrat: journal.contrats.period_registry, id: apres });
    expect(lue.periodHash.toLowerCase()).to.equal(periodHash);
    expect(Number(lue.periodStart)).to.equal(periodStart);
    // Captures de CT-4 §9.4 : ancres des points, ancre de la période, clôture ; CP-2 à CP-6 hors ligne.
    const captures = fs.readdirSync(path.join(m.repertoire, "registre")).filter((n) => n.startsWith("capture-"));
    expect(captures.some((n) => n.endsWith("-cloture.json"))).to.equal(true);
    expect(captures.filter((n) => n.endsWith("-ancre.json")).length).to.be.at.least(3);
    for (const nom of captures) {
      const index = JSON.parse(fs.readFileSync(path.join(m.repertoire, "registre", nom), "utf8"));
      expect(R.verifierCapture({ fichiers: path.join(m.repertoire, "registre"), index, jeux: m.registre.manifeste.validator_sets[0], bftChainId: m.registre.bftChainId }).premierEchec, nom).to.equal(null);
    }
    exports.manifeste = manifeste;
    exports.periodHash = periodHash;
  });

  it("mise à niveau OpenTimestamps par les calendriers factices (chaîne regtest, EX-6.9) puis export du dossier de l'événement (treize parties, point couvrant contresigné et ancré) ; vérification SANS RÉSEAU (unshare -n, P-5) par le vérificateur JavaScript et par le binaire Go : contrôles 4, 5 et 8 réussis, K-7 à K-9 réussies, énoncé conforme à CT-6 §7.9 (fragment FK) et identique entre les deux vérificateurs", async function () {
    if (!pret.call(this)) return;
    const { montage: m, journal } = ctx;
    m.calendriers.completer(1010);
    await demon.avancer(61000);
    await demon.attendre((lg) => lg.filter((x) => x.event === "ots_complete").length >= 2 && lg.some((x) => x.event === "bitcoin_headers_written"), 180000, "ots_complete et entetes-bitcoin.json");
    const destination = path.join(travail, "dossier");
    const r = await demon.exporter(exports.seqs[1], destination);
    const parts = Object.fromEntries(r.parts.map((p) => [p.name, p]));
    for (const nom of ["evenement", "voisins", "chemin", "manifeste", "manifeste_sig", "cles", "jeton_rfc3161", "preuve_ots", "registre", "certificat_commit", "validateurs", "points_de_controle"]) expect(parts[nom].present, nom).to.equal(true);
    const partie = JSON.parse(fs.readFileSync(path.join(destination, "points-de-controle.json"), "utf8"));
    expect(partie.checkpoint.tree_size).to.equal(3);
    expect(partie.anchors.rfc3161).to.not.equal(null);
    expect(partie.anchors.ots).to.not.equal(null);
    expect(partie.anchors.registry).to.include({ chain_id: EVM_RESEAU_DEV, doc_type: R.DOC_TYPE_POINT_DE_CONTROLE });
    const registre = JSON.parse(fs.readFileSync(path.join(destination, "registre.json"), "utf8"));
    expect(registre.entries.map((e) => e.role).sort()).to.deep.equal(["ancre", "ancre_point_de_controle", "cloture"]);
    const ancres = fichierTemporaire("ancres-reseau.json");
    fichierAncres({
      chemin: ancres, montage: m, bitcoin: pointDeControleBitcoin(m, 1000),
      recorders: [{ org_id: journal.orgId, journal_id: journal.journalId, key_id: journal.recorder.key_id, public_key: N.octetsVersHex(journal.clePublique), chain_key: journal.cleChaine.adresse(), source: "journal neuf inscrit par l'essai sous l'organisation du parcours de référence" }],
    });
    const entetes = path.join(destination, "entetes-bitcoin.json");
    expect(fs.existsSync(entetes)).to.equal(true);
    const js = verifierHorsLigne("js", destination, { ancres, entetes });
    console.log(`      vérification JavaScript : ${js.methode}`);
    expect(js.code, js.stderr).to.equal(0);
    expect(js.rapport.verdict).to.equal("valide");
    const s = statuts(js.rapport);
    for (const k of ["K-1", "K-2", "K-3", "K-4", "K-5", "K-6", "K-7", "K-8", "K-9"]) expect(s[k], k).to.equal("reussi");
    const controles = Object.fromEntries(js.rapport.controls.map((c) => [c.number, c]));
    for (const n of [1, 2, 3, 4, 5, 6, 8]) expect(controles[n].status, `contrôle ${n}`).to.equal("reussi");
    expect(js.rapport.facts.checkpoint.registry.inclusion).to.equal("prouvee");
    expect(enonceConformeFK(js.rapport.statement.fr), js.rapport.statement.fr).to.equal(true);
    expect(js.rapport.statement.fr).to.include("ancré au registre noortrace-2124-dev");
    expect(js.rapport.blocking_unexecuted).to.deep.equal([]);
    exports.js = js;
    const bin = binaireGo();
    if (!bin) return enAttente(this, "vérificateur Go de CT-6 absent (NOORTRACE_VERIFIER_BIN) : vérification JavaScript faite sans réseau, vérification Go non faite");
    const go = verifierHorsLigne(bin, destination, { ancres, entetes });
    console.log(`      vérification Go : ${go.methode}`);
    expect(go.code).to.equal(0);
    expect(go.rapport.verdict).to.equal("valide");
    expect(statuts(go.rapport)).to.deep.equal(s);
    expect(Object.fromEntries(go.rapport.controls.map((c) => [c.number, c.status]))).to.deep.equal(Object.fromEntries(js.rapport.controls.map((c) => [c.number, c.status])));
    expect(go.rapport.statement.fr).to.equal(js.rapport.statement.fr);
    expect(go.rapport.statement.en).to.equal(js.rapport.statement.en);
  });

  it("calendriers publics réels (agrégateurs d'EX-6.2) : la preuve de la racine reste en attente, le dossier exporté est vérifié sans réseau : contrôle 5 non exécuté partie_absente, K-9 non exécutée, K-7 réussie ; même verdict par le binaire Go — en attente hors NOORTRACE_RESEAU_PUBLIC=1", async function () {
    if (!pret.call(this)) return;
    if (process.env.NOORTRACE_RESEAU_PUBLIC !== "1") return enAttente(this, "NOORTRACE_RESEAU_PUBLIC=1 (réseau public joignable : soumission réelle aux agrégateurs OpenTimestamps)");
    // Second démon, hors registre (profil developpement), dont les calendriers sont les agrégateurs publics ; le reste du
    // décor est celui de la variante hors réseau public (autorités internes, TLS mutuel).
    const dir2 = path.join(travail, "public");
    fs.mkdirSync(dir2, { recursive: true });
    const base = Date.UTC(2026, 10, 6, 9, 0, 2);
    const periode = Math.floor(base / 3600000) * 3600;
    const m2 = await monterDemon({ dir: dir2, baseMs: base, registre: false, surchargesAncrage: { registry: { checkpoints: "aucun" }, opentimestamps: { calendars: AGREGATEURS_PUBLICS, timeout_ms: 15000, upgrade: { whitelist: CALENDRIERS_PUBLICS } } } });
    if (m2.condition) return enAttente(this, m2.condition);
    const d2 = new Demon(m2);
    try {
      await d2.demarrer();
      await d2.attendre((l) => l.some((x) => x.event === "anchoring_attached"), 30000, "anchoring_attached");
      await d2.evenement(1);
      await d2.avancer(periode * 1000 + 1791300 - m2.horloge.murale());
      const e = await d2.evenement(2);
      await d2.attendre((l) => l.some((x) => x.event === "checkpoint_countersigned" && x.data.tree_size === 3), 120000, "point de taille 3 contresigné");
      await d2.avancer((periode + 3601) * 1000 - m2.horloge.murale());
      await d2.attendre((l) => l.some((x) => x.event === "period_timestamped") && l.some((x) => x.event === "ots_submitted" && x.data.request_id?.startsWith("ots_periode")), 240000, "jeton et soumission publique de la racine");
      const soumission = d2.de("ots_submitted").find((x) => x.data.request_id.startsWith("ots_periode"));
      console.log(`      soumission publique : ${JSON.stringify(soumission.data)}`);
      expect(soumission.data.calendars_answered).to.be.at.least(2);
      expect(soumission.data.attestation).to.equal("en_attente");
      const destination = path.join(dir2, "dossier");
      const r = await d2.exporter(e.seq, destination);
      expect(r.parts.find((p) => p.name === "preuve_ots").present).to.equal(true);
      const ancres = fichierTemporaire("ancres-public.json");
      fichierAncres({ chemin: ancres, montage: m2, bitcoin: null, registry: false });
      const js = verifierHorsLigne("js", destination, { ancres, entetes: null });
      console.log(`      vérification JavaScript : ${js.methode}`);
      expect(js.code, js.stderr).to.equal(0);
      const s = statuts(js.rapport);
      expect(s["K-7"]).to.equal("reussi");
      expect(s["K-9"]).to.equal("non_execute");
      const c5 = js.rapport.controls.find((c) => c.number === 5);
      expect(c5.status).to.equal("non_execute");
      expect(c5.reason).to.equal("partie_absente");
      const bin = binaireGo();
      if (bin) {
        const go = verifierHorsLigne(bin, destination, { ancres, entetes: null });
        expect(go.code).to.equal(0);
        expect(statuts(go.rapport)).to.deep.equal(s);
        expect(go.rapport.statement.fr).to.equal(js.rapport.statement.fr);
      }
    } finally {
      if (d2.p) await d2.arreter().catch(() => {});
      await m2.fermer();
    }
  });

  it("arrêt propre du démon réel : anchoring_stopped puis shutdown, code 0 ; file durable à états finaux pour la période (jeton_periode, ancre_registre_periode obtenue, ots_periode et ots_point complete)", async function () {
    if (!pret.call(this)) return;
    const { montage: m } = ctx;
    const fin = await demon.arreter();
    expect(fin.code).to.equal(0);
    const evenements = demon.lignes().map((l) => l.event);
    expect(evenements.indexOf("anchoring_stopped")).to.be.lessThan(evenements.lastIndexOf("shutdown"));
    const relue = lireFiles(m.documentAncrage.queue.path);
    const par = (kind) => relue.demandes.filter((d) => d.kind === kind && d.subject.period_start === ctx.periodStart);
    expect(par("jeton_periode").map((d) => d.state)).to.deep.equal(["obtenue"]);
    expect(par("ancre_registre_periode").map((d) => d.state)).to.deep.equal(["obtenue"]);
    expect(par("ots_periode").map((d) => d.state)).to.deep.equal(["complete"]);
    expect(par("ots_point").map((d) => d.state)).to.deep.equal(["complete"]);
  });
});
