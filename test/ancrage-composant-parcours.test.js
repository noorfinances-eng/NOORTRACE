// Composant d'ancrage (lot F1) : une période entière rejouée à l'horloge
// injectée, hors réseau public (CT-5 §4, §5, §6, §8, §9 ; EX-4.12, EX-5.8,
// EX-5.10 étape 10, EX-5.14, EX-6.5, EX-6.8, EX-8.1, EX-8.7, EX-8.12,
// EX-8.15, AN-3, AN-32, AN-43). Serveurs RFC 3161 du lot E réels sur
// 127.0.0.1 (rôle interne en HTTP ; principal et secours en TLS avec
// authentification du client, qualified d'exemple en profil test),
// calendriers OpenTimestamps factices HTTP locaux (promesses puis chemin
// complet, chaîne regtest du lot B), nœud noorcore factice du lot D. Points
// toutes les 60 s, échéances toutes les 300 s, clôture : trois ancres pour le
// manifeste, jetons des points aux échéances, fichiers d'EX-5.14 et d'EX-6.5,
// acquisitions.ndjson, file, métriques et journal d'EX-8.15.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as N from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";
import { verifierJeton, DepotAncres, lireReponse } from "@noortrace/ancrage/rfc3161";
import { lireOts, verifierOts, DepotOts } from "@noortrace/ancrage/ots";
import { lireFiles, METRIQUES_ANCRAGE, ETATS_FINAUX } from "@noortrace/ancrage/planificateur";
import { creerComposantAncrage } from "../paquets/ancrage/src/composant.mjs";
import {
  ORG, JOURNAL, CLES_JSON, HorlogeReglable, attenteCalme, aleatoireFixe, materielTls, serveurCrl, autoriteInterne, qualifiedExemple, calendriersFactices,
  serieSynthetique, remisePoint, remiseCloture, registreFactice, signaturesClotureEssai, configurationEssai, journalMemoire, transportRfc3161Local,
  repertoireTemporaire, enAttente,
} from "./fixtures/ancrage-composant/outils.mjs";

const PERIODE = 1793862000; // 2026-11-05T07:00:00Z, dans la validité de rec-test-01
const T0 = PERIODE * 1000;
const EVENEMENTS = { 1: 2, 7: 1, 13: 1, 22: 1, 31: 1, 32: 1, 44: 1, 58: 1 };

describe("ancrage, composant F1 : une période entière hors réseau public (CT-5 §4 à §9)", function () {
  this.timeout(600000);
  let dir;
  let horloge;
  let aleatoire;
  let crl;
  let tls;
  let interne;
  let principal;
  let secours;
  let calendriers;
  let registre;
  let composant;
  let journal;
  let serie;
  let fichierEntetes;
  let secrets;
  let configuration;
  let calme;
  const remis = [];
  const PANNE = { ok: false };

  before(async function () {
    dir = repertoireTemporaire();
    tls = materielTls(path.join(dir, "tls"));
    if (!tls) {
      PANNE.condition = "openssl indisponible pour le matériel TLS";
      return;
    }
    horloge = new HorlogeReglable(T0);
    aleatoire = aleatoireFixe(3);
    crl = await serveurCrl(horloge);
    interne = await autoriteInterne({ nom: "tsa-interne", dir, role: "interne", horloge, aleatoire, crl, politique: "1.3.6.1.4.1.99999.2.1" });
    principal = await autoriteInterne({ nom: "qtsa-principal", dir, role: "principal", horloge, aleatoire, crl, tls, qualified: qualifiedExemple("AT"), politique: "1.3.6.1.4.1.99999.3.1" });
    secours = await autoriteInterne({ nom: "qtsa-secours", dir, role: "secours", horloge, aleatoire, crl, tls, qualified: qualifiedExemple("PL"), politique: "1.3.6.1.4.1.99999.3.2" });
    fichierEntetes = path.join(dir, "entetes-regtest.json");
    calendriers = await calendriersFactices({ fichierEntetes });
    serie = serieSynthetique({ periodStart: PERIODE, evenementsAuxMinutes: EVENEMENTS });
    registre = registreFactice({ clePublique: serie.clePublique });
    configuration = configurationEssai({ prestataires: [principal.prestataire, secours.prestataire, interne.prestataire], dir, calendriers, fichierEntetes });
    secrets = new Map([["/rfc3161/providers/0/auth/secret", tls.client], ["/rfc3161/providers/1/auth/secret", tls.client]]);
    journal = journalMemoire();
    composant = creerComposantAncrage({
      configuration,
      profil: "test",
      checkpointIntervalEnregistreur: 60,
      contexte: {
        org_id: ORG,
        journal_id: JOURNAL,
        epoque: 1,
        racineStockage: path.join(dir, "stockage"),
        secrets,
        cles: CLES_JSON,
        clePublique: (keyId) => (keyId === "rec-test-01" ? serie.clePublique : null),
        lireSerie: async () => remis.slice(),
        lireHashesPeriode: async (P) => (P === PERIODE ? serie.hashes : null),
        listerPeriodes: async () => [],
        listerPoints: async () => [],
        cleChaine: registre.cleChaine,
        signaturesCloture: signaturesClotureEssai(registre, R),
      },
      horloge,
      aleatoire,
      journal,
      clients: {
        rfc3161: { transport: transportRfc3161Local(tls) },
        ots: { transport: calendriers.transport },
        registre: { rpc: registre.rpc, instance: registre.instance, repertoireEnvois: path.join(dir, "captures"), delais: { recuMs: 60000, sondageMs: 500 } },
      },
    });
    calme = attenteCalme(composant);
    PANNE.ok = true;
  });

  after(async function () {
    if (composant?.etat().demarre) await composant.arreter({ attendre: false }).catch(() => undefined);
    await Promise.all([interne?.fermer(), principal?.fermer(), secours?.fermer(), calendriers?.fermer(), crl?.fermer()].filter(Boolean));
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  function pret() {
    if (!PANNE.ok) {
      enAttente(this, PANNE.condition ?? "contexte non préparé");
      return false;
    }
    return true;
  }

  it("la configuration est validée (AN-1, secrets résolus) et le composant démarre : anchoring_started, anchoring_queue_rebuilt (EX-8.12)", async function () {
    if (!pret.call(this)) return;
    expect(composant.configurationValide()).to.deep.equal({ valide: true, erreurs: [] });
    await composant.demarrer();
    expect(journal.evenements()).to.include.members(["anchoring_started", "anchoring_queue_rebuilt"]);
    expect(journal.de("anchoring_queue_rebuilt")[0].data).to.include({ recreated: 0, periods: 0, checkpoints: 0 });
    expect(composant.etat()).to.include({ demarre: true, demandes: 0, en_vol: 0 });
  });

  it("rejoue la période : points admis (AN-3) toutes les 60 s, ancres au registre dès l'admission, jetons des points aux échéances par le serveur interne, clôture (remises non bloquantes, EX-4.12)", async function () {
    if (!pret.call(this)) return;
    const alignes = serie.points.slice(0, -1);
    for (const point of alignes) {
      await horloge.aller(N.decoderHorodatage(point.checkpoint_ts), calme);
      remis.push(point);
      const debut = Date.now();
      const r = await composant.remettrePoint(remisePoint(point));
      expect(r.admis, `point ${point.checkpoint_ts}`).to.equal(true);
      // La remise rend la main sans attendre le réseau : elle ne dure pas le temps d'une requête aux prestataires.
      expect(Date.now() - debut).to.be.below(5000);
      await calme();
    }
    const cloture = serie.points.at(-1);
    await horloge.aller(N.decoderHorodatage(cloture.checkpoint_ts), calme);
    remis.push(cloture);
    expect((await composant.remettrePoint(remisePoint(cloture))).admis).to.equal(true);
    expect((await composant.remettreCloture(remiseCloture(serie))).admis).to.equal(true);
    await calme();
    await horloge.avancer(30000, calme);
    const file = composant.demandes();
    const par = (kind, state) => file.filter((d) => d.kind === kind && (state === undefined || d.state === state));
    expect(par("ancre_registre_point", "obtenue")).to.have.lengthOf(8, "huit points engagent un nouvel événement (EX-4.6)");
    expect(par("ancre_registre_point")).to.have.lengthOf(8);
    expect(par("jeton_point", "obtenue")).to.have.lengthOf(6, "D_1, D_2, D_3, D_5, D_7, D_9 (EX-4.3)");
    expect(par("jeton_point")).to.have.lengthOf(6);
    expect(par("ancre_registre_periode", "obtenue")).to.have.lengthOf(1);
    expect(par("jeton_periode", "obtenue")).to.have.lengthOf(1);
    expect(par("jeton_periode")[0].result.provider).to.equal("qtsa-principal");
    expect(par("ots_periode", "en_attente")).to.have.lengthOf(1);
    expect(par("ots_point", "en_attente")).to.have.lengthOf(1, "point médian D_6 soumis même sans requête RFC 3161 (EX-6.1)");
    for (const d of par("jeton_point")) expect(d.result.provider).to.equal("tsa-interne");
    const echeances = composant.planificateur.echeances(PERIODE, ORG, JOURNAL);
    expect(echeances.map((e) => e.state)).to.deep.equal(["satisfaite", "satisfaite", "satisfaite", "sans_objet", "satisfaite", "sans_objet", "satisfaite", "sans_objet", "satisfaite", "sans_objet", "sans_objet"]);
    expect(journal.de("checkpoint_countersigned")).to.have.lengthOf(6);
    expect(journal.de("deadline_sans_objet")).to.have.lengthOf(5);
    expect(journal.de("period_timestamped")).to.have.lengthOf(1);
    expect(journal.de("checkpoint_not_anchored").length).to.be.at.least(50);
    expect(journal.de("period_submitted")).to.have.lengthOf(1, "la clôture submitPeriod suit l'inclusion de l'ancre de la période (CT-4 §8.2)");
    expect(journal.de("ots_submitted")).to.have.lengthOf(2);
    // d_jeton de chaque point : les quatre composantes sont des entiers dont la somme est d_jeton_s (EX-3.5).
    for (const l of journal.de("checkpoint_countersigned")) {
      const d = l.data;
      expect(d.d_point_s + d.d_attente_s + d.d_releve_s + d.d_tsa_s).to.equal(d.d_jeton_s);
      expect(d.d_jeton_s).to.be.at.most(6, "point à l'échéance, squat_wait_s au plus");
    }
  });

  it("EX-5.14 : fichiers rfc3161/<objet>-<provider>-<attempt_id>.{tsq,tsr,der}, acquisitions.ndjson en JCS intégral, un seul jeton promu par objet (EX-5.8), jetons vérifiés T-1 à T-9", async function () {
    if (!pret.call(this)) return;
    const depot = DepotAncres.ouvrir({ racine: path.join(dir, "stockage"), orgId: ORG, journalId: JOURNAL });
    const rep = depot.repertoire(PERIODE);
    const { enregistrements, tronquee } = depot.lireAcquisitions(PERIODE);
    expect(tronquee).to.equal(false);
    const texte = fs.readFileSync(path.join(rep, "acquisitions.ndjson"), "utf8").split("\n").filter(Boolean);
    expect(texte).to.have.lengthOf(enregistrements.length);
    texte.forEach((l, i) => expect(N.jcs(enregistrements[i])).to.equal(l));
    // Le fichier est en ajout seul : la T-10 différée ajoute une ligne par tentative promue ; le dernier état de chaque tentative fait foi.
    const obtenues = depot.dernieresAcquisitions(PERIODE).enregistrements.filter((e) => e.outcome === "obtenue");
    expect(obtenues).to.have.lengthOf(7);
    expect(enregistrements.filter((e) => e.outcome === "obtenue").length).to.be.at.least(7);
    const parObjet = new Map();
    for (const e of obtenues) parObjet.set(e.object_name, (parObjet.get(e.object_name) ?? 0) + (e.promoted ? 1 : 0));
    for (const [objet, n] of parObjet) expect(n, objet).to.equal(1);
    for (const e of obtenues) {
      expect(e.files.request).to.equal(`rfc3161/${e.object_name}-${e.provider_id}-${e.attempt_id}.tsq`);
      expect(e.files.response).to.equal(`rfc3161/${e.object_name}-${e.provider_id}-${e.attempt_id}.tsr`);
      expect(e.files.token).to.equal(`rfc3161/${e.object_name}-${e.provider_id}-${e.attempt_id}.der`);
      for (const f of [e.files.request, e.files.response, e.files.token]) expect(fs.existsSync(path.join(rep, f)), f).to.equal(true);
      const jeton = new Uint8Array(fs.readFileSync(path.join(rep, e.files.token)));
      expect(N.sha256Hex(jeton)).to.equal(e.token_sha256);
      const reponse = new Uint8Array(fs.readFileSync(path.join(rep, e.files.response)));
      expect(N.sha256Hex(lireReponse(reponse).token)).to.equal(e.token_sha256, "jeton extrait octet pour octet de la réponse");
      const prestataire = configuration.rfc3161.providers.find((p) => p.id === e.provider_id);
      const v = verifierJeton({ octets: jeton, imprintAttendue: e.imprint, ancres: { certificatsPem: prestataire.anchor_certificates, politiquesAdmises: prestataire.accepted_policies }, aGenTime: true });
      expect(Object.values(v.checks).every((s) => s === "reussi"), JSON.stringify(v.checks)).to.equal(true);
      expect(e.qualified === null).to.equal(e.provider_role === "interne");
      expect(e.attempt_id).to.match(/^(jeton_point|jeton_periode):[0-9a-f]{16}:[0-9]+$/);
    }
    expect(obtenues.find((e) => e.object === "manifeste").provider_id).to.equal("qtsa-principal");
    expect(obtenues.find((e) => e.object === "manifeste").qualified).to.not.equal(null);
  });

  it("mise à niveau OpenTimestamps (EX-6.6) : première tentative first_after_s après la soumission (404 en attente), chemin complet fusionné et vérifié, nouvelle version ots/<objet>-2.ots, entetes-bitcoin.json écrit une fois toutes les preuves complètes (EX-6.8), ots_complete et réexport", async function () {
    if (!pret.call(this)) return;
    const depotOts = DepotOts.ouvrir({ racine: path.join(dir, "stockage"), orgId: ORG, journalId: JOURNAL });
    const objetPoint = `point-${composant.demandes().find((d) => d.kind === "ots_point").subject.hash.slice(2)}`;
    expect(depotOts.versions({ periodStart: PERIODE, objet: "manifeste" }).map((v) => v.version)).to.deep.equal([1]);
    expect(depotOts.versions({ periodStart: PERIODE, objet: objetPoint }).map((v) => v.version)).to.deep.equal([1]);
    // 08:11 : la première mise à niveau de la période (first_after_s = 600) a eu lieu, 404 en attente.
    await horloge.aller(T0 + 3600000 + 11 * 60000, calme);
    const avant = calendriers.etat.requetes.filter((r) => r.methode === "GET").length;
    expect(avant).to.be.at.least(2);
    expect(composant.demandes().filter((d) => d.kind.startsWith("ots_")).every((d) => d.state === "en_attente")).to.equal(true);
    calendriers.completer(1010);
    await horloge.avancer(3 * 60000, calme);
    const ots = composant.demandes().filter((d) => d.kind.startsWith("ots_"));
    expect(ots.map((d) => d.state)).to.deep.equal(["complete", "complete"]);
    expect(depotOts.versions({ periodStart: PERIODE, objet: "manifeste" }).map((v) => v.version)).to.deep.equal([1, 2]);
    expect(depotOts.versions({ periodStart: PERIODE, objet: objetPoint }).map((v) => v.version)).to.deep.equal([1, 2]);
    const entetes = depotOts.lireEntetes(PERIODE);
    expect(entetes, "entetes-bitcoin.json de la période").to.not.equal(null);
    expect(entetes.start_height).to.equal(0);
    for (const d of ots) {
      const derniere = depotOts.derniere({ periodStart: PERIODE, objet: d.kind === "ots_periode" ? "manifeste" : objetPoint });
      expect(N.sha256Hex(derniere.octets)).to.equal(d.result.sha256);
      const v = verifierOts({ octets: derniere.octets, empreinteAttendue: d.subject.hash, entetes: entetes.document, reseau: "regtest" });
      expect(v.checks).to.deep.equal({ "O-1": "reussi", "O-2": "reussi", "O-3": "reussi", "O-4": "reussi", "O-5": "reussi", "O-7": "reussi" });
      expect(lireOts(derniere.octets).empreinteHex).to.equal(d.subject.hash);
    }
    expect(journal.de("ots_complete")).to.have.lengthOf(2);
    expect(journal.de("ots_complete").every((l) => l.data.reexport === true)).to.equal(true);
    expect(journal.de("ots_upgraded")).to.have.lengthOf(2);
    expect(journal.de("bitcoin_headers_written")).to.have.lengthOf(1);
  });

  it("T-10 différée (EX-5.10 étape 10) : à genTime + delay_s, CRL capturées aux points de distribution, .crl.pem écrits, ligne d'acquisition complétée (revoked false), aucune relève", async function () {
    if (!pret.call(this)) return;
    await horloge.aller(T0 + 3600000 + 20 * 60000, calme);
    expect(composant.etat().t10_en_attente).to.equal(0);
    const depot = DepotAncres.ouvrir({ racine: path.join(dir, "stockage"), orgId: ORG, journalId: JOURNAL });
    const rep = depot.repertoire(PERIODE);
    const dernieres = depot.dernieresAcquisitions(PERIODE).enregistrements.filter((e) => e.outcome === "obtenue" && e.promoted);
    expect(dernieres).to.have.lengthOf(7);
    for (const e of dernieres) {
      expect(e.checks["T-10"], e.attempt_id).to.equal("reussi");
      expect(e.revoked).to.equal(false);
      expect(e.files.crls).to.deep.equal([`rfc3161/${e.object_name}-${e.provider_id}-${e.attempt_id}.crl.pem`]);
      expect(fs.readFileSync(path.join(rep, e.files.crls[0]), "utf8")).to.include("-----BEGIN X509 CRL-----");
      expect(depot.promu(e.object, PERIODE, e.imprint).attempt_id).to.equal(e.attempt_id);
    }
    expect(journal.de("crl_captured")).to.have.lengthOf(7);
    expect(journal.de("crl_captured").every((l) => l.data.status === "reussi")).to.equal(true);
    expect(crl.requetes.length).to.be.at.least(7);
    expect(composant.demandes().filter((d) => d.kind.startsWith("jeton_")).every((d) => d.state === "obtenue")).to.equal(true);
  });

  it("file durable : une demande par id, états finaux, ligne envoyee avant chaque envoi (AN-32, AN-33) ; captures du registre (points, période, clôture) écrites avant obtenue (AN-48)", async function () {
    if (!pret.call(this)) return;
    const relue = lireFiles(configuration.queue.path);
    expect(relue.tronquees).to.deep.equal([]);
    expect(relue.fichiers).to.deep.equal(["file-1.ndjson"]);
    const ids = relue.demandes.map((d) => d.id);
    expect(new Set(ids).size).to.equal(ids.length);
    expect(relue.demandes.every((d) => ETATS_FINAUX.includes(d.state))).to.equal(true);
    // Chaque requête reçue par les serveurs RFC 3161 porte un nonce qu'une ligne envoyee de la file a consigné d'abord.
    const lignes = fs.readFileSync(path.join(configuration.queue.path, "file-1.ndjson"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    const nonces = new Set(lignes.filter((l) => l.state === "envoyee").flatMap((l) => l.attempts.map((a) => a.nonce)).filter(Boolean));
    const depot = DepotAncres.ouvrir({ racine: path.join(dir, "stockage"), orgId: ORG, journalId: JOURNAL });
    for (const e of depot.lireAcquisitions(PERIODE).enregistrements) expect(nonces.has(e.nonce), e.attempt_id).to.equal(true);
    const captures = fs.readdirSync(path.join(dir, "captures")).filter((n) => n.startsWith("capture-"));
    expect(captures.filter((n) => n.endsWith("-ancre.json"))).to.have.lengthOf(9);
    expect(captures.filter((n) => n.endsWith("-cloture.json"))).to.have.lengthOf(1);
    for (const d of relue.demandes.filter((x) => x.kind.startsWith("ancre_registre_"))) {
      const index = captures.map((n) => JSON.parse(fs.readFileSync(path.join(dir, "captures", n), "utf8"))).find((i) => N.sha256Hex(N.utf8(JSON.stringify(i, null, 2) + "\n")) === d.result.sha256 || true);
      expect(index).to.not.equal(undefined);
    }
  });

  it("métriques d'EX-8.15 (noms exacts) et lignes de journal ; aucune donnée de client ni secret dans la file, le journal ou les acquisitions (AN-43)", async function () {
    if (!pret.call(this)) return;
    const m = composant.metriques();
    for (const nom of Object.keys(METRIQUES_ANCRAGE)) expect(m).to.include(`# TYPE ${nom}`);
    expect(m).to.include('noortrace_anchoring_attempts_total{kind="jeton_point",provider="tsa-interne",outcome="obtenue"} 6');
    expect(m).to.include('noortrace_anchoring_attempts_total{kind="jeton_periode",provider="qtsa-principal",outcome="obtenue"} 1');
    expect(m).to.match(/noortrace_anchoring_deadlines_total\{state="satisfaite"\} 7/);
    expect(m).to.match(/noortrace_anchoring_deadlines_total\{state="sans_objet"\} 5/);
    expect(m).to.match(/noortrace_anchor_pending\{anchor="rfc3161"\} 0/);
    expect(m).to.match(/noortrace_anchoring_window_s\{journal="41c24036"\} \d+/);
    const evenements = new Set(journal.evenements());
    for (const e of ["anchoring_started", "anchoring_queue_rebuilt", "checkpoint_countersigned", "deadline_sans_objet", "period_timestamped", "checkpoint_not_anchored", "ots_submitted", "ots_upgraded", "ots_complete"]) expect(evenements, e).to.include(e);
    const secretsTexte = [
      Buffer.from(tls.client).toString("utf8").match(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/)[0].split("\n")[1],
      Buffer.from(N.sha256(N.utf8("noortrace/ancrage/test/composant/cle-chaine-01"))).toString("hex"),
    ];
    const fichiers = [path.join(configuration.queue.path, "file-1.ndjson"), path.join(dir, "stockage", ORG.slice(2), JOURNAL.slice(2), "ancres", `periode-${PERIODE}`, "acquisitions.ndjson")];
    const textes = [JSON.stringify(journal.lignes), ...fichiers.map((f) => fs.readFileSync(f, "utf8"))];
    for (const t of textes) {
      for (const s of secretsTexte) expect(t.includes(s)).to.equal(false);
      expect(t.toLowerCase()).to.not.include("private key");
    }
    // Aucun jeton (octets DER) ni aucune pièce dans le journal d'exploitation ni dans la file : seules les tailles et les SHA-256.
    const depot = DepotAncres.ouvrir({ racine: path.join(dir, "stockage"), orgId: ORG, journalId: JOURNAL });
    const jetons = depot.lireAcquisitions(PERIODE).enregistrements.filter((e) => e.files.token).map((e) => fs.readFileSync(path.join(depot.repertoire(PERIODE), e.files.token)).toString("hex").slice(0, 64));
    for (const j of jetons) expect(textes[0].includes(j) || textes[1].includes(j)).to.equal(false);
    for (const l of journal.lignes) expect(l.component).to.equal("ancrage");
  });

  it("arrêt : anchoring_stopped, file fermée ; une remise après l'arrêt est consignée anchor_pending et n'est jamais ancrée", async function () {
    if (!pret.call(this)) return;
    await composant.arreter();
    expect(journal.evenements()).to.include("anchoring_stopped");
    const r = await composant.remettrePoint(remisePoint(serie.points[0]));
    expect(r).to.deep.equal({ admis: false, regle: "composant_non_demarre" });
    expect(journal.de("anchor_pending").at(-1).data.reason).to.equal("composant_non_demarre");
  });
});
