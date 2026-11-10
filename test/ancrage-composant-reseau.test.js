// Composant d'ancrage (lot F1) : essais qui exigent un réseau.
//
// (iii) Le parcours d'une période contre le réseau de développement réel
// (CT-4 §7.4 : quatre validateurs noorcore, `bash chain/scripts/dev-net.sh
// start`), avec le client inscrit par le parcours de référence
// `npm run e2e:registre -- --garder-reseau --sortie <répertoire> --verificateur-go <binaire>`
// exécuté comme une boîte noire (NOORTRACE_PARCOURS_REGISTRE désigne son
// répertoire de sortie ; à défaut il est joué ici quand NOORTRACE_VERIFIER_BIN
// nomme le vérificateur Go de CT-6). Serveurs RFC 3161 du lot E et calendriers
// factices locaux ; horloge hybride : le temps simulé avance avec le temps
// réel et saute entre deux points. En attente, condition nommée dans le
// titre, quand le réseau n'est pas debout.
//
// (iv) La fiche de prestataire et l'épreuve d'acceptation d'EX-11.4 sur deux
// autorités publiques (SwissSign, DFN) par le composant et par le binaire
// `noortrace-ancrage fiche --epreuve` ; en attente sans NOORTRACE_TSA_PUBLIQUE=1.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import * as N from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";
import { transportHttps, epreuveAcceptation, acquerir, lireJeton, certificatVersPem, verifierFiche, DepotAncres } from "@noortrace/ancrage/rfc3161";
import { creerComposantAncrage } from "../paquets/ancrage/src/composant.mjs";
import {
  RACINE, HorlogeHybride, attenteCalme, aleatoireFixe, materielTls, serveurCrl, autoriteInterne, qualifiedExemple, calendriersFactices, serieSynthetique,
  remisePoint, remiseCloture, configurationEssai, journalMemoire, transportRfc3161Local, repertoireTemporaire, enAttente, AC_TEST_PEM,
} from "./fixtures/ancrage-composant/outils.mjs";
import { agentDepuisEnvironnement, agentHttpDepuisEnvironnement } from "./fixtures/ancrage-rfc3161/outils.mjs";

const POINTS = ["http://127.0.0.1:8645", "http://127.0.0.1:8646", "http://127.0.0.1:8647", "http://127.0.0.1:8648"];
const IDENTIFIANTS = Object.fromEntries(POINTS.map((p, k) => [p, `v${k + 1}`]));
const EVM = 2124;
const BFT = "noortrace-2124-dev";
const BIN = path.join(RACINE, "paquets", "ancrage", "bin", "noortrace-ancrage");

async function reseauDebout() {
  const rpc = new R.ClientRpc({ points: POINTS, delaiMs: 3000, identifiants: IDENTIFIANTS });
  try {
    for (const p of POINTS) {
      const c = await rpc.appeler("eth_chainId", [], { point: p });
      if (c.erreur || c.resultat !== "0x84c") return { ok: false, condition: `le validateur ${p} ne répond pas eth_chainId 0x84c (bash chain/scripts/dev-net.sh start)` };
    }
    const m = await rpc.appeler("noor_getCommitCertificate", ["latest"]);
    if (m.erreur && m.erreur.code === -32601) return { ok: false, condition: "le binaire noorcore ne sert pas noor_getCommitCertificate (CT-4 §9.1)" };
    return { ok: true, rpc };
  } catch (e) {
    return { ok: false, condition: `le réseau de développement n'est pas debout (${e.message}) : bash chain/scripts/dev-net.sh start` };
  }
}

function parcours(travail) {
  const donne = process.env.NOORTRACE_PARCOURS_REGISTRE ?? null;
  if (donne && fs.existsSync(path.join(donne, "cles", "cle-chaine-rec-demo-01.cle"))) return { ok: true, repertoire: donne };
  const go = process.env.NOORTRACE_VERIFIER_BIN ?? null;
  if (!go || !fs.existsSync(go)) return { ok: false, condition: "aucun parcours d'inscription (NOORTRACE_PARCOURS_REGISTRE) et vérificateur Go de CT-6 absent (NOORTRACE_VERIFIER_BIN) pour exécuter npm run e2e:registre" };
  const sortie = path.join(travail, "parcours");
  const r = spawnSync("npm", ["run", "e2e:registre", "--", "--garder-reseau", "--sortie", sortie, "--verificateur-go", go], { cwd: RACINE, encoding: "utf8", timeout: 600000 });
  if (r.status !== 0) return { ok: false, condition: `le parcours npm run e2e:registre a échoué (code ${r.status})` };
  return { ok: true, repertoire: sortie };
}

describe("ancrage, composant F1 : une période contre le réseau de développement (CT-5 §9 ; CT-4 §8.2, §8.6, §9.4)", function () {
  this.timeout(900000);
  let travail;
  let ctx = null;
  const fermetures = [];

  before(async function () {
    travail = repertoireTemporaire("noortrace-ancrage-f1-reseau-");
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
    const tls = materielTls(path.join(travail, "tls"));
    if (!tls) {
      ctx = { condition: "openssl indisponible pour le matériel TLS" };
      return;
    }
    const lireJson = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
    const cles = lireJson(path.join(p.repertoire, "cles", "cles-essai.json"));
    const inscription = lireJson(path.join(p.repertoire, "demande-inscription.json"));
    const recorder = lireJson(path.join(p.repertoire, "cles", "rec-demo-01.json"));
    const graine = N.hexVersOctets(fs.readFileSync(path.join(p.repertoire, "cles", "rec-demo-01.graine"), "utf8").trim(), 32);
    const cleChaine = R.SignataireChaineFichier.depuisOctets(new Uint8Array(fs.readFileSync(path.join(p.repertoire, "cles", "cle-chaine-rec-demo-01.cle"))));
    const approbateurs = [1, 2, 3].map((k) => R.SignataireChaineFichier.depuisOctets(new Uint8Array(fs.readFileSync(path.join(p.repertoire, "cles", `approbateur-${k}.cle`)))));
    expect(cleChaine.adresse()).to.equal(cles.recorders[0].chain_key);
    const orgId = inscription.fields.org_id;
    const journalId = inscription.fields.journal_id;
    const deploiement = lireJson(path.join(RACINE, "deployments", "noorcore.json"));
    const contrats = {
      attestation_registry: deploiement.contrats.AttestationRegistry.adresse.toLowerCase(),
      period_registry: deploiement.contrats.PeriodRegistry.adresse.toLowerCase(),
      recorder_registry: deploiement.contrats.RecorderRegistry.adresse.toLowerCase(),
    };
    const fichierJeu = [path.join(RACINE, "chain", "runtime", "validators.json"), path.join(RACINE, "test", "fixtures", "certificat-commit", "validators.json")].find((f) => fs.existsSync(f));
    const jeux = { ...lireJson(fichierJeu), source: "validators.json du réseau de développement, clés publiques seulement" };
    const instance = { evmChainId: EVM, bftChainId: BFT, contrats, fees: { gas_limit: 3000000, gas_limit_max: 16777216 }, jeux };
    // La période suit celle que le parcours a close (OP-10 : continuité de temps et de séquence).
    const dernier = await R.latestPeriodOf({ rpc: reseau.rpc, contrat: contrats.period_registry, orgId, journalId });
    expect(dernier > 0n).to.equal(true, "le parcours a clos une première période");
    const precedente = await R.getPeriod({ rpc: reseau.rpc, contrat: contrats.period_registry, id: dernier });
    const periodStart = Number(precedente.periodEnd);
    const firstSeq = Number(precedente.lastSeq) + 1;
    // Une transaction de la clé de chaîne encore en mempool (essai antérieur interrompu) fausserait les nonces : l'essai attend.
    const [enAttenteNonce, dernierNonce] = await Promise.all(["pending", "latest"].map((t) => reseau.rpc.appeler("eth_getTransactionCount", [cleChaine.adresse(), t]).then((r) => r.resultat)));
    if (enAttenteNonce !== dernierNonce) {
      ctx = { condition: `une transaction de la clé de chaîne ${cleChaine.adresse()} attend encore en mempool (nonce ${dernierNonce} → ${enAttenteNonce})` };
      return;
    }
    const horloge = new HorlogeHybride(periodStart * 1000);
    const aleatoire = aleatoireFixe(17);
    const crl = await serveurCrl(horloge);
    const interne = await autoriteInterne({ nom: "tsa-interne", dir: travail, role: "interne", horloge, aleatoire, crl, politique: "1.3.6.1.4.1.99999.2.1" });
    const principal = await autoriteInterne({ nom: "qtsa-principal", dir: travail, role: "principal", horloge, aleatoire, crl, tls, qualified: qualifiedExemple("AT"), politique: "1.3.6.1.4.1.99999.3.1" });
    const secours = await autoriteInterne({ nom: "qtsa-secours", dir: travail, role: "secours", horloge, aleatoire, crl, tls, qualified: qualifiedExemple("PL"), politique: "1.3.6.1.4.1.99999.3.2" });
    const fichierEntetes = path.join(travail, "entetes-regtest.json");
    const calendriers = await calendriersFactices({ fichierEntetes });
    fermetures.push(() => interne.fermer(), () => principal.fermer(), () => secours.fermer(), () => calendriers.fermer(), () => crl.fermer());
    const evenements = Object.fromEntries([5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55].map((m) => [m, 1]));
    const serie = serieSynthetique({
      periodStart, cK: 300, keyId: recorder.key_id, graine, orgId, journalId, firstSeq, prevPeriodHash: precedente.periodHash, evenementsAuxMinutes: evenements, evenementsCloture: 1,
      // Les empreintes changent à chaque exécution : une ancre déjà faite sur le réseau par un essai antérieur ne serait pas rejouée (EX-9.3, idempotence).
      sel: `${Date.now()}/`,
      lastHashAvant: N.sha256Hex(N.utf8(`noortrace/ancrage/test/reseau/last-hash/${periodStart}`)),
    });
    const configuration = configurationEssai({
      prestataires: [principal.prestataire, secours.prestataire, interne.prestataire], dir: travail, calendriers, fichierEntetes,
      surcharges: { checkpoint_interval_s: 300, rfc3161: { checkpoints: { interval_s: 600 } } },
    });
    const secrets = new Map([["/rfc3161/providers/0/auth/secret", tls.client], ["/rfc3161/providers/1/auth/secret", tls.client]]);
    const remis = [];
    const journal = journalMemoire();
    const composant = creerComposantAncrage({
      configuration,
      profil: "test",
      checkpointIntervalEnregistreur: 300,
      contexte: {
        org_id: orgId,
        journal_id: journalId,
        epoque: 1,
        racineStockage: path.join(travail, "stockage"),
        secrets,
        clePublique: (keyId) => (keyId === recorder.key_id ? serie.clePublique : null),
        lireSerie: async () => remis.slice(),
        lireHashesPeriode: async (P) => (P === periodStart ? serie.hashes : null),
        listerPeriodes: async () => [],
        listerPoints: async () => [],
        cleChaine,
        signaturesCloture: async (periodMeta) => {
          const condense = R.periodDigest(EVM, contrats.period_registry, periodMeta);
          const hachage = R.hachageSigne(condense);
          const seuil = inscription.signer_set.threshold;
          const signatures = approbateurs.slice(0, seuil).map((a) => ({ signer: a.adresse(), ...a.signerCondense(hachage) })).sort((x, y) => (x.signer < y.signer ? -1 : 1));
          return { signatures, membres: cles.approvers.map((a) => a.toLowerCase()), seuil, periodePrecedente: { period_end: precedente.periodEnd.toString(), last_seq: precedente.lastSeq.toString() } };
        },
      },
      horloge,
      aleatoire,
      journal,
      clients: {
        rfc3161: { transport: transportRfc3161Local(tls) },
        ots: { transport: calendriers.transport },
        registre: { rpc: reseau.rpc, instance, repertoireEnvois: path.join(travail, "captures"), delais: { recuMs: 60000, sondageMs: 250 } },
      },
    });
    ctx = { rpc: reseau.rpc, contrats, instance, cleChaine, orgId, journalId, periodStart, horloge, composant, serie, remis, journal, calendriers, configuration, jeux, calme: attenteCalme(composant, { maxMs: 180000, attentesReelles: true }) };
  });

  after(async function () {
    if (ctx?.composant?.etat().demarre) await ctx.composant.arreter({ attendre: false }).catch(() => undefined);
    for (const f of fermetures) await f().catch(() => undefined);
    if (travail) fs.rmSync(travail, { recursive: true, force: true });
  });

  function pret() {
    if (!ctx || ctx.condition) {
      enAttente(this, ctx?.condition ?? "contexte non préparé");
      return false;
    }
    return true;
  }

  it("rejoue la période (points toutes les 300 s, échéances toutes les 600 s, clôture) : ancres des points incluses et capturées sur le réseau (AN-44 à AN-48), jetons des points, ancre de la période puis jeton qualifié puis submitPeriod (EX-8.4, CT-4 §8.2)", async function () {
    if (!pret.call(this)) return;
    const { composant, horloge, serie, remis, calme, journal } = ctx;
    await composant.demarrer();
    for (const point of serie.points.slice(0, -1)) {
      await horloge.aller(N.decoderHorodatage(point.checkpoint_ts), calme);
      remis.push(point);
      const r = await composant.remettrePoint(remisePoint(point));
      expect(r.admis, point.checkpoint_ts).to.equal(true);
      await calme();
    }
    const cloture = serie.points.at(-1);
    await horloge.aller(N.decoderHorodatage(cloture.checkpoint_ts), calme);
    remis.push(cloture);
    expect((await composant.remettrePoint(remisePoint(cloture))).admis).to.equal(true);
    expect((await composant.remettreCloture(remiseCloture(serie))).admis).to.equal(true);
    await calme();
    await horloge.avancer(60000, calme);
    const file = composant.demandes();
    const par = (kind, state) => file.filter((d) => d.kind === kind && (state === undefined || d.state === state));
    expect(par("ancre_registre_point", "obtenue"), JSON.stringify(par("ancre_registre_point").map((d) => [d.subject.tree_size, d.state, d.attempts.map((a) => a.error_code)]))).to.have.lengthOf(12);
    expect(par("jeton_point", "obtenue")).to.have.lengthOf(5);
    expect(par("ancre_registre_periode", "obtenue")).to.have.lengthOf(1);
    expect(par("jeton_periode", "obtenue")).to.have.lengthOf(1);
    expect(par("jeton_periode")[0].result.provider).to.equal("qtsa-principal");
    expect(par("ots_periode", "en_attente")).to.have.lengthOf(1);
    expect(par("ots_point", "en_attente")).to.have.lengthOf(1);
    expect(journal.de("period_submitted"), JSON.stringify(journal.de("registry_pending").map((l) => l.data))).to.have.lengthOf(1);
    expect(journal.de("checkpoint_countersigned")).to.have.lengthOf(5);
    expect(journal.de("period_timestamped")).to.have.lengthOf(1);
    // Captures : une par ancre (points et période) et une pour la clôture ; CP-1 à CP-6 relues hors ligne (lot D).
    const captures = fs.readdirSync(path.join(travail, "captures")).filter((n) => n.startsWith("capture-"));
    expect(captures.filter((n) => n.endsWith("-ancre.json"))).to.have.lengthOf(13);
    expect(captures.filter((n) => n.endsWith("-cloture.json"))).to.have.lengthOf(1);
    for (const nom of captures) {
      const index = JSON.parse(fs.readFileSync(path.join(travail, "captures", nom), "utf8"));
      expect(R.verifierIndexCapture(index).valide, nom).to.equal(true);
      expect(index.checks.every((c) => c.status === "reussi"), nom).to.equal(true);
      expect(POINTS).to.include(index.node.rpc);
      const v = R.verifierCapture({ fichiers: path.join(travail, "captures"), index, jeux: ctx.jeux, bftChainId: BFT });
      expect(v.premierEchec, nom).to.equal(null);
    }
    // Lectures d'état : l'empreinte de la période est ancrée par la clé de chaîne, la période est connue (OP-9, OP-12).
    const empreinte = N.empreinteAncre(ctx.orgId, ctx.journalId, serie.periodHash);
    const l = await R.lookup({ rpc: ctx.rpc, contrat: ctx.contrats.attestation_registry, fingerprint: empreinte });
    expect(l.anchored).to.equal(true);
    expect(l.issuer).to.equal(ctx.cleChaine.adresse());
    expect(l.docType).to.equal(R.DOC_TYPE_PERIODE);
    expect(await R.isKnown({ rpc: ctx.rpc, contrat: ctx.contrats.period_registry, orgId: ctx.orgId, periodHash: serie.periodHash })).to.equal(true);
    for (const d of par("ancre_registre_point", "obtenue")) {
      const lp = await R.lookup({ rpc: ctx.rpc, contrat: ctx.contrats.attestation_registry, fingerprint: N.empreinteAncre(ctx.orgId, ctx.journalId, d.subject.hash) });
      expect(lp.anchored && lp.docType === R.DOC_TYPE_POINT_DE_CONTROLE && lp.issuer === ctx.cleChaine.adresse(), d.id).to.equal(true);
    }
    for (const l2 of journal.de("checkpoint_countersigned")) expect(l2.data.d_point_s + l2.data.d_attente_s + l2.data.d_releve_s + l2.data.d_tsa_s).to.equal(l2.data.d_jeton_s);
  });

  it("mise à niveau OpenTimestamps et T-10 différée sur le même parcours : preuves complètes, entetes-bitcoin.json, CRL capturées ; métriques d'EX-8.15 ; aucun secret dans la file ni le journal", async function () {
    if (!pret.call(this)) return;
    const { composant, horloge, calme, journal, calendriers, periodStart } = ctx;
    await horloge.avancer(11 * 60000, calme);
    calendriers.completer(1010);
    await horloge.avancer(3 * 60000, calme);
    const ots = composant.demandes().filter((d) => d.kind.startsWith("ots_"));
    expect(ots.map((d) => d.state)).to.deep.equal(["complete", "complete"]);
    expect(journal.de("bitcoin_headers_written")).to.have.lengthOf(1);
    expect(composant.etat().t10_en_attente).to.equal(0);
    const depot = DepotAncres.ouvrir({ racine: path.join(travail, "stockage"), orgId: ctx.orgId, journalId: ctx.journalId });
    const promus = depot.dernieresAcquisitions(periodStart).enregistrements.filter((e) => e.outcome === "obtenue" && e.promoted);
    expect(promus).to.have.lengthOf(6);
    expect(promus.every((e) => e.checks["T-10"] === "reussi" && e.revoked === false)).to.equal(true);
    const m = composant.metriques();
    expect(m).to.include('noortrace_anchoring_attempts_total{kind="jeton_point",provider="tsa-interne",outcome="obtenue"} 5');
    expect(m).to.match(/noortrace_anchor_pending\{anchor="registre"\} 0/);
    const textes = [JSON.stringify(journal.lignes), fs.readFileSync(path.join(ctx.configuration.queue.path, "file-1.ndjson"), "utf8")];
    const cle = fs.readFileSync(path.join(process.env.NOORTRACE_PARCOURS_REGISTRE ?? path.join(travail, "parcours"), "cles", "cle-chaine-rec-demo-01.cle"), "utf8").trim().replace(/^0x/, "");
    for (const t of textes) {
      expect(t.toLowerCase()).to.not.include(cle.toLowerCase().slice(0, 32));
      expect(t.toLowerCase()).to.not.include("private key");
    }
    await composant.arreter();
    expect(journal.evenements()).to.include("anchoring_stopped");
  });
});

describe("ancrage, composant F1 : fiche et épreuve d'acceptation sur des autorités publiques (EX-10.6, EX-11.4, AN-54, AN-57)", function () {
  this.timeout(300000);
  const AUTORITES = [
    { id: "swisssign-public", url: "https://tsa.swisssign.net" },
    { id: "dfn-zeitstempel", url: "https://zeitstempel.dfn.de" },
  ];
  const condition = () => (process.env.NOORTRACE_TSA_PUBLIQUE === "1" ? null : "réseau public joignable (NOORTRACE_TSA_PUBLIQUE=1)");
  const horloge = { murale: () => Date.now(), monotone: () => performance.now(), programmer: (ms, fn) => { const t = setTimeout(fn, ms); return () => clearTimeout(t); } };
  const aleatoire = (n) => new Uint8Array(randomBytes(n));
  let dir;
  before(function () {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-ancrage-f1-public-"));
  });
  after(function () {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  for (const a of AUTORITES) {
    it(`${a.id} : fiche construite et vérifiée par le composant avec l'épreuve d'EX-11.4 (jeton obtenu, T-1 à T-9), puis par le binaire noortrace-ancrage fiche --epreuve (code 0) ; aucune valeur de secret affichée`, async function () {
      const c = condition();
      if (c) return enAttente(this, c);
      const transport = transportHttps({ agent: agentDepuisEnvironnement(), agentHttp: agentHttpDepuisEnvironnement() });
      const base = {
        id: a.id, role: "second_rang", url: a.url, auth: { method: "aucune", secret: null }, hash: "sha256", policy_oid: null, accepted_policies: null,
        anchor_certificates: [AC_TEST_PEM], qualified: null, min_interval_ms: 15000, request_timeout_ms: 20000, correlation_header: null,
        source: `autorité publique, essai d'interface du composant du ${new Date().toISOString().slice(0, 10)} ; non déclarée qualified`,
      };
      // Les certificats d'AC de la chaîne reçue servent d'anchor_certificates (essai d'interface, comme le lot A).
      const premier = await epreuveAcceptation({ prestataire: base, transport, horloge, aleatoire });
      expect(premier.http_status).to.equal(200);
      const chaine = await acquerir({ prestataire: base, imprint: premier.imprint, objet: "point", attempt: 2, horloge, aleatoire, depot: null, transport });
      expect(chaine.jeton, "jeton reçu").to.not.equal(null);
      const lu = lireJeton(chaine.jeton);
      const ac = lu.certificats.filter((x) => x.contraintesBase && x.contraintesBase.ca);
      const ancres = (ac.length > 0 ? ac : lu.certificats).map((x) => certificatVersPem(x.octets));
      const prestataire = { ...base, anchor_certificates: ancres };
      // Un prestataire public sans compte n'est pas configurable (EX-5.5 : auth aucune pour le seul rôle interne) : la configuration est refusée par AN-1,
      // mais la fiche et l'épreuve, qui ne dépendent pas du démarrage, sont jouées par le composant.
      const configuration = { version: 0, checkpoint_interval_s: 60, rfc3161: { providers: [{ ...prestataire, role: "principal" }], manifest: { fallback_after_s: 300 }, checkpoints: { interval_s: 300, provider_role: "principal", fallback_after_s: 120, countersign_idle: false }, freshness: { max_response_delay_s: 60, clock_tolerance_s: 120 }, retry: { initial_ms: 5000, factor: 2, max_ms: 300000, jitter_ms: 250 }, retention_years: 10, crl_capture: { enabled: true, delay_s: 600 } }, registry: { checkpoints: "nouveaux_evenements", squat_wait_s: 5, inclusion_alert_s: 60 }, opentimestamps: { enabled: false, calendars: [], min_responses: 1, timeout_ms: 5000, checkpoint: "aucun", upgrade: { whitelist: [], first_after_s: 21600, interval_s: 1800, give_up_after_s: 1209600 }, headers_source: null }, queue: { path: path.join(dir, "file"), max_pending: 100, anchor_pending_alert_s: 7200 } };
      const composant = creerComposantAncrage({ configuration, profil: "test", contexte: { org_id: "0x" + "11".repeat(32), journal_id: "0x" + "22".repeat(32), epoque: 1, racineStockage: dir, secrets: new Map() }, horloge, aleatoire, clients: { rfc3161: { transport } } });
      expect(composant.configurationValide().valide).to.equal(false);
      expect(composant.configurationValide().erreurs.map((e) => e.regle)).to.include("4");
      const { fiche, verification } = await composant.fiche(a.id, { epreuve: true });
      console.log(`      ${a.id} : ${JSON.stringify({ outcome: fiche.acceptance_test.outcome, error_code: fiche.acceptance_test.error_code, checks_passed: fiche.acceptance_test.checks_passed.length, gen_time: fiche.acceptance_test.gen_time, tsu: fiche.acceptance_test.tsu_subject_cn })}`);
      expect(verification.ecarts).to.deep.equal([]);
      expect(fiche.acceptance_test.outcome).to.equal("obtenue");
      expect(fiche.acceptance_test.checks_passed).to.have.lengthOf(9);
      expect(fiche).to.not.have.property("auth");
      // Le binaire : fiche --epreuve sur le même prestataire (transport direct de production).
      const fichierPrestataire = path.join(dir, `${a.id}.json`);
      fs.writeFileSync(fichierPrestataire, JSON.stringify(prestataire, null, 2));
      const sortie = path.join(dir, `prestataire-${a.id}.json`);
      const r2 = spawnSync(process.execPath, [BIN, "fiche", "--prestataire", fichierPrestataire, "--epreuve", "--sortie", sortie], { encoding: "utf8", timeout: 120000, env: { ...process.env, HTTPS_PROXY: "", https_proxy: "" } });
      console.log(`      ${a.id} binaire : code ${r2.status} ; ${r2.stdout.trim().split("\n").slice(0, 3).join(" | ")}`);
      expect(r2.status, r2.stderr).to.equal(0);
      expect(r2.stdout).to.include("conforme (AN-54)");
      expect(r2.stdout).to.include("épreuve d'acceptation (EX-11.4)");
      const ecrite = JSON.parse(fs.readFileSync(sortie, "utf8"));
      expect(verifierFiche(ecrite).conforme).to.equal(true);
      expect(ecrite.acceptance_test.outcome).to.equal("obtenue");
    });
  }
});
