// TI-16 de CT-9 (CT-5 §5, §6, §10.2, §11 : EX-5.2, EX-5.4 à EX-5.6, EX-5.8,
// EX-5.9, EX-5.14 à EX-5.16, EX-6.8 à EX-6.10, EX-11.1 à EX-11.5, AN-7,
// AN-12, AN-14, AN-15, AN-54 à AN-58) : prestataires RFC 3161 et calendriers
// OpenTimestamps réels.
//
// (i) Sur deux autorités publiques qui répondent sans compte (SwissSign, DFN),
// par le transport de production du lot A : jeton acquis par `acquerir` et
// déposé (EX-5.14, AN-28 : une ligne d'acquisition), accepté par T-1 à T-9 ;
// T-10 par les CRL publiées aux points de distribution du chemin, capturées
// après `genTime` : `reussi` quand une CRL postérieure à `genTime` existe pour
// chaque certificat, sinon `crl_indisponible` consigné (la capture différée
// d'EX-5.10, étape 10, réessaie) ; fiche de prestataire relue conforme
// (EX-10.6, AN-54). En attente hors NOORTRACE_TSA_PUBLIQUE=1.
// (ii) `min_interval_ms` (EX-5.5, EX-8.7) tenu par le composant sur un
// prestataire réel : l'autorité publique est servie au composant par un
// relais HTTP local (rôle `interne`, seule forme qu'AN-1 admet sans compte,
// lecture F1-8 du LISEZMOI) ; deux points consécutifs, deux requêtes espacées
// d'au moins `min_interval_ms` (mesure dans le journal du relais et dans
// `acquisitions.ndjson`, `anchor_retry` de raison `backoff`). Aucune horloge
// n'est manipulée pendant la mesure (horloge hybride, temps réel).
// (iii) Preuve `.ots` d'une racine auprès de deux calendriers publics
// (agrégateurs d'EX-6.2) : en attente, O-1 et O-3 réussies ; en attente hors
// NOORTRACE_RESEAU_PUBLIC=1.
// Le retrait de qualification du principal sans rechargement (EX-5.9, TC-24)
// est éprouvé hors réseau par test/ancrage-composant-pannes.test.js (« retrait
// de la qualification (EX-5.9 ; TC-24 de CT-9) et rechargement (EX-4.9) »).

import { expect } from "chai";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import path from "node:path";
import { randomBytes } from "node:crypto";
import * as N from "@noortrace/noyau";
import {
  acquerir, epreuveAcceptation, transportHttps, construireFiche, verifierFiche, certificatVersPem, lireJeton, lireCrl, capturerCrls, verifierRevocation, verifierJeton,
  VERIFICATIONS_ACQUISITION, DepotAncres,
} from "@noortrace/ancrage/rfc3161";
import { soumettre, transportHttps as transportOts, verifierOts, etatPreuve, DepotOts } from "@noortrace/ancrage/ots";
import { creerComposantAncrage } from "@noortrace/ancrage";
import { AC_TEST_PEM, agentDepuisEnvironnement, agentHttpDepuisEnvironnement, enAttente, repertoireTemporaire } from "./fixtures/ancrage-rfc3161/outils.mjs";
import {
  HorlogeHybride, attenteCalme, aleatoireFixe, materielTls, serveurCrl, autoriteInterne, qualifiedExemple, calendriersFactices, serieSynthetique, remisePoint,
  configurationEssai, journalMemoire, transportRfc3161Local, registreFactice, CLES_JSON, ORG, JOURNAL,
} from "./fixtures/ancrage-composant/outils.mjs";

const AUTORITES = [
  { id: "swisssign-public", url: "https://tsa.swisssign.net" },
  { id: "dfn-zeitstempel", url: "https://zeitstempel.dfn.de" },
];
const AGREGATEURS = ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org", "https://a.pool.eternitywall.com", "https://ots.btc.catallaxy.com"];
const conditionTsa = () => (process.env.NOORTRACE_TSA_PUBLIQUE === "1" ? null : "réseau public joignable (NOORTRACE_TSA_PUBLIQUE=1)");
const conditionOts = () => (process.env.NOORTRACE_RESEAU_PUBLIC === "1" ? null : "NOORTRACE_RESEAU_PUBLIC=1 (réseau public joignable, soumission réelle d'un engagement d'essai aux agrégateurs OpenTimestamps)");
const horlogeReelle = { murale: () => Date.now(), monotone: () => performance.now() };
const aleatoire = (n) => new Uint8Array(randomBytes(n));
const PERIODE_ESSAI = 1793862000; // 2026-11-05T07:00:00Z (dans la validité de la clé de test rec-test-01 de CT-1 §13)

/**
 * Prestataire `ancrage-v0` d'une autorité publique sans compte (essai
 * d'interface : `anchor_certificates` lus dans la chaîne reçue ; au premier
 * passage, l'AC de test de CT-6 tient la place, T-7 échoue et la réponse est
 * lue pour découvrir la chaîne, comme dans l'essai du lot A).
 */
function prestatairePublic(a, ancres) {
  return {
    id: a.id, role: "second_rang", url: a.url, auth: { method: "aucune", secret: null }, hash: "sha256", policy_oid: null, accepted_policies: null,
    anchor_certificates: ancres.length ? ancres : [AC_TEST_PEM], qualified: null, min_interval_ms: 15000, request_timeout_ms: 20000, correlation_header: null,
    source: `autorité publique, essai TI-16 du ${new Date().toISOString().slice(0, 10)} ; non déclarée qualified`,
  };
}

/** Certificats d'AC lus dans un jeton reçu, en PEM (à défaut, tous les certificats du jeton). */
function ancresDuJeton(octets) {
  const lu = lireJeton(octets);
  const ac = lu.certificats.filter((x) => x.contraintesBase && x.contraintesBase.ca);
  return (ac.length > 0 ? ac : lu.certificats).map((x) => certificatVersPem(x.octets));
}

describe("TI-16 (i) : autorités RFC 3161 publiques (SwissSign, DFN) par le transport de production : jeton acquis et déposé, T-1 à T-9, T-10 par les CRL publiées, fiche relue conforme (CT-5 §5, §10.2, §11)", function () {
  this.timeout(180000);
  let dir;
  before(function () {
    dir = repertoireTemporaire("noortrace-ti16-tsa-");
  });
  after(function () {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  for (const a of AUTORITES) {
    it(`${a.id} (${a.url}) : jeton acquis (acquerir, EX-5.10 étapes 1 à 9) et déposé (EX-5.14, AN-28), accepté par T-1 à T-9 ; T-10 par les CRL capturées après genTime (reussi, ou crl_indisponible consigné) ; fiche de prestataire conforme (AN-54) — en attente hors NOORTRACE_TSA_PUBLIQUE=1`, async function () {
      const c = conditionTsa();
      if (c) return enAttente(this, c);
      const transport = transportHttps({ agent: agentDepuisEnvironnement(), agentHttp: agentHttpDepuisEnvironnement() });
      // Épreuve d'acceptation (EX-11.4) pour connaître la chaîne de l'unité, puis acquisition avec ces ancres.
      const premier = await epreuveAcceptation({ prestataire: prestatairePublic(a, []), transport, horloge: horlogeReelle, aleatoire });
      expect(premier.http_status).to.equal(200);
      const decouverte = await acquerir({ prestataire: prestatairePublic(a, []), imprint: premier.imprint, objet: "point", attempt: 1, horloge: horlogeReelle, aleatoire, depot: null, transport });
      expect(decouverte.jeton, "jeton reçu").to.not.equal(null);
      const ancres = ancresDuJeton(decouverte.jeton);
      const prestataire = prestatairePublic(a, ancres);
      const depot = DepotAncres.ouvrir({ racine: path.join(dir, a.id), orgId: ORG, journalId: JOURNAL });
      const imprint = N.sha256Hex(N.utf8(`noortrace/ancrage/test/ti16/${a.id}/${Date.now()}`));
      // Une réponse transitoire (503, délai) d'un service public est reprise une fois après l'attente d'EX-5.12 (seconde tentative, nouveau nonce).
      let r = null;
      for (let tentative = 1; tentative <= 2; tentative++) {
        r = await acquerir({ prestataire, imprint, objet: "manifeste", attempt: tentative, attemptId: `jeton_periode:${imprint.slice(2, 18)}:${tentative}`, periodStart: PERIODE_ESSAI, deadlineIndex: null, horloge: horlogeReelle, aleatoire, depot, transport, fraicheur: { max_response_delay_s: 60, clock_tolerance_s: 120 }, retry: { initial_ms: 5000, factor: 2, max_ms: 300000, jitter_ms: 0 } });
        if (r.outcome !== "echec_transitoire" || tentative === 2) break;
        console.log(`      ${a.id} : réponse transitoire (${r.code}, HTTP ${r.data.http_status}) ; reprise après ${r.classement?.attenteMs ?? 5000} ms (EX-5.12)`);
        await new Promise((res) => setTimeout(res, Math.min(r.classement?.attenteMs ?? 5000, 15000)));
      }
      console.log(`      ${a.id} : ${JSON.stringify({ outcome: r.outcome, code: r.code, checks: r.data.checks_passed, gen_time: r.data.gen_time, token_size: r.data.token_size, warnings: r.warnings })}`);
      expect(r.outcome, JSON.stringify(r.data)).to.equal("obtenue");
      expect(r.data.nonce_in_response).to.equal(r.enregistrement.nonce);
      expect(r.data.imprint_matches).to.equal(true);
      for (const t of VERIFICATIONS_ACQUISITION) expect(r.verification.checks[t], t).to.equal("reussi");
      // EX-5.14, AN-28 : pièces écrites (requête, réponse, jeton) et une ligne d'acquisition, jamais un secret.
      const lignes = depot.lireAcquisitions(PERIODE_ESSAI).enregistrements;
      const obtenue = lignes.find((l) => l.outcome === "obtenue");
      expect(lignes.length).to.be.within(1, 2);
      expect(obtenue).to.include({ provider_id: a.id, outcome: "obtenue", promoted: true });
      for (const f of [obtenue.files.request, obtenue.files.response, obtenue.files.token]) expect(fs.existsSync(path.join(depot.repertoire(PERIODE_ESSAI), f)), f).to.equal(true);
      // T-10 : CRL capturées aux points de distribution des certificats du chemin, postérieures à genTime (EX-5.10 étape 10).
      const v = verifierJeton({ octets: r.jeton, imprintAttendue: imprint, ancres: { certificatsPem: ancres, politiquesAdmises: null }, aGenTime: true });
      const captures = await capturerCrls({ chemin: v.chemin, transport, horloge: horlogeReelle, apresInstant: v.tstInfo.genTime });
      const crls = captures.filter((x) => x.crl).map((x) => x.crl);
      for (const x of crls) expect(lireCrl(x).complete).to.equal(true);
      const dix = verifierRevocation({ chemin: v.chemin, autorite: { nom: v.autorite.nom, certificat: v.autorite.certificat, identite: v.identite }, crls, crlsJeton: v.jeton.crls, aInstant: v.tstInfo.genTime });
      // `capturerCrls` rend, pour une CRL dont thisUpdate précède genTime, une erreur (« thisUpdate antérieur à genTime ») que le composant consigne `crl_indisponible` et réessaie.
      const indisponibles = captures.filter((x) => x.erreur && /crl_indisponible|thisUpdate antérieur/.test(x.erreur));
      console.log(`      ${a.id} T-10 : ${JSON.stringify({ statut: dix.statut, raison: dix.raison, crl_posterieures_a_genTime: crls.length, chemin: v.chemin.length, crl_indisponible: indisponibles.length, captures: captures.map((x) => ({ sources: x.sources, erreur: x.erreur })) })}`);
      if (crls.length === v.chemin.length) expect(dix.statut, "T-10 avec une CRL postérieure à genTime pour chaque certificat").to.equal("reussi");
      else {
        // Aucune CRL postérieure à genTime n'existe encore pour un certificat du chemin : consigné crl_indisponible, T-10 non exécutée (ancre_absente), à réessayer (EX-5.10 étape 10).
        expect(indisponibles.length).to.be.at.least(1);
        expect(dix).to.include({ statut: "non_execute", raison: "ancre_absente" });
        this.test.title += ` — T-10 : crl_indisponible (aucune CRL postérieure à genTime publiée pour ${indisponibles.length} certificat(s) du chemin au moment de l'essai)`;
      }
      // Fiche de prestataire (EX-10.6) relue : conforme à AN-54, sans auth, avec l'épreuve.
      const epreuve = await epreuveAcceptation({ prestataire, transport, horloge: horlogeReelle, aleatoire });
      expect(epreuve.outcome).to.equal("obtenue");
      const fiche = construireFiche(prestataire, { epreuve });
      const chemin = path.join(dir, `prestataire-${a.id}.json`);
      fs.writeFileSync(chemin, `${JSON.stringify(fiche, null, 2)}\n`);
      const relue = JSON.parse(fs.readFileSync(chemin, "utf8"));
      const verif = verifierFiche(relue);
      expect(verif.conforme, JSON.stringify(verif.ecarts)).to.equal(true);
      expect(relue).to.not.have.property("auth");
      expect(relue.qualified).to.equal(null);
      expect(relue.acceptance_test.outcome).to.equal("obtenue");
    });
  }
});

/**
 * Relais HTTP local vers une autorité publique : il reçoit la requête
 * `TimeStampReq` du composant (rôle `interne`, `http://127.0.0.1`), la
 * transmet telle quelle en HTTPS à l'autorité (par le mandataire HTTPS de
 * l'environnement quand il y en a un) et rend sa réponse ; il consigne
 * l'instant de réception de chaque requête (mesure de `min_interval_ms`).
 */
async function relaisVers(url) {
  const cible = new URL(url);
  const agent = agentDepuisEnvironnement();
  const recues = [];
  const serveur = http.createServer((req, rep) => {
    const morceaux = [];
    req.on("data", (d) => morceaux.push(d));
    req.on("end", () => {
      const corps = Buffer.concat(morceaux);
      recues.push({ at: Date.now(), octets: corps.length });
      const amont = https.request({ host: cible.hostname, port: cible.port || 443, path: cible.pathname, method: "POST", headers: { "Content-Type": "application/timestamp-query", "Content-Length": String(corps.length), Accept: "application/timestamp-reply" }, agent, servername: cible.hostname, minVersion: "TLSv1.2" }, (r) => {
        const parts = [];
        r.on("data", (d) => parts.push(d));
        r.on("end", () => {
          rep.writeHead(r.statusCode ?? 502, { "content-type": r.headers["content-type"] ?? "application/octet-stream" });
          rep.end(Buffer.concat(parts));
        });
      });
      amont.on("error", (e) => {
        rep.writeHead(502, { "content-type": "text/plain" });
        rep.end(String(e.message));
      });
      amont.end(corps);
    });
  });
  await new Promise((r) => serveur.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${serveur.address().port}`, recues, fermer: () => new Promise((r) => { serveur.closeAllConnections?.(); serveur.close(() => r()); }) };
}

describe("TI-16 (ii) : min_interval_ms (EX-5.5, EX-8.7) tenu par le composant sur une autorité publique réelle servie par un relais local (rôle interne) : deux points consécutifs, deux requêtes espacées d'au moins min_interval_ms, mesurées dans le journal", function () {
  this.timeout(300000);
  let dir;
  const fermetures = [];
  before(function () {
    dir = repertoireTemporaire("noortrace-ti16-intervalle-");
  });
  after(async function () {
    for (const f of fermetures) await f().catch(() => undefined);
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("SwissSign derrière le relais, min_interval_ms 15000 : la seconde requête est programmée (anchor_retry backoff) et part au plus tôt 15 s après la première ; les deux jetons sont obtenus (T-1 à T-9) ; aucune requête sous l'intervalle dans le journal du relais ni dans acquisitions.ndjson — en attente hors NOORTRACE_TSA_PUBLIQUE=1", async function () {
    const c = conditionTsa();
    if (c) return enAttente(this, c);
    const a = AUTORITES[0];
    const transportPublic = transportHttps({ agent: agentDepuisEnvironnement(), agentHttp: agentHttpDepuisEnvironnement() });
    const premier = await epreuveAcceptation({ prestataire: prestatairePublic(a, []), transport: transportPublic, horloge: horlogeReelle, aleatoire });
    const decouverte = await acquerir({ prestataire: prestatairePublic(a, []), imprint: premier.imprint, objet: "point", attempt: 1, horloge: horlogeReelle, aleatoire, depot: null, transport: transportPublic });
    expect(decouverte.jeton).to.not.equal(null);
    const ancres = ancresDuJeton(decouverte.jeton);
    const relais = await relaisVers(a.url);
    fermetures.push(relais.fermer);
    // Décor du composant : principal TLS mutuel du lot E (clôture), relais public pour les points ; horloge hybride (temps réel) placée
    // après les deux premières échéances de la période, pour que les deux points remis soient servis à la suite.
    const tls = materielTls(path.join(dir, "tls"));
    if (!tls) return enAttente(this, "openssl indisponible pour le matériel TLS");
    const periodStart = PERIODE_ESSAI;
    const horloge = new HorlogeHybride(periodStart * 1000 + 125000);
    const alea = aleatoireFixe(41);
    const crl = await serveurCrl(horloge);
    fermetures.push(crl.fermer);
    const principal = await autoriteInterne({ nom: "qtsa-principal", dir, role: "principal", horloge, aleatoire: alea, crl, tls, qualified: qualifiedExemple("AT"), politique: "1.3.6.1.4.1.99999.3.1" });
    fermetures.push(principal.fermer);
    const fichierEntetes = path.join(dir, "entetes-regtest.json");
    const calendriers = await calendriersFactices({ fichierEntetes });
    fermetures.push(calendriers.fermer);
    const relaisPrestataire = {
      id: "tsa-publique-relais", role: "interne", url: relais.url, auth: { method: "aucune", secret: null }, hash: "sha256", policy_oid: null, accepted_policies: null,
      anchor_certificates: ancres, qualified: null, min_interval_ms: 15000, request_timeout_ms: 25000, correlation_header: null,
      source: `${a.url} servie au composant par un relais HTTP local (essai TI-16) ; non déclarée qualified`,
    };
    const serie = serieSynthetique({ periodStart, cK: 60, evenementsAuxMinutes: { 1: 1, 2: 1 }, sel: `${Date.now()}/` });
    const registre = registreFactice({ clePublique: serie.clePublique });
    const configuration = configurationEssai({
      prestataires: [principal.prestataire, relaisPrestataire], dir, calendriers, fichierEntetes,
      surcharges: { checkpoint_interval_s: 60, rfc3161: { checkpoints: { interval_s: 60, provider_role: "interne", fallback_after_s: 120 }, retry: { initial_ms: 5000, factor: 2, max_ms: 60000, jitter_ms: 0 } }, registry: { checkpoints: "aucun" }, opentimestamps: { checkpoint: "aucun" } },
    });
    const journal = journalMemoire();
    const remis = [];
    const composant = creerComposantAncrage({
      configuration, profil: "test", checkpointIntervalEnregistreur: 60,
      contexte: {
        org_id: ORG, journal_id: JOURNAL, epoque: 1, racineStockage: path.join(dir, "stockage"), secrets: new Map([["/rfc3161/providers/0/auth/secret", tls.client]]), cles: CLES_JSON,
        clePublique: (k) => (k === "rec-test-01" ? serie.clePublique : null), lireSerie: async () => remis.slice(), lireHashesPeriode: async (P) => (P === periodStart ? serie.hashes : null),
        listerPeriodes: async () => [], listerPoints: async () => [], cleChaine: registre.cleChaine,
      },
      horloge, aleatoire, journal,
      clients: { rfc3161: { transport: transportRfc3161Local(tls) }, ots: { transport: calendriers.transport }, registre: { rpc: registre.rpc, instance: registre.instance, repertoireEnvois: path.join(dir, "captures"), delais: { recuMs: 60000, sondageMs: 250 } } },
    });
    const calme = attenteCalme(composant, { maxMs: 120000, attentesReelles: true });
    await composant.demarrer();
    try {
      const debut = Date.now();
      for (const point of serie.points.slice(0, 3)) {
        remis.push(point);
        expect((await composant.remettrePoint(remisePoint(point))).admis, point.checkpoint_ts).to.equal(true);
      }
      // Deux échéances satisfaites (D_1, D_2) : deux demandes jeton_point pour le relais ; la seconde attend min_interval_ms.
      const limite = Date.now() + 120000;
      for (;;) {
        const jetons = composant.demandes().filter((d) => d.kind === "jeton_point");
        if (jetons.length >= 2 && jetons.every((d) => d.state === "obtenue")) break;
        if (Date.now() > limite) throw new Error(`jetons non obtenus : ${JSON.stringify(jetons.map((d) => [d.state, d.attempts.map((x) => [x.provider, x.outcome, x.error_code])]))}`);
        await new Promise((r) => setTimeout(r, 500));
      }
      await calme();
      const jetons = composant.demandes().filter((d) => d.kind === "jeton_point").sort((x, y) => (x.subject.declared_at < y.subject.declared_at ? -1 : 1));
      expect(jetons.every((d) => d.result.provider === "tsa-publique-relais")).to.equal(true);
      const depot = DepotAncres.ouvrir({ racine: path.join(dir, "stockage"), orgId: ORG, journalId: JOURNAL });
      const acquisitions = depot.lireAcquisitions(periodStart).enregistrements.filter((e) => e.provider_id === "tsa-publique-relais").sort((x, y) => (x.sent_at < y.sent_at ? -1 : 1));
      expect(acquisitions.length).to.be.at.least(2);
      for (const e of acquisitions) {
        expect(e.outcome).to.equal("obtenue");
        for (const t of VERIFICATIONS_ACQUISITION) expect(e.checks[t], `${e.attempt_id} ${t}`).to.equal("reussi");
      }
      const envois = acquisitions.map((e) => N.decoderHorodatage(e.sent_at));
      const ecartsEnvois = envois.slice(1).map((t, k) => t - envois[k]);
      const recues = relais.recues.map((x) => x.at);
      const ecartsRelais = recues.slice(1).map((t, k) => t - recues[k]);
      const reprise = journal.de("anchor_retry").filter((l) => l.data.reason === "backoff" && l.data.kind === "jeton_point");
      console.log(`      relais ${a.id} : ${relais.recues.length} requête(s) reçue(s), écarts ${JSON.stringify(ecartsRelais)} ms ; sent_at des acquisitions, écarts ${JSON.stringify(ecartsEnvois)} ms ; anchor_retry backoff : ${reprise.length} ; durée ${Date.now() - debut} ms`);
      expect(relais.recues.length).to.equal(acquisitions.length, "chaque requête part une fois");
      // Aucune requête sous min_interval_ms (EX-8.7 : toutes demandes confondues) ; la seconde a été reprogrammée (backoff).
      for (const e of ecartsRelais) expect(e).to.be.at.least(15000 - 50);
      for (const e of ecartsEnvois) expect(e).to.be.at.least(15000 - 1000);
      expect(reprise.length).to.be.at.least(1);
      // Les instants d'envoi des acquisitions sont lus sur l'horloge du composant (EX-5.13) et suivent le temps réel : la seconde requête a attendu.
      expect(Date.now() - debut).to.be.at.least(15000);
    } finally {
      await composant.arreter({ attendre: false });
    }
  });
});

describe("TI-16 (iii) : preuve OpenTimestamps d'une racine auprès de deux calendriers publics (EX-6.2 : agrégateurs, min_responses 2) : preuve en attente écrite au dépôt (EX-6.5), O-1 et O-3 réussies", function () {
  this.timeout(120000);
  let dir;
  before(function () {
    dir = repertoireTemporaire("noortrace-ti16-ots-");
  });
  after(function () {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("la racine (periodHash d'un manifeste synthétique) soumise aux agrégateurs publics : au moins deux réponses valables, attestation en_attente, fichier .ots déposé sous ancres/periode-<P>/ots/manifeste-1.ots, O-1 et O-3 réussies, O-7 non exécutée (aucune attestation Bitcoin) — en attente hors NOORTRACE_RESEAU_PUBLIC=1", async function () {
    const c = conditionOts();
    if (c) return enAttente(this, c);
    const serie = serieSynthetique({ periodStart: PERIODE_ESSAI, evenementsAuxMinutes: { 1: 1 }, sel: `${Date.now()}/` });
    const transport = transportOts();
    const r = await soumettre({ empreinte: serie.periodHash, nonce: aleatoire(16), calendriers: AGREGATEURS, minReponses: 2, delaiMs: 15000, transport, horloge: horlogeReelle });
    console.log(`      soumission : ${r.valides} réponse(s) valable(s) sur ${AGREGATEURS.length}, attestation ${r.attestation}, ${r.dureeMs} ms ; ${r.reponses.map((x) => `${x.calendrier} ${x.status ?? "-"} ${x.erreur ?? "ok"}`).join(" ; ")}`);
    expect(r.ecrire).to.equal(true);
    expect(r.valides).to.be.at.least(2);
    expect(r.attestation).to.equal("en_attente");
    const v = verifierOts({ octets: r.octets, empreinteAttendue: serie.periodHash });
    expect(v.checks["O-1"]).to.equal("reussi");
    expect(v.checks["O-3"]).to.equal("reussi");
    expect(v.checks["O-7"]).to.equal("non_execute");
    expect(etatPreuve(r.octets)).to.equal("en_attente");
    const depot = DepotOts.ouvrir({ racine: path.join(dir, "stockage"), orgId: ORG, journalId: JOURNAL });
    const ecrit = depot.ecrire({ periodStart: PERIODE_ESSAI, objet: "manifeste", octets: r.octets });
    expect(ecrit.version).to.equal(1);
    expect(fs.existsSync(path.join(depot.repertoirePeriode(PERIODE_ESSAI), "ots", "manifeste-1.ots"))).to.equal(true);
    expect(depot.derniere({ periodStart: PERIODE_ESSAI, objet: "manifeste" }).octets.length).to.equal(r.octets.length);
  });
});
