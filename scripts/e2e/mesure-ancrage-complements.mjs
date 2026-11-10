// Compléments de la campagne de mesures de l'étape 5 (scripts/e2e/mesure-ancrage.mjs
// complements) : les grandeurs qui n'exigent ni le réseau de développement ni
// une heure de temps réel.
//
// - TM-18 (CT-5 AN-26) : dix jetons du serveur RFC 3161 interne de référence
//   (paquet d'ancrage), redémarrage du serveur (compteur de série durable relu), dix
//   jetons ; `an26_serie_croissante` = paires consécutives non croissantes.
// - TM-30 (CT-8 EX-9.1, b_ots) : dix preuves OpenTimestamps mises à niveau par
//   les calendriers factices à chaîne regtest (chemin Bitcoin complet, en-têtes
//   du fichier) ; tailles en octets (`b_ots_mis_a_niveau`, max et mean) ; avec
//   `--reseau-public`, la taille des preuves EN ATTENTE réelles obtenues des
//   agrégateurs publics d'EX-6.2 (chacune nommée dans les notes).
// - TM-17 (CT-5 §15) : débit de points du composant à l'horloge réglable
//   (une heure de points rejouée en temps accéléré, J = 1 puis J = 10 journaux
//   sur le même décor : serveurs internes de référence réels sur la boucle locale), puis
//   la file en régime de panne (prestataire coupé pendant une heure simulée :
//   taille maximale de la file durable et mémoire résidente du processus).
//   Ces lignes sont accélérées et le disent : elles ne comptent pour aucune
//   cible (TM-17 n'en a pas).
// Écrit `complements.json` sous `--sortie` ; rien dans le dépôt.

import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import { randomBytes } from "node:crypto";
import * as N from "@noortrace/noyau";
import { acquerir, lireJeton, transportHttps as transportRfc3161, DepotAncres } from "@noortrace/ancrage/rfc3161";
import { soumettre, mettreANiveau, lireFichierEntetes, transportHttps as transportOts, etatPreuve } from "@noortrace/ancrage/ots";
import { initialiserAutorite, chargerAutorite, demarrerServeur } from "@noortrace/ancrage/serveur-interne";
import { lireFiles } from "@noortrace/ancrage/planificateur";
import { creerComposantAncrage } from "@noortrace/ancrage";
import {
  HorlogeReglable, attenteCalme, aleatoireFixe, materielTls, serveurCrl, autoriteInterne, qualifiedExemple, calendriersFactices, serieSynthetique, remisePoint,
  remiseCloture, configurationEssai, journalMemoire, transportRfc3161Local, transportCommutable, registreFactice, CLES_JSON, ORG, repertoireTemporaire,
} from "../../test/fixtures/ancrage-composant/outils.mjs";

const AGREGATEURS = ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org", "https://a.pool.eternitywall.com", "https://ots.btc.catallaxy.com"];
const PERIODE = 1793862000; // 2026-11-05T07:00:00Z (dans la validité des clés de test de CT-1 §13)
const horlogeReelle = { murale: () => Date.now(), monotone: () => performance.now() };
const aleatoireReel = (n) => new Uint8Array(randomBytes(n));

function portLibre() {
  return new Promise((res) => {
    const s = http.createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
}

// ----------------------------------------------------------------- TM-18

export async function mesurerSerie({ dir, log }) {
  const horloge = horlogeReelle;
  const crl = await serveurCrl(horloge);
  const repertoire = path.join(dir, "tsa-serie");
  crl.declarer("tsa", repertoire);
  const init = initialiserAutorite({ repertoire, algorithme: "p-256", politique: "1.3.6.1.4.1.99999.2.9", crlUrl: crl.url("tsa"), validiteJours: 365, horloge: { murale: () => Date.now() - 86400000 }, aleatoire: aleatoireReel, sujetUnite: { O: "NOORTRACE essai", CN: "TSA interne non qualifiee" } });
  const port = await portLibre();
  const journal = { consigner() {} };
  let autorite = chargerAutorite({ repertoire });
  let serveur = await demarrerServeur({ autorite, ecoute: { hote: "127.0.0.1", port }, horloge, journal });
  const prestataire = { id: "tsa-interne", role: "interne", url: serveur.adresse.url, auth: { method: "aucune", secret: null }, hash: "sha256", policy_oid: "1.3.6.1.4.1.99999.2.9", accepted_policies: ["1.3.6.1.4.1.99999.2.9"], anchor_certificates: [init.acPem], qualified: null, min_interval_ms: 0, request_timeout_ms: 5000, correlation_header: "X-Request-ID", source: "autorité d'essai (serveur interne de référence)" };
  const depot = DepotAncres.ouvrir({ racine: path.join(dir, "stockage-serie"), orgId: "0x" + "11".repeat(32), journalId: "0x" + "22".repeat(32) });
  const transport = transportRfc3161({ agentHttp: new http.Agent({ keepAlive: false }) });
  const series = [];
  const un = async (k) => {
    const imprint = N.sha256Hex(N.utf8(`noortrace/mesure/tm-18/${k}/${Date.now()}`));
    const r = await acquerir({ prestataire, imprint, objet: "point", attempt: 1, attemptId: `jeton_point:${imprint.slice(2, 18)}:${k}`, periodStart: PERIODE, horloge, aleatoire: aleatoireReel, depot, transport, fraicheur: { max_response_delay_s: 60, clock_tolerance_s: 120 }, retry: { initial_ms: 1000, factor: 2, max_ms: 10000, jitter_ms: 0 } });
    if (r.outcome !== "obtenue") throw new Error(`TM-18 : jeton ${k} non obtenu (${r.code})`);
    series.push(BigInt(lireJeton(r.jeton).tstInfo.serialNumber));
  };
  for (let k = 1; k <= 10; k++) await un(k);
  await serveur.fermer();
  autorite.compteur.fermer?.();
  autorite = chargerAutorite({ repertoire });
  serveur = await demarrerServeur({ autorite, ecoute: { hote: "127.0.0.1", port }, horloge, journal });
  for (let k = 11; k <= 20; k++) await un(k);
  await serveur.fermer();
  autorite.compteur.fermer?.();
  await crl.fermer();
  let nonCroissantes = 0;
  for (let k = 1; k < series.length; k++) if (!(series[k] > series[k - 1])) nonCroissantes += 1;
  log(`TM-18 : ${series.length} jetons, ${nonCroissantes} paire(s) non croissante(s) ; séries ${series[0]}…${series[9]} puis ${series[10]}…${series[19]}`);
  return { jetons: series.length, non_croissantes: nonCroissantes, series: series.map((x) => x.toString()), redemarrage_apres: 10, algorithme: "p-256" };
}

// ----------------------------------------------------------------- TM-30

export async function mesurerOts({ dir, reseauPublic, log }) {
  const fichierEntetes = path.join(dir, "entetes-regtest.json");
  const calendriers = await calendriersFactices({ fichierEntetes });
  const resultats = [];
  try {
    const horloge = horlogeReelle;
    const engagements = [];
    for (let k = 1; k <= 10; k++) {
      const empreinte = N.sha256Hex(N.utf8(`noortrace/mesure/tm-30/${k}`));
      const r = await soumettre({ empreinte, nonce: aleatoireReel(16), calendriers: calendriers.uris, minReponses: 2, delaiMs: 5000, transport: calendriers.transport, horloge });
      if (!r.ecrire) throw new Error(`TM-30 : soumission ${k} refusée`);
      engagements.push({ k, empreinte, enAttente: r.octets });
    }
    calendriers.completer(1010);
    for (const e of engagements) {
      // Les en-têtes sont relus après la réponse du calendrier (qui pose la racine dans la chaîne regtest), comme le composant le fait (EX-6.9).
      const entetes = async () => {
        const lu = lireFichierEntetes(new Uint8Array(fs.readFileSync(fichierEntetes)));
        return lu.document ?? lu;
      };
      const m = await mettreANiveau({ preuve: e.enAttente, listeBlanche: calendriers.uris, transport: calendriers.transport, horloge, delaiMs: 5000, entetes, reseau: "regtest" });
      if (m.etat !== "complete" || !m.nouvelle) throw new Error(`TM-30 : preuve ${e.k} non mise à niveau (${JSON.stringify(m.refus)})`);
      resultats.push({ k: e.k, en_attente: e.enAttente.length, mise_a_niveau: m.nouvelle.length, etat: etatPreuve(m.nouvelle) });
    }
  } finally {
    await calendriers.fermer();
  }
  const publiques = [];
  if (reseauPublic) {
    const transport = transportOts();
    for (let k = 1; k <= 3; k++) {
      const empreinte = N.sha256Hex(N.utf8(`noortrace/mesure/tm-30/public/${k}/${Date.now()}`));
      try {
        const r = await soumettre({ empreinte, nonce: aleatoireReel(16), calendriers: AGREGATEURS, minReponses: 2, delaiMs: 15000, transport, horloge: horlogeReelle });
        publiques.push({ k, octets: r.octets ? r.octets.length : null, calendriers_repondu: r.valides, attestation: r.attestation, reponses: r.reponses.map((x) => ({ calendrier: x.calendrier, status: x.status, erreur: x.erreur, octets: x.octets ? x.octets.length : null })) });
      } catch (e) {
        publiques.push({ k, octets: null, erreur: String(e?.message ?? e) });
      }
    }
  }
  log(`TM-30 : ${resultats.length} preuves mises à niveau (regtest), tailles ${resultats.map((r) => r.mise_a_niveau).join(", ")} ; en attente réelles : ${publiques.map((p) => p.octets ?? "échec").join(", ") || "non demandées"}`);
  return { regtest: resultats, publiques };
}

// ----------------------------------------------------------------- TM-17

/** Décor commun : serveurs internes de référence (TLS mutuel et HTTP), calendriers factices, registre factice. */
async function decor(dir, horloge) {
  const tls = materielTls(path.join(dir, "tls"));
  if (!tls) throw new Error("openssl indisponible pour le matériel TLS");
  const aleatoire = aleatoireFixe(7);
  const crl = await serveurCrl(horloge);
  const interne = await autoriteInterne({ nom: "tsa-interne", dir, role: "interne", horloge, aleatoire, crl, politique: "1.3.6.1.4.1.99999.2.1" });
  const principal = await autoriteInterne({ nom: "qtsa-principal", dir, role: "principal", horloge, aleatoire, crl, tls, qualified: qualifiedExemple("AT"), politique: "1.3.6.1.4.1.99999.3.1" });
  const fichierEntetes = path.join(dir, "entetes-regtest.json");
  const calendriers = await calendriersFactices({ fichierEntetes });
  return { tls, aleatoire, crl, interne, principal, calendriers, fichierEntetes, fermer: () => Promise.all([interne.fermer(), principal.fermer(), calendriers.fermer(), crl.fermer()]) };
}

/** Un composant par journal sur le décor commun, à l'horloge réglable partagée. */
function composantJournal({ d, dir, horloge, j, serie, registre, surcharges, transport, journal }) {
  const racine = path.join(dir, `journal-${j}`);
  const configuration = configurationEssai({ prestataires: [d.principal.prestataire, d.interne.prestataire], dir: racine, calendriers: d.calendriers, fichierEntetes: d.fichierEntetes, surcharges });
  const remis = [];
  const composant = creerComposantAncrage({
    configuration, profil: "test", checkpointIntervalEnregistreur: 60,
    contexte: {
      // Les clés de CT-1 §13 passées en tableau : cles.json porte le journal_id de l'exemple, les journaux mesurés en ont un propre.
      org_id: ORG, journal_id: serie.journalId, epoque: 1, racineStockage: path.join(racine, "stockage"), secrets: new Map([["/rfc3161/providers/0/auth/secret", d.tls.client]]), cles: CLES_JSON.keys,
      clePublique: (k) => (k === "rec-test-01" ? serie.clePublique : null), lireSerie: async () => remis.slice(), lireHashesPeriode: async (P) => (P === PERIODE ? serie.hashes : null),
      listerPeriodes: async () => [], listerPoints: async () => [], cleChaine: registre.cleChaine,
    },
    horloge, aleatoire: d.aleatoire, journal,
    clients: { rfc3161: { transport }, ots: { transport: d.calendriers.transport }, registre: undefined },
  });
  return { composant, remis, configuration, serie };
}

export async function mesurerPlanificateur({ dir, log }) {
  const TOUTES = Object.fromEntries(Array.from({ length: 59 }, (_, i) => [i + 1, 1]));
  const resultats = {};
  for (const J of [1, 10]) {
    const horloge = new HorlogeReglable(PERIODE * 1000);
    const d = await decor(path.join(dir, `debit-${J}`), horloge);
    const journaux = [];
    const transport = transportRfc3161Local(d.tls);
    try {
      for (let j = 1; j <= J; j++) {
        const journalId = N.octetsVersHex(N.keccak256(N.utf8(`noortrace/mesure/tm-17/journal/${j}`)));
        const serie = serieSynthetique({ periodStart: PERIODE, cK: 60, evenementsAuxMinutes: TOUTES, journalId, sel: `${j}/` });
        serie.journalId = journalId;
        const registre = registreFactice({ clePublique: serie.clePublique });
        const c = composantJournal({ d, dir: path.join(dir, `debit-${J}`), horloge, j, serie, registre, transport, journal: journalMemoire(), surcharges: { checkpoint_interval_s: 60, rfc3161: { checkpoints: { interval_s: 300, provider_role: "interne" } }, registry: { checkpoints: "aucun" }, opentimestamps: { checkpoint: "aucun" } } });
        await c.composant.demarrer();
        journaux.push(c);
      }
      const calmes = journaux.map((c) => attenteCalme(c.composant, { maxMs: 120000 }));
      const calme = async () => {
        for (const f of calmes) await f();
      };
      const t0 = process.hrtime.bigint();
      let pointsAdmis = 0;
      for (let k = 0; k < journaux[0].serie.points.length - 1; k++) {
        const t = N.decoderHorodatage(journaux[0].serie.points[k].checkpoint_ts);
        await horloge.aller(t, calme);
        for (const c of journaux) {
          const point = c.serie.points[k];
          c.remis.push(point);
          const r = await c.composant.remettrePoint(remisePoint(point));
          if (r.admis) pointsAdmis += 1;
        }
        await calme();
      }
      for (const c of journaux) {
        const cloture = c.serie.points.at(-1);
        await horloge.aller(N.decoderHorodatage(cloture.checkpoint_ts), calme);
        c.remis.push(cloture);
        await c.composant.remettrePoint(remisePoint(cloture));
        await c.composant.remettreCloture(remiseCloture(c.serie));
      }
      await horloge.avancer(10000, calme);
      const dureeS = Number(process.hrtime.bigint() - t0) / 1e9;
      const jetons = journaux.reduce((a, c) => a + c.composant.demandes().filter((x) => x.kind.startsWith("jeton") && x.state === "obtenue").length, 0);
      const pointsParS = pointsAdmis / dureeS;
      resultats[`J${J}`] = { journaux: J, points_admis: pointsAdmis, jetons_obtenus: jetons, duree_s: Math.round(dureeS * 1000) / 1000, points_par_s: Math.round(pointsParS * 1000) / 1000, jetons_par_s: Math.round((jetons / dureeS) * 1000) / 1000, rss_octets: process.memoryUsage().rss };
      log(`TM-17 J=${J} : ${pointsAdmis} points admis et ${jetons} jetons obtenus en ${dureeS.toFixed(1)} s de temps réel (une heure simulée) : ${pointsParS.toFixed(2)} points/s`);
      for (const c of journaux) await c.composant.arreter({ attendre: false });
    } finally {
      await d.fermer();
    }
  }
  // Régime de panne : prestataire des points coupé pendant une heure simulée, c_T = 60 s (une demande par point), file bornée à max_pending.
  {
    const horloge = new HorlogeReglable(PERIODE * 1000);
    const rep = path.join(dir, "panne");
    const d = await decor(rep, horloge);
    const { ErreurTransport } = await import("@noortrace/ancrage/rfc3161");
    const transport = transportCommutable(transportRfc3161Local(d.tls), ErreurTransport);
    try {
      const journalId = N.octetsVersHex(N.keccak256(N.utf8("noortrace/mesure/tm-17/panne")));
      const serie = serieSynthetique({ periodStart: PERIODE, cK: 60, evenementsAuxMinutes: TOUTES, journalId, sel: "panne/" });
      serie.journalId = journalId;
      const registre = registreFactice({ clePublique: serie.clePublique });
      const journal = journalMemoire();
      const c = composantJournal({ d, dir: rep, horloge, j: 1, serie, registre, transport, journal, surcharges: { checkpoint_interval_s: 60, rfc3161: { checkpoints: { interval_s: 60, provider_role: "interne", fallback_after_s: 120 }, retry: { initial_ms: 5000, factor: 2, max_ms: 60000, jitter_ms: 0 } }, registry: { checkpoints: "aucun" }, opentimestamps: { checkpoint: "aucun" }, queue: { max_pending: 1000 } } });
      await c.composant.demarrer();
      const calme = attenteCalme(c.composant, { maxMs: 120000 });
      transport.pannes.add(d.interne.prestataire.url);
      transport.pannes.add(d.principal.prestataire.url);
      let maxActives = 0;
      let maxLignes = 0;
      let maxRss = process.memoryUsage().rss;
      for (let k = 0; k < c.serie.points.length - 1; k++) {
        const point = c.serie.points[k];
        await horloge.aller(N.decoderHorodatage(point.checkpoint_ts), calme);
        c.remis.push(point);
        await c.composant.remettrePoint(remisePoint(point));
        await calme();
        maxActives = Math.max(maxActives, c.composant.etat().actives);
        maxRss = Math.max(maxRss, process.memoryUsage().rss);
      }
      const relue = lireFiles(c.configuration.queue.path);
      maxLignes = relue.fichiers.reduce((a, f) => a + fs.readFileSync(path.join(c.configuration.queue.path, f), "utf8").split("\n").filter(Boolean).length, 0);
      const demandes = c.composant.demandes();
      const taille = relue.fichiers.reduce((a, f) => a + fs.statSync(path.join(c.configuration.queue.path, f)).size, 0);
      resultats.panne = {
        heure_simulee: true, demandes_en_file: demandes.length, demandes_actives_max: maxActives, lignes_file: maxLignes, octets_file: taille, rss_max_octets: maxRss,
        tentatives: demandes.reduce((a, x) => a + x.attempts.length, 0), anchor_retry: journal.de("anchor_retry").length, file_pleine: journal.de("anchor_queue_full").length, max_pending: 1000,
      };
      log(`TM-17 panne : ${demandes.length} demandes en file (max actives ${maxActives}), ${maxLignes} lignes (${taille} octets), RSS max ${maxRss} octets, ${resultats.panne.tentatives} tentatives`);
      await c.composant.arreter({ attendre: false });
    } finally {
      await d.fermer();
    }
  }
  return resultats;
}

export async function complements({ sortie, reseauPublic = false, log = () => {} }) {
  const racine = path.resolve(sortie);
  fs.mkdirSync(racine, { recursive: true });
  const dir = repertoireTemporaire("noortrace-mesure-complements-");
  try {
    const debut = new Date();
    const tm18 = await mesurerSerie({ dir, log });
    const tm30 = await mesurerOts({ dir, reseauPublic, log });
    const tm17 = await mesurerPlanificateur({ dir, log });
    const r = { version: 0, kind: "complements-mesure-ancrage", debut: debut.toISOString(), fin: new Date().toISOString(), tm18, tm30, tm17 };
    fs.writeFileSync(path.join(racine, "complements.json"), `${JSON.stringify(r, null, 2)}\n`);
    log(`compléments écrits : ${path.join(racine, "complements.json")}`);
    return r;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
