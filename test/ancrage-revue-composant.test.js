// Revue de sécurité interne de l'étape 8 : composant temps réel et
// exportateur. Pertes silencieuses et bornes (causes S-1, S-6) : CT-5 EX-8.12
// (reconstruction au démarrage : rien n'est écarté au-delà de 10 000
// périodes), (recul de l'heure murale : les attentes ne gèlent pas,
// EX-4.13), (retrait de `qualified` durable ;
// automatique sur PKIStatus 4 ou 5, EX-5.12 ; rechargement refusé en
// production, EX-5.9), CT-5 EX-10.1 (exportateur : jeton et preuve de la période
// confrontés à periodHash ; fichiers du dossier en 0600, index écrit en dernier
// par remplacement atomique).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as N from "@noortrace/noyau";
import { ErreurTransport, DepotAncres } from "@noortrace/ancrage/rfc3161";
import { DepotOts, Noeud, OP, attestationBitcoin, ecrireOts } from "@noortrace/ancrage/ots";
import { depotsJournal, piecesPeriode, ecrireFichierDossier } from "@noortrace/ancrage/exportateur";
import { monterComposant, remisePoint, remiseCloture, attenteCalme, repertoireTemporaire, enAttente, ORG, JOURNAL } from "./fixtures/ancrage-composant/outils.mjs";

const PERIODE = 1793862000;
const jamais = () => new Promise(() => {});

describe("ancrage, revue de sécurité de l'étape 8 : reconstruction au démarrage sans coupe (CT-5 EX-8.12)", function () {
  this.timeout(600000);

  it("10 003 périodes closes sans demande : toutes reçoivent leurs trois demandes, les plus récentes d'abord, par lots de 10 000 consignés (était : les 3 plus récentes écartées sans trace)", async function () {
    const NB = 10003;
    const dir = repertoireTemporaire("ancrage-revue-composant-1-");
    const P0 = PERIODE - NB * 3600;
    let m;
    const vraiEcrire = DepotAncres.prototype.ecrirePiece;
    // Les nonces OpenTimestamps ne sont pas écrits sur le disque (30 000 fichiers inutiles ici) ; seules les demandes comptent.
    DepotAncres.prototype.ecrirePiece = function (periodStart, sous, nom) {
      return `${sous}/${nom}`;
    };
    try {
      m = await monterComposant({
        dir, periodStart: PERIODE, evenements: { 1: 1 }, ErreurTransport,
        contexteSurcharges: {
          // Ordre du démon (`ancrage-demon.mjs`) : noms triés, période croissante : les plus récentes arrivent en dernier.
          listerPeriodes: async () => Array.from({ length: NB }, (_, i) => ({ manifeste: { ...m.serie.manifeste, period_start: P0 + i * 3600, period_end: P0 + (i + 1) * 3600 } })),
        },
      });
      if (m.condition) return enAttente(this, m.condition);
      let lignesFile = 0;
      const bouchon = new Proxy({}, { get: () => jamais });
      const composant = m.creer({ clients: { file: { ouvrir: () => ({ ecrire() { lignesFile += 1; }, fermer() {} }) }, registre: { envoyeur: { ancrer: jamais, repertoire: dir } }, rfc3161: { transport: bouchon }, ots: { transport: bouchon } } });
      await composant.demarrer();
      const demandes = [...composant.planificateur.demandes.values()];
      const avecJeton = new Set(demandes.filter((d) => d.kind === "jeton_periode").map((d) => d.subject.period_start));
      const sans = [];
      for (let i = 0; i < NB; i++) if (!avecJeton.has(P0 + i * 3600)) sans.push(i);
      expect(sans, "périodes closes sans aucune demande après la reconstruction").to.deep.equal([]);
      expect(avecJeton.size).to.equal(NB);
      expect(demandes.length, "trois demandes par période (ancre, jeton, preuve)").to.equal(3 * NB);
      expect(lignesFile).to.be.at.least(3 * NB);
      const reconstruites = m.journal.de("anchoring_queue_rebuilt");
      expect(reconstruites.length, "une ligne par lot").to.equal(2);
      expect(reconstruites.reduce((n, l) => n + l.data.recreated, 0)).to.equal(3 * NB);
      // Les plus récentes d'abord : le premier lot porte 10 000 périodes, le second les 3 plus anciennes.
      expect(reconstruites.map((l) => l.data.periods)).to.deep.equal([10000, 3]);
      const lots = m.journal.de("anchoring_storage_batched");
      expect(lots).to.have.length(1);
      expect(lots[0].data).to.include({ periods: NB, batches: 2, batch_size: 10000 });
      expect(m.journal.de("alerte_file_perdue").length).to.be.at.least(1);
      await composant.arreter({ attendre: false });
    } finally {
      DepotAncres.prototype.ecrirePiece = vraiEcrire;
      if (m && !m.condition) await m.fermer();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("ancrage, revue de sécurité de l'étape 8 : recul de l'heure murale (CT-5 EX-4.13)", function () {
  this.timeout(600000);

  it("jeton de clôture en reprise, prestataires rétablis, heure murale reculée d'une heure : une tentative repart en dix minutes, le recul est consigné et alerté une fois, le jeton est obtenu (était : aucune tentative ni ligne pendant une heure)", async function () {
    const dir = repertoireTemporaire("ancrage-revue-composant-2-");
    const m = await monterComposant({ dir, periodStart: PERIODE, evenements: { 1: 1 }, ErreurTransport, surcharges: { rfc3161: { checkpoints: { provider_role: "aucun" } }, opentimestamps: { enabled: false, checkpoint: "aucun" } } });
    if (m.condition) return enAttente(this, m.condition);
    try {
      const composant = m.creer();
      const calme = attenteCalme(composant);
      await composant.demarrer();
      for (const point of m.serie.points) {
        await m.horloge.aller(N.decoderHorodatage(point.checkpoint_ts), calme);
        m.remis.push(point);
        await composant.remettrePoint(remisePoint(point));
        await calme();
      }
      m.transport.pannes.add(m.principal.prestataire.url);
      m.transport.pannes.add(m.secours.prestataire.url);
      await composant.remettreCloture(remiseCloture(m.serie));
      await calme();
      await m.horloge.avancer(120000, calme);
      const jeton = () => composant.demandes().find((d) => d.kind === "jeton_periode");
      const n0 = jeton().attempts_total;
      expect(n0, "des tentatives ont échoué pendant la panne").to.be.at.least(1);
      expect(jeton().state).to.not.equal("obtenue");
      // Les prestataires reviennent ; l'heure murale recule d'une heure, la monotone ne recule pas (les minuteries du
      // système gardent leur délai restant).
      m.transport.pannes.clear();
      m.horloge.m -= 3600000;
      for (const t of m.horloge.minuteries) t.due -= 3600000;
      const avant = m.journal.lignes.length;
      await m.horloge.avancer(10 * 60000, calme);
      const n1 = jeton().attempts_total;
      expect(n1, "une tentative nouvelle part dans les dix minutes qui suivent le recul").to.be.above(n0);
      expect(jeton().state, "le jeton est obtenu des prestataires rétablis").to.equal("obtenue");
      const lignes = m.journal.lignes.slice(avant);
      expect(lignes.filter((l) => l.event === "anchoring_clock_backwards")).to.have.length(1);
      expect(lignes.filter((l) => l.event === "alerte_horloge_reculee")).to.have.length(1);
      expect(lignes.find((l) => l.event === "anchoring_clock_backwards").data.behind_s).to.be.within(3500, 3700);
      await composant.arreter({ attendre: false });
    } finally {
      await m.fermer();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("ancrage, revue de sécurité de l'étape 8 : retrait de qualified durable et automatique (CT-5 EX-5.9, EX-5.12)", function () {
  this.timeout(600000);

  it("le retrait survit au rechargement du même document et au redémarrage (fichier qualifications-retirees.json) ; la fiche porte qualified null ; retablirQualification le lève, durablement", async function () {
    const dir = repertoireTemporaire("ancrage-revue-composant-3-");
    const m = await monterComposant({ dir, periodStart: PERIODE, evenements: { 1: 1 }, ErreurTransport });
    if (m.condition) return enAttente(this, m.condition);
    try {
      const principal = m.principal.prestataire.id;
      const c1 = m.creer();
      await c1.demarrer();
      await c1.retirerQualification(principal);
      expect(c1.etat().qualifications_retirees).to.deep.equal([principal]);
      expect((await c1.fiche(principal)).fiche.qualified).to.equal(null);
      expect(c1.recharger(m.configuration).accepte).to.equal(true);
      expect(c1.etat().qualifications_retirees, "le rechargement ne rétablit rien").to.deep.equal([principal]);
      await c1.arreter({ attendre: false });
      const fichier = path.join(m.contexte.racineStockage, ORG.slice(2), JOURNAL.slice(2), "ancres", "qualifications-retirees.json");
      expect(JSON.parse(fs.readFileSync(fichier, "utf8"))).to.include({ version: 0 });
      expect(JSON.parse(fs.readFileSync(fichier, "utf8")).providers).to.deep.equal([principal]);
      const c2 = m.creer({ epoque: 2 });
      await c2.demarrer();
      expect(c2.etat().qualifications_retirees, "le redémarrage relit le retrait").to.deep.equal([principal]);
      expect(m.journal.de("provider_qualifications_withdrawn_reloaded")).to.have.length(1);
      expect((await c2.fiche(principal)).fiche.qualified).to.equal(null);
      expect(await c2.retablirQualification(principal)).to.equal(true);
      expect(await c2.retablirQualification(principal)).to.equal(false);
      expect(c2.etat().qualifications_retirees).to.deep.equal([]);
      expect((await c2.fiche(principal)).fiche.qualified).to.not.equal(null);
      await c2.arreter({ attendre: false });
      const c3 = m.creer({ epoque: 3 });
      await c3.demarrer();
      expect(c3.etat().qualifications_retirees).to.deep.equal([]);
      await c3.arreter({ attendre: false });
    } finally {
      await m.fermer();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("en production, le rechargement d'un document qui désigne comme principal un prestataire au retrait en vigueur est refusé (règle 4, EX-5.9) tant que l'exploitant ne l'a pas rétabli", async function () {
    const dir = repertoireTemporaire("ancrage-revue-composant-3-prod-");
    const m = await monterComposant({ dir, periodStart: PERIODE, evenements: { 1: 1 }, ErreurTransport });
    if (m.condition) return enAttente(this, m.condition);
    try {
      const principal = m.principal.prestataire.id;
      const c = m.creer({ profil: "production" });
      expect(c.configurationValide(), "la configuration d'essai est valide en production").to.deep.include({ valide: true });
      await c.demarrer();
      await c.retirerQualification(principal);
      const r = c.recharger(m.configuration);
      expect(r.accepte).to.equal(false);
      expect(r.erreurs.map((e) => e.regle)).to.deep.equal(["4"]);
      expect(r.erreurs[0].message).to.include(principal).and.to.match(/retrait de qualified/);
      expect(m.journal.de("config_reload_rejected").at(-1).data).to.include({ reason: "qualification_retiree" });
      await c.retablirQualification(principal);
      expect(c.recharger(m.configuration).accepte).to.equal(true);
      await c.arreter({ attendre: false });
    } finally {
      await m.fermer();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("CT-5 EX-5.9 : une réponse PKIStatus 4 (revocationWarning) du principal retire qualified sans décision de l'exploitant, durablement et avec sa raison ; la relève obtient le jeton du secours", async function () {
    const dir = repertoireTemporaire("ancrage-revue-composant-4-");
    const m = await monterComposant({ dir, periodStart: PERIODE, evenements: { 1: 1 }, ErreurTransport, surcharges: { rfc3161: { checkpoints: { provider_role: "aucun" } }, opentimestamps: { enabled: false, checkpoint: "aucun" } } });
    if (m.condition) return enAttente(this, m.condition);
    try {
      const principal = m.principal.prestataire;
      // TimeStampResp { status: PKIStatusInfo { status INTEGER 4 } } : revocationWarning, sans jeton (RFC 3161 §2.4.2).
      const revocationWarning = Uint8Array.from([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x04]);
      const transport = {
        envoyer: async (req) => (req.url === principal.url ? { status: 200, entetes: { "content-type": "application/timestamp-reply" }, corps: revocationWarning, tronque: false } : m.transport.envoyer(req)),
        obtenir: (url, delaiMs) => m.transport.obtenir(url, delaiMs),
      };
      const composant = m.creer({ clients: { rfc3161: { transport } } });
      const calme = attenteCalme(composant);
      await composant.demarrer();
      for (const point of m.serie.points) {
        await m.horloge.aller(N.decoderHorodatage(point.checkpoint_ts), calme);
        m.remis.push(point);
        await composant.remettrePoint(remisePoint(point));
        await calme();
      }
      await composant.remettreCloture(remiseCloture(m.serie));
      await calme();
      await m.horloge.avancer(30000, calme);
      expect(composant.etat().qualifications_retirees).to.deep.equal([principal.id]);
      const retraits = m.journal.de("provider_qualification_withdrawn");
      expect(retraits).to.have.length(1);
      expect(retraits[0].data).to.include({ provider: principal.id, reason: "pki_status_4" });
      expect(m.journal.de("alerte_revoque").length).to.be.at.least(1);
      const jeton = composant.demandes().find((d) => d.kind === "jeton_periode");
      expect(jeton.state).to.equal("obtenue");
      expect(jeton.result.provider).to.equal(m.secours.prestataire.id);
      const fichier = path.join(m.contexte.racineStockage, ORG.slice(2), JOURNAL.slice(2), "ancres", "qualifications-retirees.json");
      expect(JSON.parse(fs.readFileSync(fichier, "utf8")).providers).to.deep.equal([principal.id]);
      await composant.arreter({ attendre: false });
    } finally {
      await m.fermer();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("ancrage, revue de sécurité de l'étape 8 : exportateur, pièces de la période confrontées à periodHash et écriture du dossier (CT-5 EX-10.1, EX-6.10 ; EX-5.9)", function () {
  const H1 = "0x" + "11".repeat(32);
  const H2 = "0x" + "22".repeat(32);
  const jetonOctets = N.utf8("jeton de la periode (octets quelconques : seul le SHA-256 est confronte)");
  /** Enregistrement d'acquisition d'EX-5.13 (forme des vecteurs de reprise), promu, pour un jeton écrit dans le dépôt. */
  const enregistrement = ({ imprint, fichier }) => ({
    version: 0, object: "manifeste", object_name: "manifeste", imprint, period_start: PERIODE, provider_id: "qtsa-principal", provider_role: "principal", attempt_id: `jeton_periode:${imprint.slice(2, 18)}:1`, attempt: 1,
    request_id: `jeton_periode:${imprint}`, nonce: "0x74a6f4979421411e", sent_at: "2026-11-05T09:32:01.000Z", received_at: "2026-11-05T09:32:02.000Z",
    outcome: "obtenue", error_code: null, http_status: 200, pki_status: 0, failure_info: null, gen_time: "2026-11-05T09:32:02Z", accuracy_s: 1, upper_bound: "2026-11-05T09:32:03.000Z",
    token_sha256: N.sha256Hex(jetonOctets), token_size: jetonOctets.length, checks: { "T-1": "reussi", "T-2": "reussi", "T-3": "reussi", "T-4": "reussi", "T-5": "reussi", "T-6": "reussi", "T-7": "reussi", "T-8": "reussi", "T-9": "reussi", "T-10": "reussi" },
    qualified: { framework: "eidas" }, promoted: true, files: { request: `${fichier}.tsq`, response: `${fichier}.tsr`, token: `${fichier}.der`, crls: [] },
  });
  const preuve = (empreinte) => {
    const racine = new Noeud();
    racine.operation(OP.SHA256, null).ajouterAttestation(attestationBitcoin(5));
    return ecrireOts({ empreinte: N.hexVersOctets(empreinte, 32), arbre: racine });
  };

  it("un jeton promu et une preuve d'une autre empreinte que periodHash sont rendus en défaut, jamais remis ; pour la bonne empreinte, remis", function () {
    const racine = repertoireTemporaire("ancrage-revue-composant-5-");
    try {
      const depot = DepotAncres.ouvrir({ racine, orgId: ORG, journalId: JOURNAL });
      const depotOts = DepotOts.ouvrir({ racine, orgId: ORG, journalId: JOURNAL });
      const base = depot.nomPiece({ objet: "manifeste", imprint: H1, providerId: "qtsa-principal", attemptId: `jeton_periode:${H1.slice(2, 18)}:1` });
      depot.ecrirePiece(PERIODE, "rfc3161", `${base}.der`, jetonOctets);
      depot.ajouterAcquisition(PERIODE, enregistrement({ imprint: H1, fichier: `rfc3161/${base}` }));
      depotOts.ecrire({ periodStart: PERIODE, objet: "manifeste", octets: preuve(H1) });
      const depots = depotsJournal({ racineStockage: racine, orgId: ORG, journalId: JOURNAL });
      const bonne = piecesPeriode({ depots, periodStart: PERIODE, periodHash: H1 });
      expect(bonne.defauts).to.deep.equal([]);
      expect(bonne.jeton.sha256).to.equal(N.sha256Hex(jetonOctets));
      expect(bonne.preuve.etat).to.equal("complete");
      const autre = piecesPeriode({ depots, periodStart: PERIODE, periodHash: H2 });
      expect(autre.jeton, "aucun jeton d'une autre empreinte n'est remis").to.equal(null);
      expect(autre.preuve, "aucune preuve d'une autre empreinte n'est remise").to.equal(null);
      expect(autre.defauts.map((d) => d.raison)).to.deep.equal([
        "jeton promu du manifeste pour une autre empreinte que periodHash (EX-10.1)",
        "empreinte de la preuve OpenTimestamps différente de celle attendue (EX-6.10)",
      ]);
      // Sans empreinte attendue (appelant d'avant), la conduite est inchangée.
      const sans = piecesPeriode({ depots, periodStart: PERIODE });
      expect(sans.jeton).to.not.equal(null);
      expect(sans.preuve).to.not.equal(null);
    } finally {
      fs.rmSync(racine, { recursive: true, force: true });
    }
  });

  it("ecrireFichierDossier écrit en mode 0600 par un fichier provisoire renommé : remplacement atomique, aucun provisoire résiduel, contenu exact", function () {
    const dir = repertoireTemporaire("ancrage-revue-composant-5-ecriture-");
    try {
      const chemin = path.join(dir, "dossier.json");
      ecrireFichierDossier(chemin, N.utf8("{\"a\":1}"));
      expect(fs.statSync(chemin).mode & 0o777).to.equal(0o600);
      expect(fs.readFileSync(chemin, "utf8")).to.equal("{\"a\":1}");
      ecrireFichierDossier(chemin, N.utf8("{\"a\":2}"));
      expect(fs.readFileSync(chemin, "utf8")).to.equal("{\"a\":2}");
      expect(fs.readdirSync(dir)).to.deep.equal(["dossier.json"]);
      // Un répertoire de destination inexistant : l'erreur est levée, aucun provisoire ne traîne ailleurs.
      expect(() => ecrireFichierDossier(path.join(dir, "absent", "x.json"), N.utf8("x"))).to.throw();
      expect(fs.readdirSync(dir)).to.deep.equal(["dossier.json"]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
