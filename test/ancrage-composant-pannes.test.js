// Composant d'ancrage (lot F1) : pannes et reprises à l'horloge injectée,
// hors réseau public. Prestataire injoignable puis retour (relève EX-5.7,
// EX-8.8 ; remplacee EX-4.4 ; jetons de rattrapage EX-4.3), registre
// injoignable (repli de clôture EX-4.2, ordre_ancres_non_respecte EX-9.6),
// calendriers en panne (EX-6.2, EX-8.11 : même engagement), file pleine
// (EX-8.5 règle 4), écriture de file impossible (EX-8.1), arrêt brutal entre
// ecrire_file et l'envoi puis redémarrage (AN-32, AN-33, EX-8.12), T-10 avec
// CRL révoquée (EX-5.10 étape 10, EX-8.3 : relève), retrait de la
// qualification (EX-5.9, TC-24 de CT-9), entrées hostiles et refus
// d'admission (AN-3, EX-3.1), configuration refusée (AN-1, EX-4.8).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as N from "@noortrace/noyau";
import { ErreurTransport, DepotAncres } from "@noortrace/ancrage/rfc3161";
import { FileDurable, lireFiles } from "@noortrace/ancrage/planificateur";
import { creerComposantAncrage, ErreurConfigurationAncrage, validerConfigurationComposant } from "../paquets/ancrage/src/composant.mjs";
import { ORG, JOURNAL, attenteCalme, monterComposant, remisePoint, remiseCloture, repertoireTemporaire, enAttente, HorlogeReglable, aleatoireFixe, serieSynthetique } from "./fixtures/ancrage-composant/outils.mjs";

const PERIODE = 1793862000; // 2026-11-05T07:00:00Z
const T0 = PERIODE * 1000;
const minute = (m) => T0 + m * 60000;
const TOUTES_LES_MINUTES = Object.fromEntries(Array.from({ length: 59 }, (_, i) => [i + 1, 1]));

/** Rejoue les points alignés de `de` à `a` (minutes), l'horloge avançant à chaque instant. */
async function rejouer(m, composant, calme, de, a) {
  for (const point of m.serie.points.slice(0, -1)) {
    const t = N.decoderHorodatage(point.checkpoint_ts);
    const mn = (t - T0) / 60000;
    if (mn < de || mn > a) continue;
    await m.horloge.aller(t, calme);
    m.remis.push(point);
    const r = await composant.remettrePoint(remisePoint(point));
    expect(r.admis, point.checkpoint_ts).to.equal(true);
    await calme();
  }
}

async function clore(m, composant, calme) {
  const cloture = m.serie.points.at(-1);
  await m.horloge.aller(N.decoderHorodatage(cloture.checkpoint_ts), calme);
  m.remis.push(cloture);
  expect((await composant.remettrePoint(remisePoint(cloture))).admis).to.equal(true);
  expect((await composant.remettreCloture(remiseCloture(m.serie))).admis).to.equal(true);
  await calme();
}

describe("ancrage, composant F1 : pannes et reprises (CT-5 §5.3, §8, §9)", function () {
  this.timeout(600000);

  describe("prestataire des points injoignable puis retour (EX-5.7, EX-8.8, EX-4.4, EX-4.3)", function () {
    let dir;
    let m;
    let composant;
    let calme;
    before(async function () {
      dir = repertoireTemporaire();
      m = await monterComposant({ dir, periodStart: PERIODE, evenements: TOUTES_LES_MINUTES, ErreurTransport, surcharges: { rfc3161: { checkpoints: { provider_role: "principal" } } } });
      if (m.condition) return;
      composant = m.creer();
      calme = attenteCalme(composant);
      await composant.demarrer();
    });
    after(async function () {
      if (composant?.etat().demarre) await composant.arreter({ attendre: false });
      await m?.fermer?.();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it("principal et secours injoignables : tentatives transitoires, relève au secours à fallback_after_s (anchor_fallback), demandes accumulées (règle 4 d'EX-8.5)", async function () {
      if (m.condition) return enAttente(this, m.condition);
      m.transport.pannes.add(m.principal.prestataire.url);
      m.transport.pannes.add(m.secours.prestataire.url);
      await rejouer(m, composant, calme, 0, 19);
      const jetons = composant.demandes().filter((d) => d.kind === "jeton_point");
      expect(jetons.map((d) => d.deadlines)).to.deep.equal([[1], [2], [3]]);
      expect(jetons.every((d) => d.state === "a_reprendre" || d.state === "envoyee")).to.equal(true);
      expect(jetons.every((d) => d.attempts.some((a) => a.outcome === "echec_transitoire" && a.error_code === "erreur_transport"))).to.equal(true);
      const releves = m.journal.de("anchor_fallback");
      expect(releves.length).to.be.at.least(1);
      expect(releves[0].data).to.include({ to: "qtsa-secours", reason: "delai" });
      expect(jetons[0].attempts.some((a) => a.provider === "qtsa-secours")).to.equal(true);
      expect(m.journal.de("anchor_retry").length).to.be.at.least(3);
    });

    it("retour des prestataires : la demande la plus récente est servie d'abord, les antérieures passent remplacee avec replaced_by (checkpoint_anchor_late), un jeton de rattrapage est obtenu", async function () {
      if (m.condition) return enAttente(this, m.condition);
      m.transport.pannes.clear();
      await rejouer(m, composant, calme, 20, 35);
      const jetons = composant.demandes().filter((d) => d.kind === "jeton_point");
      const obtenus = jetons.filter((d) => d.state === "obtenue");
      const remplaces = jetons.filter((d) => d.state === "remplacee");
      expect(obtenus.length).to.be.at.least(1);
      expect(remplaces.length, "au moins une échéance antérieure close par la suivante (EX-4.4)").to.be.at.least(1);
      for (const d of remplaces) expect(d.replaced_by).to.match(/^jeton_point:0x/);
      expect(m.journal.de("checkpoint_anchor_late").length).to.equal(remplaces.length);
      expect(m.journal.de("alerte_checkpoint_anchor_late")[0].data.severity).to.equal("majeure");
      const rattrapage = obtenus.find((d) => d.deadlines.includes(3) || d.deadlines.includes(2) || d.deadlines.includes(1));
      expect(rattrapage, "jeton de rattrapage d'une demande créée pendant la panne").to.not.equal(undefined);
      expect(rattrapage.attempts.length).to.be.at.least(2);
      expect(["qtsa-principal", "qtsa-secours"]).to.include(rattrapage.result.provider);
      // Les échéances suivantes (après le retour) sont servies normalement, sans relève.
      const apres = jetons.filter((d) => Math.min(...d.deadlines) >= 5);
      expect(apres.length).to.be.at.least(2);
      expect(apres.every((d) => d.state === "obtenue" && d.attempts.length === 1)).to.equal(true);
    });
  });

  describe("registre injoignable à la clôture (EX-4.2 repli de clôture, EX-8.4, EX-9.6 ordre_ancres_non_respecte, EX-9.5 rattrapage)", function () {
    let dir;
    let m;
    let composant;
    let calme;
    before(async function () {
      dir = repertoireTemporaire();
      m = await monterComposant({ dir, periodStart: PERIODE, evenements: TOUTES_LES_MINUTES, evenementsCloture: 1, ErreurTransport });
      if (m.condition) return;
      composant = m.creer();
      calme = attenteCalme(composant);
      await composant.demarrer();
    });
    after(async function () {
      if (composant?.etat().demarre) await composant.arreter({ attendre: false });
      await m?.fermer?.();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it("registre en panne depuis 07:50 : ancres a_reprendre, jeton du point de D_11 part après squat_wait_s avec ordre_ancres_non_respecte ; à la clôture jeton_periode attend, repli de clôture sur le point de clôture (checkpoint_closing_fallback)", async function () {
      if (m.condition) return enAttente(this, m.condition);
      await rejouer(m, composant, calme, 0, 49);
      for (const p of m.registre.points) m.registre.noeud.pannes.add(p);
      await rejouer(m, composant, calme, 50, 59);
      expect(m.journal.de("ordre_ancres_non_respecte").length).to.be.at.least(1);
      const d11 = composant.demandes().find((d) => d.kind === "jeton_point" && d.deadlines.includes(11));
      expect(d11.state).to.equal("obtenue");
      await clore(m, composant, calme);
      await m.horloge.avancer(10000, calme);
      const periode = composant.demandes().find((d) => d.kind === "jeton_periode");
      expect(periode.state).to.equal("attente_registre");
      const ancre = composant.demandes().find((d) => d.kind === "ancre_registre_periode");
      expect(["a_reprendre", "envoyee"]).to.include(ancre.state);
      expect(ancre.attempts.at(-1).error_code === "noeud_injoignable" || ancre.attempts.at(-1).outcome === "en_cours").to.equal(true);
      expect(m.journal.de("checkpoint_closing_fallback")).to.have.lengthOf(1);
      const repli = composant.demandes().find((d) => d.kind === "jeton_point" && d.deadlines.length === 0);
      expect(repli, "jeton_point sans échéance pour le point de clôture").to.not.equal(undefined);
      expect(repli.subject.hash).to.equal(N.hacherPoint(m.serie.points.at(-1)));
      // Seule l'ancre du dernier point admis pendant la panne part au retour ; les autres sont remplacee (EX-9.5).
      const ancresPoints = composant.demandes().filter((d) => d.kind === "ancre_registre_point" && N.decoderHorodatage(d.subject.declared_at) >= minute(50));
      expect(ancresPoints.filter((d) => d.state === "remplacee").length).to.be.at.least(1);
    });

    it("retour du registre : l'ancre de la période est incluse et capturée, le jeton de la période part puis est obtenu, la clôture submitPeriod suit (period_submitted), registry_pending consigné pendant la panne", async function () {
      if (m.condition) return enAttente(this, m.condition);
      await m.horloge.avancer(120000, calme);
      expect(m.journal.de("registry_pending").length).to.be.at.least(1);
      m.registre.noeud.pannes.clear();
      await m.horloge.avancer(600000, calme);
      const periode = composant.demandes().find((d) => d.kind === "jeton_periode");
      expect(periode.state).to.equal("obtenue");
      expect(composant.demandes().find((d) => d.kind === "ancre_registre_periode").state).to.equal("obtenue");
      expect(m.journal.de("period_submitted")).to.have.lengthOf(1);
      const repli = composant.demandes().find((d) => d.kind === "jeton_point" && d.deadlines.length === 0);
      expect(["obtenue", "remplacee"]).to.include(repli.state);
      expect(m.journal.de("checkpoint_countersigned").some((l) => l.data.closing_fallback === true) || repli.state === "remplacee").to.equal(true);
    });
  });

  describe("registre absent hors production (EX-8.4 règles 2 et 3) : aucune ancre au registre n'est écrite ni reprise", function () {
    let dir;
    let m;
    let composant;
    let calme;
    before(async function () {
      dir = repertoireTemporaire();
      m = await monterComposant({ dir, periodStart: PERIODE, evenements: TOUTES_LES_MINUTES, ErreurTransport, surcharges: { opentimestamps: { enabled: false } } });
      if (m.condition) return;
      composant = m.creer({ clients: { registre: undefined } });
      calme = attenteCalme(composant);
      await composant.demarrer();
    });
    after(async function () {
      if (composant?.etat().demarre) await composant.arreter({ attendre: false });
      await m?.fermer?.();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it("étape 6 : sans registre configuré, aucune ancre de point ni de période n'est écrite (checkpoint_not_anchored registre_absent), le jeton de la période part aussitôt à la clôture et est obtenu ; deux heures plus tard, aucune reprise registre_absent et aucune demande active", async function () {
      if (m.condition) return enAttente(this, m.condition);
      await rejouer(m, composant, calme, 0, 59);
      await clore(m, composant, calme);
      await m.horloge.avancer(2 * 3600 * 1000, calme);
      const demandes = composant.demandes();
      expect(demandes.filter((d) => d.kind.startsWith("ancre_registre_")).map((d) => d.id), "aucune ancre au registre").to.deep.equal([]);
      expect(demandes.find((d) => d.kind === "jeton_periode").state).to.equal("obtenue");
      expect(m.journal.de("checkpoint_closing_fallback")).to.deep.equal([]);
      const nonAncres = m.journal.de("checkpoint_not_anchored");
      expect(nonAncres.length).to.be.at.least(1);
      expect(nonAncres.every((l) => l.data.reason === "registre_absent"), JSON.stringify(nonAncres.map((l) => l.data.reason))).to.equal(true);
      const reprises = m.journal.de("anchor_retry").filter((l) => l.data.error_code === "registre_absent");
      expect(reprises, "aucune reprise registre_absent").to.deep.equal([]);
      expect(m.journal.de("registry_pending")).to.deep.equal([]);
      expect(composant.etat().actives, "aucune demande active").to.equal(0);
    });
  });

  describe("calendriers OpenTimestamps en panne puis muets puis de retour (EX-6.2, EX-8.11)", function () {
    let dir;
    let m;
    let composant;
    let calme;
    before(async function () {
      dir = repertoireTemporaire();
      m = await monterComposant({ dir, periodStart: PERIODE, evenements: TOUTES_LES_MINUTES, ErreurTransport, surcharges: { opentimestamps: { timeout_ms: 1000 } } });
      if (m.condition) return;
      composant = m.creer();
      calme = attenteCalme(composant);
      await composant.demarrer();
    });
    after(async function () {
      if (composant?.etat().demarre) await composant.arreter({ attendre: false });
      await m?.fermer?.();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it("503 puis silence : calendriers_insuffisants, a_reprendre, la soumission est rejouée avec le même engagement (nonce durable) ; au retour, en_attente et fichier .ots écrit", async function () {
      if (m.condition) return enAttente(this, m.condition);
      m.calendriers.etat.panne = true;
      await rejouer(m, composant, calme, 0, 30);
      const ots = composant.demandes().find((d) => d.kind === "ots_point");
      expect(ots, "ots_point du point médian D_6").to.not.equal(undefined);
      expect(ots.state).to.equal("a_reprendre");
      expect(ots.attempts[0]).to.include({ outcome: "echec_transitoire", error_code: "calendriers_insuffisants" });
      const corps = m.calendriers.etat.requetes.filter((r) => r.methode === "POST").map((r) => Buffer.from(r.corps).toString("hex"));
      expect(new Set(corps).size).to.equal(1, "même engagement à chaque rejeu (EX-6.2)");
      m.calendriers.etat.panne = false;
      m.calendriers.etat.muets = true;
      await m.horloge.avancer(20000, calme);
      expect(composant.demandes().find((d) => d.kind === "ots_point").attempts.length).to.be.at.least(2);
      m.calendriers.etat.muets = false;
      await m.horloge.avancer(120000, calme);
      const apres = composant.demandes().find((d) => d.kind === "ots_point");
      expect(apres.state).to.equal("en_attente");
      expect(apres.result.size).to.be.greaterThan(100);
      const nonces = new Set(m.calendriers.etat.requetes.filter((r) => r.methode === "POST").map((r) => Buffer.from(r.corps).toString("hex")));
      expect(nonces.size).to.equal(1);
      expect(fs.existsSync(path.join(dir, "stockage", ORG.slice(2), JOURNAL.slice(2), "ancres", `periode-${PERIODE}`, "ots", `point-${apres.subject.hash.slice(2)}-1.ots`))).to.equal(true);
      expect(fs.readFileSync(path.join(dir, "stockage", ORG.slice(2), JOURNAL.slice(2), "ancres", `periode-${PERIODE}`, "ots", `point-${apres.subject.hash.slice(2)}.nonce`), "utf8")).to.match(/^0x[0-9a-f]{32}\n$/);
      expect(m.journal.de("anchor_response_rejected").some((l) => l.data.error_code === "calendriers_insuffisants")).to.equal(true);
    });
  });

  describe("file pleine (EX-8.5 règle 4) et écriture de file impossible (EX-8.1)", function () {
    let dir;
    let m;
    let composant;
    let calme;
    const filePanne = { active: false, ecritures: 0 };
    before(async function () {
      dir = repertoireTemporaire();
      m = await monterComposant({
        dir, periodStart: PERIODE, evenements: TOUTES_LES_MINUTES, ErreurTransport,
        surcharges: { rfc3161: { checkpoints: { interval_s: 60 } }, registry: { checkpoints: "tous" }, opentimestamps: { checkpoint: "aucun" }, queue: { max_pending: 100 } },
      });
      if (m.condition) return;
      composant = m.creer({
        clients: {
          file: {
            ouvrir: (p) => {
              const f = FileDurable.ouvrir(p);
              return {
                ecrire(d) {
                  if (filePanne.active) throw Object.assign(new Error("espace disque insuffisant (essai)"), { code: "ENOSPC" });
                  filePanne.ecritures += 1;
                  return f.ecrire(d);
                },
                fermer: () => f.fermer(),
              };
            },
          },
        },
      });
      calme = attenteCalme(composant);
      await composant.demarrer();
    });
    after(async function () {
      if (composant?.etat().demarre) await composant.arreter({ attendre: false });
      await m?.fermer?.();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it("écriture impossible : anchor_queue_write_failed et alerte file_perdue, la demande reste en mémoire et l'ancre part quand même ; au retour du disque les lignes gardées sont réécrites (anchor_queue_write_recovered)", async function () {
      if (m.condition) return enAttente(this, m.condition);
      await rejouer(m, composant, calme, 0, 2);
      filePanne.active = true;
      await rejouer(m, composant, calme, 3, 4);
      expect(m.journal.de("anchor_queue_write_failed").length).to.be.at.least(1);
      expect(m.journal.de("alerte_file_perdue")).to.have.lengthOf(1);
      expect(composant.etat().file_en_panne).to.equal(true);
      const p3 = composant.demandes().filter((d) => N.decoderHorodatage(d.subject.declared_at) === minute(3));
      expect(p3.length).to.be.at.least(1);
      expect(p3.every((d) => d.state === "obtenue")).to.equal(true, "les demandes gardées en mémoire ont été servies");
      const avant = lireFiles(m.configuration.queue.path).demandes.map((d) => d.id);
      for (const d of p3) expect(avant).to.not.include(d.id);
      filePanne.active = false;
      await rejouer(m, composant, calme, 5, 5);
      expect(m.journal.de("anchor_queue_write_recovered")).to.have.lengthOf(1);
      const apres = lireFiles(m.configuration.queue.path);
      for (const d of p3) expect(apres.parId.get(d.id)?.state).to.equal("obtenue");
      expect(composant.etat().file_en_panne).to.equal(false);
    });

    it("file pleine : prestataires en panne, c_T = 60 s sans registre ni OpenTimestamps, deux périodes : à max_pending demandes actives un nouveau point n'est plus ancré (anchor_queue_full, file_pleine critique) ; la clôture crée toujours sa demande", async function () {
      if (m.condition) return enAttente(this, m.condition);
      // Second montage sur le même répertoire d'essai : deux périodes de points, jetons toutes les minutes, tous les prestataires en panne.
      const dir2 = path.join(dir, "pleine");
      fs.mkdirSync(dir2);
      const P2 = PERIODE + 3600;
      const serie2 = serieSynthetique({ periodStart: P2, evenementsAuxMinutes: TOUTES_LES_MINUTES, nonce: N.sha256Hex(N.utf8("noortrace/ancrage/test/nonce/p2")) });
      const remis2 = [];
      const m2 = await monterComposant({
        dir: dir2, periodStart: PERIODE, evenements: TOUTES_LES_MINUTES, ErreurTransport,
        surcharges: { rfc3161: { checkpoints: { interval_s: 60 } }, registry: { checkpoints: "aucun" }, opentimestamps: { enabled: false }, queue: { max_pending: 100 } },
        contexteSurcharges: { lireSerie: async (P) => remis2.filter((p) => p.period_start === P), lireHashesPeriode: async (P) => (P === P2 ? serie2.hashes : null) },
      });
      m2.remis.length = 0;
      Object.defineProperty(m2, "remis", { value: remis2 });
      const c2 = m2.creer({ clients: { registre: undefined } });
      const calme2 = attenteCalme(c2);
      await c2.demarrer();
      m2.transport.pannes.add(m2.interne.prestataire.url);
      m2.transport.pannes.add(m2.principal.prestataire.url);
      m2.transport.pannes.add(m2.secours.prestataire.url);
      try {
        await rejouer(m2, c2, calme2, 0, 59);
        await clore(m2, c2, calme2);
        expect(c2.demandes().filter((d) => d.kind === "jeton_point").length).to.equal(59);
        for (const point of serie2.points.slice(0, -1)) {
          await m2.horloge.aller(N.decoderHorodatage(point.checkpoint_ts), calme2);
          remis2.push(point);
          expect((await c2.remettrePoint(remisePoint(point))).admis).to.equal(true);
          await calme2();
        }
        expect(c2.etat().actives).to.be.at.most(100);
        const plein = m2.journal.de("anchor_queue_full");
        expect(plein.length).to.be.at.least(1);
        expect(plein[0].data).to.include({ max_pending: 100 });
        expect(m2.journal.de("alerte_file_pleine")[0].data.severity).to.equal("critique");
        const derniers = serie2.points.slice(-5, -1).map((p) => N.hacherPoint(p));
        const sansDemande = derniers.filter((h) => !c2.demandes().some((d) => d.subject.hash === h));
        expect(sansDemande.length).to.be.at.least(1, "un point tardif n'a reçu aucune demande");
        const cloture2 = serie2.points.at(-1);
        await m2.horloge.aller(N.decoderHorodatage(cloture2.checkpoint_ts), calme2);
        remis2.push(cloture2);
        await c2.remettrePoint(remisePoint(cloture2));
        await c2.remettreCloture(remiseCloture(serie2));
        await calme2();
        expect(c2.demandes().filter((d) => d.kind === "jeton_periode").map((d) => d.subject.period_start).sort()).to.deep.equal([PERIODE, P2]);
      } finally {
        await c2.arreter({ attendre: false });
        await m2.fermer();
      }
    });
  });

  describe("arrêt brutal entre ecrire_file et l'envoi, puis redémarrage (AN-32, AN-33, EX-8.12)", function () {
    let dir;
    let m;
    let composant;
    let calme;
    before(async function () {
      dir = repertoireTemporaire();
      m = await monterComposant({ dir, periodStart: PERIODE, evenements: TOUTES_LES_MINUTES, ErreurTransport, surcharges: { opentimestamps: { enabled: false }, registry: { checkpoints: "aucun" } } });
      if (m.condition) return;
    });
    after(async function () {
      if (composant?.etat().demarre) await composant.arreter({ attendre: false });
      await m?.fermer?.();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it("la ligne envoyee précède la requête ; le processus s'arrête avant que la requête parte ; au redémarrage (autre époque) la demande relue passe a_reprendre, une seule demande par id, nouvelle tentative à nouveau nonce ; aucune requête reçue sans ligne de file", async function () {
      if (m.condition) return enAttente(this, m.condition);
      composant = m.creer({ epoque: 1 });
      calme = attenteCalme(composant, { tolerance: () => m.transport.etat.pendantesEnVol });
      await composant.demarrer();
      m.transport.pendantes.add(m.interne.prestataire.url);
      await rejouer(m, composant, calme, 0, 5);
      const avant = lireFiles(m.configuration.queue.path);
      const jeton = avant.demandes.find((d) => d.kind === "jeton_point");
      expect(jeton.state).to.equal("envoyee");
      expect(jeton.attempts).to.have.lengthOf(1);
      expect(jeton.attempts[0].outcome).to.equal("en_cours");
      const nonce1 = jeton.attempts[0].nonce;
      expect(m.transport.requetes.filter((r) => r.url === m.interne.prestataire.url)).to.have.lengthOf(0, "la requête n'est jamais partie");
      // Arrêt brutal : rien n'est attendu, la requête en vol est perdue.
      await composant.arreter({ attendre: false });
      m.transport.pendantes.clear();
      const relance = m.creer({ epoque: 2 });
      calme = attenteCalme(relance);
      m.transport.etat.pendantesEnVol = 0;
      await relance.demarrer();
      composant = relance;
      await m.horloge.avancer(2000, calme);
      const apres = lireFiles(m.configuration.queue.path);
      expect(apres.fichiers).to.deep.equal(["file-1.ndjson", "file-2.ndjson"]);
      expect(new Set(apres.demandes.map((d) => d.id)).size).to.equal(apres.demandes.length);
      const relu = apres.parId.get(jeton.id);
      expect(relu.state).to.equal("obtenue");
      expect(relu.attempts).to.have.lengthOf(2);
      expect(relu.attempts[0]).to.include({ outcome: "echec_transitoire", error_code: "redemarrage" });
      expect(relu.attempts[1].nonce).to.not.equal(nonce1);
      expect(relu.attempts[1].correlation_id).to.equal(`jeton_point:${jeton.subject.hash.slice(2, 18)}:2`);
      // AN-32 : chaque requête reçue par l'autorité porte un nonce consigné dans une ligne envoyee de la file.
      const lignes = ["file-1.ndjson", "file-2.ndjson"].flatMap((f) => fs.readFileSync(path.join(m.configuration.queue.path, f), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)));
      const nonces = new Set(lignes.filter((l) => l.state === "envoyee").flatMap((l) => l.attempts.map((a) => a.nonce)));
      const depot = DepotAncres.ouvrir({ racine: path.join(dir, "stockage"), orgId: ORG, journalId: JOURNAL });
      const acquisitions = depot.lireAcquisitions(PERIODE).enregistrements;
      expect(acquisitions.length).to.be.at.least(1);
      for (const e of acquisitions) expect(nonces.has(e.nonce)).to.equal(true);
      expect(m.transport.requetes.length).to.equal(acquisitions.length);
      expect(m.journal.de("anchoring_started")).to.have.lengthOf(2);
      expect(m.journal.de("anchoring_started")[1].data.queue_entries).to.equal(avant.demandes.length);
    });
  });

  describe("T-10 : CRL révoquée après genTime → alerte critique, jeton marqué revoque, demande obtenue → a_reprendre et relève au secours (EX-5.10 étape 10, EX-8.3, EX-5.8)", function () {
    let dir;
    let m;
    let composant;
    let calme;
    before(async function () {
      dir = repertoireTemporaire();
      m = await monterComposant({ dir, periodStart: PERIODE, evenements: { 1: 1 }, ErreurTransport, surcharges: { opentimestamps: { enabled: false } } });
      if (m.condition) return;
      composant = m.creer();
      calme = attenteCalme(composant);
      await composant.demarrer();
    });
    after(async function () {
      if (composant?.etat().demarre) await composant.arreter({ attendre: false });
      await m?.fermer?.();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it("le jeton de clôture du principal est promu, puis la CRL révoque l'unité (keyCompromise) : .crl.pem écrit, ligne revoked, alerte revoque, nouveau jeton du secours promu, l'ancien conservé", async function () {
      if (m.condition) return enAttente(this, m.condition);
      await rejouer(m, composant, calme, 0, 59);
      await clore(m, composant, calme);
      await m.horloge.avancer(5000, calme);
      const periode = composant.demandes().find((d) => d.kind === "jeton_periode");
      expect(periode.state).to.equal("obtenue");
      expect(periode.result.provider).to.equal("qtsa-principal");
      const depot = DepotAncres.ouvrir({ racine: path.join(dir, "stockage"), orgId: ORG, journalId: JOURNAL });
      const promuAvant = depot.promu("manifeste", PERIODE);
      expect(promuAvant.provider_id).to.equal("qtsa-principal");
      // Révocation de l'unité du principal, datée une minute après genTime, raison keyCompromise (jamais tolérée).
      m.crl.revoquer("qtsa-principal", { serie: m.principal.serieUnite, date: m.horloge.murale() + 60000, raison: 1 });
      await m.horloge.avancer(11 * 60000, calme);
      expect(m.journal.de("alerte_revoque")).to.have.lengthOf(1);
      expect(m.journal.de("alerte_revoque")[0].data.severity).to.equal("critique");
      expect(m.journal.de("crl_captured").some((l) => l.data.status === "echoue" && l.data.provider === "qtsa-principal")).to.equal(true);
      expect(m.journal.de("anchor_fallback").some((l) => l.data.reason === "revoque" && l.data.to === "qtsa-secours")).to.equal(true);
      const apres = composant.demandes().find((d) => d.kind === "jeton_periode");
      expect(apres.state).to.equal("obtenue");
      expect(apres.result.provider).to.equal("qtsa-secours");
      expect(apres.attempts.map((a) => [a.provider, a.outcome, a.error_code])).to.deep.equal([["qtsa-principal", "echec_permanente", "revoque"], ["qtsa-secours", "obtenue", null]]);
      const dernieres = depot.dernieresAcquisitions(PERIODE).enregistrements.filter((e) => e.object === "manifeste");
      const ancien = dernieres.find((e) => e.provider_id === "qtsa-principal");
      expect(ancien.revoked).to.equal(true);
      expect(ancien.checks["T-10"]).to.equal("echoue");
      expect(ancien.files.crls).to.have.lengthOf(1);
      expect(fs.existsSync(path.join(depot.repertoire(PERIODE), ancien.files.token)), "le jeton révoqué reste conservé comme pièce").to.equal(true);
      const nouveau = depot.promu("manifeste", PERIODE);
      expect(nouveau.provider_id).to.equal("qtsa-secours");
      expect(nouveau.promoted).to.equal(true);
      expect(nouveau.attempt_id).to.not.equal(promuAvant.attempt_id);
    });
  });

  describe("retrait de la qualification (EX-5.9 ; TC-24 de CT-9) et rechargement (EX-4.9)", function () {
    let dir;
    let m;
    let composant;
    let calme;
    before(async function () {
      dir = repertoireTemporaire();
      m = await monterComposant({ dir, periodStart: PERIODE, evenements: { 1: 1 }, ErreurTransport, surcharges: { opentimestamps: { enabled: false } } });
      if (m.condition) return;
      composant = m.creer();
      calme = attenteCalme(composant);
      await composant.demarrer();
    });
    after(async function () {
      if (composant?.etat().demarre) await composant.arreter({ attendre: false });
      await m?.fermer?.();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it("qualified du principal retiré pendant que la clôture attend sa réponse : la demande part aussi au secours, le jeton du secours est promu avec qualified non nul, l'instantané du principal passe null jusqu'au rechargement ; aucun rôle ne change ; en production un rechargement sans principal qualifié est refusé (AN-1)", async function () {
      if (m.condition) return enAttente(this, m.condition);
      await rejouer(m, composant, calme, 0, 59);
      m.transport.pendantes.add(m.principal.prestataire.url);
      calme = attenteCalme(composant, { tolerance: () => m.transport.etat.pendantesEnVol });
      await clore(m, composant, calme);
      await m.horloge.avancer(5000, calme);
      const avant = composant.demandes().find((d) => d.kind === "jeton_periode");
      expect(avant.state).to.equal("envoyee");
      expect(avant.attempts.map((a) => a.provider)).to.deep.equal(["qtsa-principal"]);
      const actions = await composant.retirerQualification("qtsa-principal");
      expect(actions.some((a) => a.action === "releve" && a.detail.provider === "qtsa-secours")).to.equal(true);
      await calme();
      await m.horloge.avancer(2000, calme);
      const apres = composant.demandes().find((d) => d.kind === "jeton_periode");
      expect(apres.state).to.equal("obtenue");
      expect(apres.result.provider).to.equal("qtsa-secours");
      expect(m.journal.de("anchor_fallback")[0].data).to.include({ to: "qtsa-secours", reason: "qualification_retiree" });
      expect(m.journal.de("provider_qualification_withdrawn")[0].data).to.include({ provider: "qtsa-principal", role: "principal" });
      expect(composant.etat().qualifications_retirees).to.deep.equal(["qtsa-principal"]);
      expect(composant.configuration.rfc3161.providers.find((p) => p.id === "qtsa-principal").role).to.equal("principal");
      const { fiche } = await composant.fiche("qtsa-principal");
      expect(fiche.qualified).to.equal(null);
      expect(fiche.role).to.equal("principal");
      // Rechargement de la même configuration : accepté en profil test ; l'instantané revient.
      const r = composant.recharger(m.configuration);
      expect(r.accepte).to.equal(true);
      expect(composant.etat().qualifications_retirees).to.deep.equal([]);
      expect((await composant.fiche("qtsa-principal")).fiche.qualified).to.not.equal(null);
      // En production : un document dont le principal n'est pas qualifié est refusé par la règle 4 d'EX-4.9.
      const sansQualification = structuredClone(m.configuration);
      sansQualification.rfc3161.providers[0].qualified = null;
      for (const p of sansQualification.rfc3161.providers) if (p.role !== "interne") p.url = p.url.replace(/^http:/, "https:");
      const v = validerConfigurationComposant(sansQualification, { profil: "production", checkpointIntervalEnregistreur: 60, secrets: m.secrets });
      expect(v.valide).to.equal(false);
      expect(v.erreurs.map((e) => e.regle)).to.include("4");
      expect(v.erreurs.some((e) => e.message.includes("sans qualified"))).to.equal(true);
      const invalide = structuredClone(m.configuration);
      invalide.rfc3161.retry.initial_ms = invalide.rfc3161.retry.max_ms + 1;
      expect(composant.recharger(invalide)).to.deep.include({ accepte: false });
      expect(m.journal.de("config_reload_rejected")).to.have.lengthOf(1);
      expect(composant.configuration.rfc3161.retry.initial_ms).to.equal(5000, "l'ancienne configuration reste en vigueur");
    });
  });

  describe("entrées hostiles : admission AN-3, configuration AN-1, secrets, horloge", function () {
    let dir;
    let m;
    let composant;
    let calme;
    before(async function () {
      dir = repertoireTemporaire();
      m = await monterComposant({ dir, periodStart: PERIODE, evenements: { 1: 1 }, ErreurTransport, surcharges: { opentimestamps: { enabled: false } } });
      if (m.condition) return;
      composant = m.creer();
      calme = attenteCalme(composant);
      await composant.demarrer();
    });
    after(async function () {
      if (composant?.etat().demarre) await composant.arreter({ attendre: false });
      await m?.fermer?.();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it("un point à signature altérée, un point hors série (chaînage), un checkpointHash remis différent, un manifeste mal signé : refusés, consignés anchor_admission_refused et alertés, jamais ancrés (EX-3.1, AN-3)", async function () {
      if (m.condition) return enAttente(this, m.condition);
      await rejouer(m, composant, calme, 0, 1);
      const bon = m.serie.points[2];
      const altere = { ...bon, sig: "0x" + bon.sig.slice(2, 4).replace(/./g, (c) => (c === "0" ? "1" : "0")) + bon.sig.slice(4) };
      const r1 = await composant.remettrePoint(remisePoint(altere));
      expect(r1).to.deep.equal({ admis: false, regle: "signature" });
      const saute = m.serie.points[5];
      const r2 = await composant.remettrePoint(remisePoint(saute));
      expect(r2).to.deep.equal({ admis: false, regle: "chainage" });
      const r3 = await composant.remettrePoint({ ...remisePoint(bon), checkpointHash: "0x" + "ab".repeat(32) });
      expect(r3).to.deep.equal({ admis: false, regle: "empreinte" });
      const r4 = await composant.remettrePoint({ point: null });
      expect(r4).to.deep.equal({ admis: false, regle: "format" });
      const sig = { ...m.serie.signature, sig: "0x" + "00".repeat(64) };
      const r5 = await composant.remettreCloture({ ...remiseCloture(m.serie), signature: sig });
      expect(r5).to.deep.equal({ admis: false, regle: "signature" });
      const r6 = await composant.remettreCloture({ ...remiseCloture(m.serie), periodHash: "0x" + "cd".repeat(32) });
      expect(r6).to.deep.equal({ admis: false, regle: "empreinte" });
      expect(m.journal.de("anchor_admission_refused")).to.have.lengthOf(6);
      expect(m.journal.de("alerte_admission_refusee")).to.have.lengthOf(6);
      const demandes = composant.demandes();
      expect(demandes.some((d) => d.subject.hash === N.hacherPoint(altere) || d.subject.hash === N.hacherPoint(saute))).to.equal(false);
      expect(demandes.some((d) => d.subject.kind === "periode")).to.equal(false);
      // Le bon point, lui, est admis ensuite.
      await m.horloge.aller(N.decoderHorodatage(bon.checkpoint_ts), calme);
      m.remis.push(bon);
      expect((await composant.remettrePoint(remisePoint(bon))).admis).to.equal(true);
    });

    it("configuration refusée (AN-1) : demarrer lève ErreurConfigurationAncrage avec le rapport nominatif ; secret non résolu : règle secrets ; horloge sans programmer, contexte sans org_id : refusés", async function () {
      if (m.condition) return enAttente(this, m.condition);
      const mauvaise = structuredClone(m.configuration);
      mauvaise.rfc3161.providers.push({ ...mauvaise.rfc3161.providers[0], id: "second-principal" });
      const c = m.creer({ configuration: mauvaise, epoque: 7 });
      expect(c.configurationValide().valide).to.equal(false);
      expect(c.configurationValide().erreurs.map((e) => e.regle)).to.include("2");
      let erreur = null;
      try {
        await c.demarrer();
      } catch (e) {
        erreur = e;
      }
      expect(erreur).to.be.instanceOf(ErreurConfigurationAncrage);
      expect(erreur.erreurs.some((e) => e.regle === "2")).to.equal(true);
      expect(m.journal.de("config_invalid").length).to.be.at.least(1);
      expect((await c.remettrePoint(remisePoint(m.serie.points[0]))).regle).to.equal("composant_non_demarre");
      const sansSecret = validerConfigurationComposant(m.configuration, { profil: "test", checkpointIntervalEnregistreur: 60, secrets: new Map() });
      expect(sansSecret.valide).to.equal(false);
      expect(sansSecret.erreurs.map((e) => e.regle)).to.deep.equal(["secrets", "secrets"]);
      expect(() => creerComposantAncrage({ configuration: m.configuration, contexte: m.contexte, horloge: { murale: () => 0, monotone: () => 0 }, aleatoire: aleatoireFixe() })).to.throw(TypeError, /programmer/);
      expect(() => creerComposantAncrage({ configuration: m.configuration, contexte: { ...m.contexte, org_id: "0x12" }, horloge: new HorlogeReglable(T0), aleatoire: aleatoireFixe() })).to.throw(TypeError, /org_id/);
      expect(() => creerComposantAncrage({ configuration: m.configuration, contexte: m.contexte, horloge: new HorlogeReglable(T0), aleatoire: null })).to.throw(TypeError, /aleatoire/);
    });
  });
});
