// Composant d'ancrage, révision 0.6 de CT-5 : clé facultative
// `queue.compact_bytes` (EX-4.8, AN-1 : défaut 16 777 216, bornes du schéma au
// démarrage et au rechargement ; hors de la projection, EX-8.2), compactage de
// la file à la clôture et ligne `anchor_queue_compacted`, échec du compactage
// consigné `anchor_queue_compaction_failed` sans retarder les envois (EX-8.5,
// règle 5), `.compactage` résiduel supprimé au démarrage (EX-8.12), aucun
// autre fichier supprimé (EX-8.14, EX-5.15), lignes du journal qui rendent
// compte d'une tentative avec `attempt` et `attempt_id` (EX-8.15). Horloge
// injectée, autorités et calendriers locaux, répertoires sous `os.tmpdir()` ;
// aucun réseau public.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as N from "@noortrace/noyau";
import { ErreurTransport } from "@noortrace/ancrage/rfc3161";
import { lireFiles, projection, COMPACT_BYTES_DEFAUT } from "@noortrace/ancrage/planificateur";
import { ErreurConfigurationAncrage, validerConfigurationComposant } from "../paquets/ancrage/src/composant.mjs";
import { attenteCalme, monterComposant, remisePoint, remiseCloture, repertoireTemporaire, enAttente } from "./fixtures/ancrage-composant/outils.mjs";

const PERIODE = 1793862000; // 2026-11-05T07:00:00Z
const T0 = PERIODE * 1000;
const QUELQUES_MINUTES = { 1: 1, 2: 1, 3: 1, 6: 1, 11: 1 };

async function rejouer(m, composant, calme, de, a) {
  for (const point of m.serie.points.slice(0, -1)) {
    const t = N.decoderHorodatage(point.checkpoint_ts);
    const mn = (t - T0) / 60000;
    if (mn < de || mn > a) continue;
    await m.horloge.aller(t, calme);
    m.remis.push(point);
    expect((await composant.remettrePoint(remisePoint(point))).admis, point.checkpoint_ts).to.equal(true);
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

/** Inventaire récursif des fichiers d'un répertoire (chemins relatifs). */
function inventaire(racine) {
  const r = [];
  const parcourir = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) parcourir(p);
      else r.push(path.relative(racine, p));
    }
  };
  if (fs.existsSync(racine)) parcourir(racine);
  return r.sort();
}

describe("ancrage, composant : file de la révision 0.6 de CT-5 (EX-4.8, EX-8.5 règle 5, EX-8.12, EX-8.14, EX-8.15)", function () {
  this.timeout(600000);

  describe("EX-4.8, AN-1, EX-8.2 : queue.compact_bytes facultative", function () {
    let dir;
    let m;
    before(async function () {
      dir = repertoireTemporaire("noortrace-ancrage-compact-cfg-");
      m = await monterComposant({ dir, periodStart: PERIODE, evenements: QUELQUES_MINUTES });
    });
    after(async function () {
      await m?.fermer?.();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it("sans la clé : document accepté, défaut 16 777 216 appliqué par la couche de fichier ; 2 097 152 appliqué tel quel ; la projection du planificateur ne la porte pas", async function () {
      if (m.condition) return enAttente(this, m.condition);
      expect(m.configuration.queue).to.not.have.property("compact_bytes");
      expect(validerConfigurationComposant(m.configuration, { profil: "test", checkpointIntervalEnregistreur: 60, secrets: m.secrets }).valide).to.equal(true);
      const c1 = m.creer();
      await c1.demarrer();
      expect(c1.etat().file).to.include({ compact_bytes: COMPACT_BYTES_DEFAUT, compactages: 0, echecs: 0 });
      await c1.arreter({ attendre: false });
      const conf = structuredClone(m.configuration);
      conf.queue.compact_bytes = 2097152;
      const c2 = m.creer({ configuration: conf, epoque: 2 });
      await c2.demarrer();
      expect(c2.etat().file.compact_bytes).to.equal(2097152);
      expect(projection(conf).queue).to.deep.equal(projection(m.configuration).queue);
      expect(Object.keys(projection(conf).queue)).to.deep.equal(["max_pending", "anchor_pending_alert_s"]);
      await c2.arreter({ attendre: false });
    });

    it("1 048 575 et 1 073 741 825 sont refusés (règle schema) au démarrage et au rechargement ; les bornes 1 048 576 et 1 073 741 824 sont admises", async function () {
      if (m.condition) return enAttente(this, m.condition);
      const avec = (v) => {
        const c = structuredClone(m.configuration);
        c.queue.compact_bytes = v;
        return c;
      };
      for (const v of [1048575, 1073741825]) {
        const c = m.creer({ configuration: avec(v), epoque: 3 });
        let erreur = null;
        try {
          await c.demarrer();
        } catch (e) {
          erreur = e;
        }
        expect(erreur, String(v)).to.be.instanceOf(ErreurConfigurationAncrage);
        expect(erreur.erreurs.map((x) => x.regle), String(v)).to.deep.equal(["schema"]);
        expect(erreur.erreurs[0].message).to.match(/compact_bytes/);
      }
      const c = m.creer({ epoque: 4 });
      await c.demarrer();
      for (const v of [1048575, 1073741825]) {
        const r = c.recharger(avec(v));
        expect(r.accepte, String(v)).to.equal(false);
        expect(r.erreurs.map((x) => x.regle)).to.deep.equal(["schema"]);
      }
      for (const v of [1048576, 1073741824]) expect(c.recharger(avec(v)).accepte, String(v)).to.equal(true);
      await c.arreter({ attendre: false });
    });
  });

  describe("EX-8.5 règle 5, EX-8.12, EX-8.14 : compactage à la clôture, .compactage résiduel, aucune autre suppression", function () {
    let dir;
    let m;
    let composant;
    let calme;
    let avantDemarrage;
    before(async function () {
      dir = repertoireTemporaire("noortrace-ancrage-compact-cloture-");
      m = await monterComposant({ dir, periodStart: PERIODE, evenements: QUELQUES_MINUTES });
      if (m.condition) return;
      fs.mkdirSync(m.configuration.queue.path, { recursive: true });
      fs.writeFileSync(path.join(m.configuration.queue.path, "file-1.ndjson.compactage"), '{"reste":');
      fs.writeFileSync(path.join(m.configuration.queue.path, "file-0.ndjson"), "");
      avantDemarrage = inventaire(dir);
      composant = m.creer();
      calme = attenteCalme(composant);
      await composant.demarrer();
    });
    after(async function () {
      if (composant?.etat().demarre) await composant.arreter({ attendre: false });
      await m?.fermer?.();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it("au démarrage, le .compactage resté d'un arrêt est supprimé, les autres fichiers de file restent", async function () {
      if (m.condition) return enAttente(this, m.condition);
      const fichiers = fs.readdirSync(m.configuration.queue.path).sort();
      expect(fichiers).to.not.include("file-1.ndjson.compactage");
      expect(fichiers).to.include("file-0.ndjson");
      expect(fichiers).to.include("file-1.ndjson");
    });

    it("à la clôture, après l'écriture des trois demandes, la file est compactée (anchor_queue_compacted : bytes_before, bytes_after, requests) ; l'état relu est celui du composant ; aucun fichier n'a disparu hors le .compactage", async function () {
      if (m.condition) return enAttente(this, m.condition);
      await rejouer(m, composant, calme, 0, 59);
      expect(m.journal.de("anchor_queue_compacted")).to.have.lengthOf(0);
      await clore(m, composant, calme);
      const lignes = m.journal.de("anchor_queue_compacted");
      expect(lignes.length).to.be.at.least(1);
      const premiere = lignes[0].data;
      expect(Object.keys(premiere).sort()).to.deep.equal(["bytes_after", "bytes_before", "requests"]);
      expect(premiere.bytes_after).to.be.below(premiere.bytes_before);
      expect(lignes[0].level).to.equal("info");
      const relue = lireFiles(m.configuration.queue.path);
      expect(relue.tronquees).to.deep.equal([]);
      expect(premiere.requests).to.be.at.least(composant.demandes().filter((d) => d.subject.kind === "point").length);
      const parId = new Map(composant.demandes().map((d) => [d.id, N.jcs(d)]));
      for (const d of relue.demandes) expect(N.jcs(d)).to.equal(parId.get(d.id));
      expect(composant.etat().file.compactages).to.equal(lignes.length);
      const apres = inventaire(dir);
      const disparus = avantDemarrage.filter((f) => !apres.includes(f));
      expect(disparus).to.deep.equal([path.join("file", "file-1.ndjson.compactage")]);
    });
  });

  describe("EX-8.15 et EX-8.5 règle 5 (échec) : attempt et attempt_id au journal ; compactage en échec sans retard", function () {
    let dir;
    let m;
    let composant;
    let calme;
    before(async function () {
      dir = repertoireTemporaire("noortrace-ancrage-compact-echec-");
      m = await monterComposant({ dir, periodStart: PERIODE, evenements: QUELQUES_MINUTES, ErreurTransport });
      if (m.condition) return;
      composant = m.creer({ clients: { file: { crochet: (pas) => {
        if (pas === "ecriture") throw Object.assign(new Error("plus de place (essai)"), { code: "ENOSPC" });
      } } } });
      calme = attenteCalme(composant);
      await composant.demarrer();
    });
    after(async function () {
      if (composant?.etat().demarre) await composant.arreter({ attendre: false });
      await m?.fermer?.();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it("prestataire des points coupé quelques minutes : les lignes anchor_response_rejected et anchor_retry consignées portent attempt (rang n) et attempt_id (<kind>:<16 hex>:<n>)", async function () {
      if (m.condition) return enAttente(this, m.condition);
      m.transport.pannes.add(m.interne.prestataire.url);
      await rejouer(m, composant, calme, 0, 7);
      await m.horloge.aller(T0 + 8 * 60000, calme);
      m.transport.pannes.clear();
      const lignes = m.journal.lignes.filter((l) => ["anchor_response_rejected", "anchor_retry", "anchor_fallback"].includes(l.event) && String(l.data.request_id).startsWith("jeton_point:"));
      const rejets = lignes.filter((l) => l.event === "anchor_response_rejected" && l.data.error_code === "erreur_transport");
      const reprises = lignes.filter((l) => l.event === "anchor_retry");
      expect(rejets.length).to.be.at.least(2);
      expect(reprises.length).to.be.at.least(2);
      for (const l of [...rejets, ...reprises]) {
        const [kind, hash] = String(l.data.request_id).split(":");
        expect(Number.isInteger(l.data.attempt), JSON.stringify(l.data)).to.equal(true);
        expect(l.data.attempt_id, JSON.stringify(l.data)).to.equal(`${kind}:${hash.slice(2, 18)}:${l.data.attempt}`);
      }
      // Les rangs consignés couvrent toutes les tentatives échouées de chaque demande.
      for (const d of composant.demandes().filter((x) => x.kind === "jeton_point")) {
        const echouees = d.attempts.filter((a) => a.error_code === "erreur_transport").map((a) => a.n);
        const consignees = new Set(rejets.filter((l) => l.data.request_id === d.id).map((l) => l.data.attempt));
        for (const n of echouees) expect(consignees.has(n), `${d.id} ${n}`).to.equal(true);
      }
    });

    it("ENOSPC à l'écriture du fichier neuf à la clôture : anchor_queue_compaction_failed (step ecriture, errno ENOSPC, bytes), sans alerte propre ; ancienne file intacte ; la demande de jeton de la période part au même instant", async function () {
      if (m.condition) return enAttente(this, m.condition);
      await rejouer(m, composant, calme, 8, 59);
      const fichier = path.join(m.configuration.queue.path, "file-1.ndjson");
      const envoisAvant = m.transport.requetes.length;
      await clore(m, composant, calme);
      const echecs = m.journal.de("anchor_queue_compaction_failed");
      expect(echecs).to.have.lengthOf(1);
      expect(echecs[0].level).to.equal("error");
      expect(echecs[0].data).to.include({ step: "ecriture", errno: "ENOSPC" });
      expect(echecs[0].data.bytes).to.be.above(0);
      expect(m.journal.evenements().filter((e) => e.startsWith("alerte_") && /compact/.test(e))).to.deep.equal([]);
      expect(fs.readdirSync(m.configuration.queue.path).filter((n) => n.endsWith(".compactage"))).to.deep.equal([]);
      expect(lireFiles(m.configuration.queue.path).tronquees).to.deep.equal([]);
      expect(fs.statSync(fichier).size).to.be.at.least(echecs[0].data.bytes);
      const jetonPeriode = composant.demandes().find((d) => d.kind === "jeton_periode");
      expect(jetonPeriode.state).to.equal("obtenue");
      expect(m.transport.requetes.length).to.be.above(envoisAvant);
    });

  });
});
