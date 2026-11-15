// Revue de sécurité interne de l'étape 8 (enregistreur : cœur, politique,
// approbations, points de contrôle). Chaque `it` nomme l'exigence ou le défaut qu'il reproduit ;
// chaque essai échoue sur le code d'avant la correction et passe après.
//
//   CT-2 EX-7.19   remises bornées, jamais réinscrites, une ligne d'erreur par remise refusée, boucle decisions qui marque une pause
//   EX-3.6   relecture d'un segment par tranches qui rendent la main (bail, points, hôtes)
//     RL-3 lit les événements en attente et les intentions ouvertes
//   EX-7.14   réponses du service hors des formes de CT-3 §12 : erreur du service, jamais adoptées
//     lire une série de points ne la tronque pas ; seule la reprise de l'écrivain coupe

import { expect } from "chai";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import * as N from "@noortrace/noyau";
import * as E from "@noortrace/enregistreur";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { configurationDev, repertoireTemporaire, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";

// Espaces de noms : les fonctions nouvelles manquent dans le code d'avant la correction (rejeu) ; chaque essai échoue alors par son oracle.
const { Coeur, HorlogeReglable, validerConfiguration, pieceJson, lireEvenements, ligneRemise, ErreurServiceApprobation, ErreurEnregistreur, ClientServiceApprobation, relireSegment, relireSerie, verifierSegment, ClesChaine } = E;
const relireSegmentParTranches = E.relireSegmentParTranches ?? (async (o, options) => relireSegment(o, options));
const defautFormeCharger = E.defautFormeCharger ?? (() => undefined);

const enc = (o) => new TextEncoder().encode(JSON.stringify(o));
const SEGMENT_DEMO = new URL("../spec/vecteurs/ct-2/evenements/journal-demo/segment.ndjson", import.meta.url);

/** Cœur réel, service factice ; `decider` fixe les décisions. */
async function demarrer(o = {}) {
  const dir = repertoireTemporaire("noortrace-revue-coeur-");
  let { config } = configurationDev(dir);
  config = validerConfiguration(enc(config)).config;
  const horloge = new HorlogeReglable(N.decoderHorodatage("2026-11-10T10:14:02.000Z"));
  const service = new ServiceApprobationFactice({ org_id: config.recorder.org_id, journal_id: config.recorder.journal_id, decider: o.decider ?? (() => ({ decision: "a_approuver", rule: "paiement > 5000 CHF" })) });
  if (o.service) o.service(service);
  const coeur = await Coeur.demarrer({ config, secrets: secretsDev(), horloge, service, ...(o.coeur ?? {}) });
  return { dir, config, coeur, service, async arreter() { await coeur.arreter().catch(() => {}); fs.rmSync(dir, { recursive: true, force: true }); } };
}

/** Retenue scellée puis approuvée : rend le ticket et les objets de relais. */
async function retenueApprouvee(b) {
  const { coeur, service } = b;
  const delegation = { launched_by: "agent-sinistres", on_behalf_of: null, scope: "sinistres:paiement", run_id: null };
  const args = { claim_id: "2026-1", amount: "7400.00", currency: "CHF" };
  const p = pieceJson(args);
  await coeur.ecrirePiece(p);
  const capture = { host: { id: "agent-sinistres-stdio" }, delegation, tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", class: "ecriture", arguments: p.reference, context: [], intent: null, code: {} };
  const requete = { tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", arguments: args, class: "ecriture", delegation, intent: null, code: { model: null, prompt_version: null, policy_version: coeur.versionPolitique, recorder: "0.1.0" }, context: [] };
  const r1 = await coeur.evaluer(requete);
  await coeur.scellerRetenue(capture, r1, args);
  await new Promise((x) => setTimeout(x, 30));
  const remise = service.decider_ticket(r1.ticket);
  const acq = await coeur.traiterRemise(remise);
  return { ticket: r1.ticket, capture, requete, args, acq, remise };
}

/** Segment de `n` événements valides, chaînés et signés par une graine éphémère (jamais écrite). */
function segmentSigne(n) {
  const lignes = fs.readFileSync(SEGMENT_DEMO, "utf8").split("\n").filter(Boolean);
  const entete = JSON.parse(lignes[0]);
  const modele = JSON.parse(lignes[2]);
  const g = new Uint8Array(randomBytes(32));
  const pub = N.clePubliqueEd25519(g);
  const utf8 = new TextEncoder();
  const morceaux = [utf8.encode(JSON.stringify(entete) + "\n")];
  let prev = entete.prev_hash;
  for (let seq = 1; seq <= n; seq++) {
    const e = N.scellerEvenement({ ...modele, seq, prev_hash: prev }, g);
    prev = e.hash;
    morceaux.push(utf8.encode(JSON.stringify(e) + "\n"));
  }
  g.fill(0);
  return { entete, pub, octets: new Uint8Array(Buffer.concat(morceaux)) };
}

describe("enregistreur, revue (étape 8) : cœur, politique, approbations, points", function () {
  this.timeout(120000);

  describe("CT-2 EX-7.19 : remises du service d'approbation", function () {
    it("une remise au-delà des bornes (ticket > 256, remise_id > 512, plus de 1 024 membres, plus de 1 Mio) n'a pas la forme d'une remise (ligneRemise null : ni inscrite, ni gardée) ; une remise ordinaire la garde", function () {
      const base = { remise_id: "apr-x/1", ticket: "apr-x", approval: { decision: "approuve" }, approver_set: { members: ["0x" + "11".repeat(20)] } };
      expect(ligneRemise(base)).to.include({ kind: "remise", ticket: "apr-x", remise_id: "apr-x/1", decision: "approuve" });
      expect(ligneRemise({ ...base, ticket: "t".repeat(257) })).to.equal(null);
      expect(ligneRemise({ ...base, remise_id: "r".repeat(513) })).to.equal(null);
      expect(ligneRemise({ ...base, approver_set: { members: Array(1025).fill("0x" + "11".repeat(20)) } })).to.equal(null);
      expect(ligneRemise({ ...base, approver_set: { remplissage: "A".repeat(1048576) } })).to.equal(null);
      expect(E.MEMBRES_JEU_REMISE_MAX).to.equal(1024);
      expect(E.REMISE_MAX_OCTETS).to.equal(1048576);
    });

    it("une remise représentée (acquitter en échec, CT-3 T12) n'est inscrite qu'une fois au fichier des approbations et en mémoire, approval_remise_refused n'est consigné qu'une fois par remise, et la boucle decisions marque une pause croissante : moins de dix appels en 1,5 s (avant : des milliers)", async function () {
      const b = await demarrer();
      try {
        const { coeur, service } = b;
        // La remise qui a produit la décision, représentée par le service tant qu'elle n'est pas acquittée (CT-3 T12).
        const { ticket, remise } = await retenueApprouvee(b);
        let appels = 0;
        service.decisions = async () => {
          appels++;
          return { remises: [remise] };
        };
        service.acquitter = async () => {
          throw new ErreurServiceApprobation("indisponible");
        };
        const fichier = path.join(coeur.repertoire, "approbations", "approbations-00000000000000000001.ndjson");
        const avant = fs.readFileSync(fichier, "utf8").trim().split("\n").filter((l) => JSON.parse(l).kind === "remise").length;
        expect(avant).to.equal(1);
        coeur.politique.demarrerBoucle({ wait_ms: 25000 });
        await new Promise((x) => setTimeout(x, 1500));
        coeur.politique.arreter();
        await new Promise((x) => setTimeout(x, 50));
        const lignes = fs.readFileSync(fichier, "utf8").trim().split("\n").map((l) => JSON.parse(l));
        expect(lignes.filter((l) => l.kind === "remise"), "aucune réinscription").to.have.length(1);
        expect(coeur.approbations.remises.get(ticket), "une seule ligne en mémoire").to.have.length(1);
        expect(appels, `appels decisions : ${appels}`).to.be.within(2, 9);
        const refus = coeur.journal.trouver("approval_remise_refused").filter((l) => l.level === "error");
        expect(refus, "une ligne d'erreur pour cette remise").to.have.length(1);
        expect(refus[0].data).to.include({ check: "SG-3", raison: "ticket_deja_decide" });
        expect(coeur.metriques.valeur("noortrace_approval_remises_refused_total", { check: "SG-3" })).to.equal(appels);
        expect(E.PAUSE_REFUS_MIN_MS).to.equal(200);
        expect(E.PAUSE_REFUS_MAX_MS).to.equal(5000);
      } finally {
        await b.arreter();
      }
    });
  });

  describe("RL-3 après une panne du pas 12", function () {
    it("après un relais approuvé dont l'événement est en attente (-31017), un second relais du même ticket est refusé par RL-3 (intention ouverte, événement en attente), avant comme après le scellement de l'attente : la chaîne porte un seul executee du ticket", async function () {
      let libres = 1e12;
      const b = await demarrer({ coeur: { octetsLibres: async () => libres } });
      try {
        const { coeur } = b;
        const { ticket, capture, requete, args } = await retenueApprouvee(b);
        const r2 = await coeur.evaluer(requete);
        expect(r2.ticket_state).to.equal("approuve");
        const relais1 = await coeur.preparerRelais(capture, { reponse: r2, argumentsEnClair: args, upstream_id: "1" });
        libres = 0;
        let code1 = null;
        try {
          await coeur.terminerRelais(relais1, { resultat: pieceJson({ content: [{ type: "text", text: "paiement 1 fait" }] }), resultatRedige: {}, argumentsRediges: args, duration_ms: 5, is_error: false });
        } catch (e) {
          code1 = e.code;
        }
        expect(code1).to.equal(-31017);
        expect(coeur.attente).to.have.length(1);
        // Le stockage revient ; l'événement en attente n'est pas encore scellé : un service fautif répond de nouveau approuve.
        libres = 1e12;
        await coeur.ecrivain.reprendreStockage();
        const r3 = await coeur.evaluer(requete);
        expect(r3.ticket_state).to.equal("approuve");
        let refus = null;
        try {
          await coeur.preparerRelais(capture, { reponse: r3, argumentsEnClair: args, upstream_id: "2" });
        } catch (e) {
          refus = e;
        }
        expect(refus, "second relais refusé").to.be.instanceOf(ErreurEnregistreur);
        expect(refus.donnees?.verification).to.equal("RL-3");
        expect(coeur.metriques.valeur("noortrace_approval_relays_refused_total", { check: "RL-3" })).to.equal(1);
        // Scellement de l'attente : le premier executee devient durable ; RL-3 refuse toujours (index).
        await coeur.viderAttente();
        expect(coeur.attente).to.have.length(0);
        let refus2 = null;
        try {
          await coeur.preparerRelais(capture, { reponse: await coeur.evaluer(requete), argumentsEnClair: args, upstream_id: "3" });
        } catch (e) {
          refus2 = e;
        }
        expect(refus2?.donnees?.verification).to.equal("RL-3");
        const executees = (await lireEvenements(coeur.repertoire)).filter((e) => e.execution.status === "executee" && e.approval?.ticket === ticket && e.execution.tool === "sap__payments.create");
        expect(executees.map((e) => e.seq)).to.have.length(1);
        expect(coeur.relaisEnCours.has(ticket), "ticket libéré après le scellement").to.equal(false);
      } finally {
        await b.arreter();
      }
    });
  });

  describe("CT-2 EX-7.14 : réponses du service d'approbation hors des formes de CT-3 §12", function () {
    it("une réponse charger sans approval_candidates (ou hors forme) vaut une erreur du service (approval_service_unavailable, code hors_forme:*), n'est pas adoptée (tout outil reste susceptible) et le charger suivant bien formé l'est", async function () {
      // Décision du porteur du 14 novembre 2026, addendum : la réponse bien formée de charger porte aussi approval_sha256 (hex de 32 octets).
      expect(defautFormeCharger({ approval_candidates: ["sap__payments.create"], approval_sha256: `0x${"ab".repeat(32)}` })).to.equal(null);
      expect(defautFormeCharger({ state: "x" })).to.equal("approval_candidates_absent");
      expect(defautFormeCharger({ approval_candidates: [1] })).to.equal("approval_candidates_hors_forme");
      expect(defautFormeCharger({ approval_candidates: ["x".repeat(257)] })).to.equal("approval_candidates_hors_forme");
      expect(defautFormeCharger(null)).to.equal("reponse_non_objet");
      const b = await demarrer({ decider: (r) => (r.tool_announced === "sap__lire" ? { decision: "autorise" } : { decision: "a_approuver", rule: "r" }) });
      try {
        const { coeur, service } = b;
        const chargerOrigine = service.charger.bind(service);
        const candidatsAvant = coeur.journal.trouver("approval_candidates").length; // charger du démarrage (liste d'outils vide)
        service.charger = async (r) => ({ policy_version: r.policy_version, policy_sha256: r.policy_sha256, state: "x".repeat(8) });
        const outils = [
          { tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", class: "ecriture", effects: null },
          { tool_announced: "sap__lire", tool_original: "lire", server_alias: "sap", class: "lecture", effects: null },
        ];
        coeur.definirOutils(outils);
        await new Promise((x) => setTimeout(x, 150));
        expect(coeur.susceptible("sap__payments.create")).to.equal(true);
        expect(coeur.susceptible("sap__lire"), "sans liste adoptée, tout outil reste susceptible").to.equal(true);
        const ind = coeur.journal.trouver("approval_service_unavailable").filter((l) => l.data.message === "charger");
        expect(ind.length).to.be.at.least(1);
        expect(String(ind[0].data.code)).to.match(/^hors_forme:approval_candidates_absent/);
        expect(coeur.journal.trouver("approval_candidates"), "aucune liste adoptée depuis la réponse hors forme").to.have.length(candidatsAvant);
        // Réponse bien formée : adoptée.
        service.charger = chargerOrigine;
        coeur.definirOutils(outils);
        await new Promise((x) => setTimeout(x, 150));
        expect(coeur.susceptible("sap__payments.create")).to.equal(true);
        expect(coeur.susceptible("sap__lire")).to.equal(false);
        expect(coeur.journal.trouver("approval_candidates")).to.have.length(candidatsAvant + 1);
      } finally {
        await b.arreter();
      }
    });

    it("le code d'erreur d'une réponse HTTP du service n'est repris que sous la forme de CT-3 §12.8 (snake_case ASCII, 64 caractères au plus) ; toute autre chaîne vaut hors_forme", async function () {
      let code = "ticket_inconnu";
      const serveur = http.createServer((req, res) => {
        req.resume();
        req.on("end", () => res.writeHead(400, { "content-type": "application/json" }).end(JSON.stringify({ error: { code, data: {} } })));
      });
      await new Promise((r) => serveur.listen(0, "127.0.0.1", r));
      try {
        const client = new ClientServiceApprobation({ url: `http://127.0.0.1:${serveur.address().port}/`, timeout_ms: 2000 });
        const erreur = async () => {
          try {
            await client.appeler("evaluer", {});
          } catch (e) {
            return e;
          }
          return null;
        };
        expect((await erreur()).code).to.equal("ticket_inconnu");
        code = "X".repeat(100) + " ; chaîne choisie par le service <script>";
        const e2 = await erreur();
        expect(e2).to.be.instanceOf(ErreurServiceApprobation);
        expect(e2.code).to.equal("hors_forme");
        code = "Ticket-Inconnu";
        expect((await erreur()).code).to.equal("hors_forme");
      } finally {
        serveur.close();
      }
    });
  });

  describe("lecture d'une série de points", function () {
    it("relireSerie laisse le fichier intact quand sa dernière ligne est illisible et rapporte le défaut (points.defaut) ; seule la reprise de l'écrivain (tronquer: true) coupe la ligne", async function () {
      const dir = repertoireTemporaire("noortrace-revue-points-");
      try {
        const f = path.join(dir, "periode-1794304800.ndjson");
        const l1 = JSON.stringify({ tree_size: 1, checkpoint_ts: "2026-11-10T10:15:00.000Z" }) + "\n";
        const l2 = JSON.stringify({ tree_size: 2, checkpoint_ts: "2026-11-10T10:16:00.000Z" }) + "\n";
        const abimee = '{"tree_size":3,"checkpoint_ts":"2026-11-10T11:00:00.000Z","sig":"0x12\u0000\u0000"\n';
        fs.writeFileSync(f, l1 + l2 + abimee);
        const avant = fs.statSync(f).size;
        const points = await relireSerie(f);
        expect(points).to.have.length(2);
        expect(fs.statSync(f).size, "une lecture ne modifie pas le stockage").to.equal(avant);
        expect(points.defaut).to.include({ fichier: "periode-1794304800.ndjson", ligne: 3 });
        expect(points.defaut.octets, "octets de la ligne illisible, fin de ligne comprise").to.equal(Buffer.byteLength(abimee));
        // Reprise de l'écrivain (EX-12.28) : la ligne tronquée est coupée.
        const repris = await relireSerie(f, { tronquer: true });
        expect(repris).to.have.length(2);
        expect(fs.statSync(f).size).to.equal(Buffer.byteLength(l1 + l2));
        expect(repris.defaut).to.equal(undefined);
        // Le seul appelant qui tronque est la reprise ; l'export d'un dossier relit sans écrire.
        const reprise = fs.readFileSync(new URL("../paquets/enregistreur/src/reprise.mjs", import.meta.url), "utf8");
        expect(reprise).to.match(/relireSerie\([\s\S]*?\{ tronquer: true \}\)/);
        const dossier = fs.readFileSync(new URL("../paquets/enregistreur/src/dossier.mjs", import.meta.url), "utf8");
        expect(dossier).to.not.match(/tronquer: true/);
        expect(dossier).to.match(/serie\.defaut/);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  });

  describe("CT-2 EX-3.6 : relecture d'un segment dans le fil du démon", function () {
    it("la relecture vérifiée de 4 000 événements rend la main à la boucle d'événements (un minuteur de 1 ms s'exécute pendant l'appel), par relireSegmentParTranches comme par verifierSegment, avec le même résultat que la relecture d'une traite", async function () {
      const { entete, pub, octets } = segmentSigne(4000);
      const sync = relireSegment(octets, { verifierSignatures: true, clePublique: () => pub, prevHashAttendu: entete.prev_hash, firstSeqAttendu: 1 });
      expect(sync.evenements).to.have.length(4000);
      expect(sync.corruption).to.equal(null);
      let tics = 0;
      const minuteur = setInterval(() => tics++, 1);
      const r = await relireSegmentParTranches(octets, { verifierSignatures: true, clePublique: () => pub, prevHashAttendu: entete.prev_hash, firstSeqAttendu: 1 });
      const pendant = tics;
      expect(r.evenements.length).to.equal(4000);
      expect(r.corruption).to.equal(null);
      expect(r.finValide).to.equal(sync.finValide);
      expect(r.evenements.at(-1).hash).to.equal(sync.evenements.at(-1).hash);
      expect(pendant, `exécutions du minuteur pendant la relecture : ${pendant}`).to.be.at.least(3);
      // Le contrôle quotidien (verifierSegment) passe par la même relecture.
      const cles = new ClesChaine(async () => pub);
      const t1 = tics;
      const v = await verifierSegment(octets, { nom: "seg-00000000000000000001-00000000000000000001.ndjson", prevHash: entete.prev_hash, firstSeq: 1, cles, id: { org_id: entete.org_id, journal_id: entete.journal_id } });
      clearInterval(minuteur);
      expect(v.incident).to.equal(null);
      expect(v.evenements).to.have.length(4000);
      expect(tics - t1, "verifierSegment rend la main").to.be.at.least(3);
      // Une corruption est vue de la même façon par les deux relectures.
      const abime = Buffer.from(octets);
      const k = abime.indexOf(Buffer.from('"claim_id"')) > 0 ? abime.indexOf(Buffer.from('"claim_id"')) : 4000;
      abime[k + 4] ^= 0x01;
      const s2 = relireSegment(new Uint8Array(abime), { verifierSignatures: true, clePublique: () => pub });
      const t2 = await relireSegmentParTranches(new Uint8Array(abime), { verifierSignatures: true, clePublique: () => pub });
      expect(t2.corruption?.raison ?? t2.tronque).to.deep.equal(s2.corruption?.raison ?? s2.tronque);
      expect(t2.evenements.length).to.equal(s2.evenements.length);
      expect(E.TRANCHE_RELECTURE).to.equal(256);
    });
  });
});
