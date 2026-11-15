// Revue de sécurité interne de l'étape 8 (enregistreur : frontal du
// modèle). Chaque `it` nomme l'exigence ou le défaut qu'il reproduit ; chaque essai échoue
// sur le code d'avant la correction et passe après. Sans fournisseur réel ni réseau : objets du module et prises
// locales.
//
//   CT-2 EX-5.6   mode miroir : perte de la prise du démon dite et rendue, arrêt non retenu, sens illisible jeté, bornes, couple qui lève
//   EX-5.11   corrélation d'un appel d'outil : attente de la réponse rédigée bornée ; scellement qui résout l'entrée en toute issue
//   EX-5.27   réassemblages Chat Completions et Gemini en temps linéaire, index bornés
//     ICAP : lecteur sans recopie, en-têtes encapsulés et morceaux bornés, délai d'inactivité
//   CT-2 EX-14.12   scellement d'un échange : place du quota rendue et entrée résolue en toute issue ; échec consigné
//   EX-5.33   décompression arrêtée à la borne de capture ; corps coupé vidé avant l'inscription

import { expect } from "chai";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { EventEmitter } from "node:events";
import * as E from "@noortrace/enregistreur";
import { repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";

const { ReassemblageChat, ReassemblageGemini, LecteurOctets, lireEncapsulated, RegistreCorrelation, MoteurEchanges, CaptureReponse, AdaptateurMiroir, RecepteurMiroir, lancerAdaptateur, ServeurIcap } = E;
// Fonctions nouvelles : absentes du code d'avant la correction (rejeu) ; les essais échouent alors par leur oracle.
const lireCorpsChunked = E.lireCorpsChunked ?? (async function* () { throw new Error("lireCorpsChunked non exporté"); });
const chrono = () => Number(process.hrtime.bigint() / 1000000n);
const LIMITES = { json_max_depth: 128, json_max_members: 100000, model_request_max_bytes: 33554432, model_response_max_bytes: 1048576, line_max_bytes: 16842752, piece_max_bytes: 16777216 };

/** Journal en mémoire des bancs. */
function journalMemoire() {
  const lignes = [];
  return { lignes, consigner: (niveau, composant, evenement, data = {}, ctx = {}) => lignes.push({ level: niveau, component: composant, event: evenement, data, ...ctx }), trouver: (ev) => lignes.filter((l) => l.event === ev), abonner: () => () => {} };
}

/** Prise factice pour LecteurOctets. */
class PriseFactice extends EventEmitter {
  pause() {}
  resume() {}
}

describe("enregistreur, revue (étape 8) : frontal du modèle", function () {
  this.timeout(60000);

  describe("CT-2 EX-5.27 : réassemblages Chat Completions et Gemini", function () {
    it("un événement Chat Completions de 90 000 choix d'index distincts est réassemblé en moins de 2,5 s (avant : une quinzaine de secondes), de même pour 50 000 candidats Gemini ; au-delà de 100 000 index les fragments sont ignorés et comptés", function () {
      const n = 90000;
      const choices = Array.from({ length: n }, (_, k) => ({ index: k, delta: { role: "assistant", content: "x" }, finish_reason: null }));
      const data = JSON.stringify({ id: "chatcmpl-1", object: "chat.completion.chunk", created: 1, model: "m", choices });
      const r = new ReassemblageChat(LIMITES);
      const t0 = chrono();
      r.donnee("message", data);
      const duree = chrono() - t0;
      expect(r.forme.choices).to.have.length(n);
      expect(r.forme.choices[n - 1].message.content).to.equal("x");
      expect(duree, `${duree} ms`).to.be.below(2500);
      // Second fragment des mêmes index : fusionné (pas de doublon), en temps linéaire.
      r.donnee("message", JSON.stringify({ id: "chatcmpl-1", choices: choices.slice(0, 1000).map((c) => ({ index: c.index, delta: { content: "y" } })) }));
      expect(r.forme.choices).to.have.length(n);
      expect(r.forme.choices[0].message.content).to.equal("xy");
      // Borne des index : 100 000 gardés, le reste ignoré et compté.
      const suite = Array.from({ length: 60000 }, (_, k) => ({ index: n + k, delta: { content: "z" } }));
      const ignoresAvant = r.ignores;
      r.donnee("message", JSON.stringify({ id: "chatcmpl-1", choices: suite }));
      expect(r.forme.choices).to.have.length(100000);
      expect(r.ignores - ignoresAvant).to.equal(50000);
      // Appels d'outils d'un choix : même table.
      const r2 = new ReassemblageChat(LIMITES);
      const appels = Array.from({ length: 50000 }, (_, k) => ({ index: k, id: `c${k}`, type: "function", function: { name: "f", arguments: "{" } }));
      const t1 = chrono();
      r2.donnee("message", JSON.stringify({ id: "a", choices: [{ index: 0, delta: { tool_calls: appels } }] }));
      r2.donnee("message", JSON.stringify({ id: "a", choices: [{ index: 0, delta: { tool_calls: appels.map((a) => ({ index: a.index, function: { arguments: "}" } })) } }] }));
      expect(chrono() - t1).to.be.below(2500);
      expect(r2.forme.choices[0].message.tool_calls).to.have.length(50000);
      expect(r2.forme.choices[0].message.tool_calls[49999].function.arguments).to.equal("{}");
      // Gemini.
      const g = new ReassemblageGemini(LIMITES);
      const candidats = Array.from({ length: 50000 }, (_, k) => ({ index: k, content: { parts: [{ text: "x" }] } }));
      const t2 = chrono();
      g.objet({ candidates: candidats });
      g.objet({ candidates: candidats.slice(0, 100).map((c) => ({ index: c.index, content: { parts: [{ text: "y" }] } })) });
      expect(chrono() - t2).to.be.below(2500);
      expect(g.candidats).to.have.length(50000);
      g.objet({ candidates: Array.from({ length: 60000 }, (_, k) => ({ index: 50000 + k, content: { parts: [] } })) });
      expect(g.candidats).to.have.length(100000);
      expect(g.ignores).to.be.at.least(10000);
      expect(E.INDEX_REASSEMBLAGE_MAX).to.equal(100000);
    });
  });

  describe("lecture des messages ICAP", function () {
    it("LecteurOctets lit 16 Mio en paquets de 16 Kio sans recopie du tampon (moins de 1,5 s ; avant 4 s) ; Encapsulated au-delà de 256 Kio d'en-têtes et un morceau chunked au-delà de 16 Mio sont refusés (400) avant d'être lus", async function () {
      const prise = new PriseFactice();
      const lecteur = new LecteurOctets(prise);
      const total = 16 * 1048576;
      const morceau = Buffer.alloc(16384, 0x61);
      const attente = lecteur.octets(total);
      const t0 = chrono();
      for (let k = 0; k < total / 16384; k++) prise.emit("data", morceau);
      const lu = await attente;
      const duree = chrono() - t0;
      expect(lu.length).to.equal(total);
      expect(duree, `${duree} ms`).to.be.below(1500);
      // En-têtes encapsulés bornés.
      expect(lireEncapsulated("req-hdr=0, req-body=1024")).to.deep.equal([{ nom: "req-hdr", decalage: 0 }, { nom: "req-body", decalage: 1024 }]);
      let e = null;
      try {
        lireEncapsulated("req-hdr=0, req-body=999999999");
      } catch (x) {
        e = x;
      }
      expect(e?.statut).to.equal(400);
      expect(e?.raison).to.equal("encapsulated_trop_grand");
      // Morceau chunked borné : refusé sur sa ligne de taille, sans lire 4 Gio.
      const p2 = new PriseFactice();
      const l2 = new LecteurOctets(p2);
      const it = lireCorpsChunked(l2);
      const suite = it.next();
      p2.emit("data", Buffer.from("ffffffff\r\n"));
      let e2 = null;
      try {
        await suite;
      } catch (x) {
        e2 = x;
      }
      expect(e2?.statut).to.equal(400);
      expect(e2?.raison).to.equal("chunk_trop_grand");
      // Un morceau ordinaire se lit.
      const p3 = new PriseFactice();
      const l3 = new LecteurOctets(p3);
      const it3 = lireCorpsChunked(l3);
      const s3 = it3.next();
      p3.emit("data", Buffer.from("5\r\nhello\r\n0\r\n\r\n"));
      expect((await s3).value.donnees.toString()).to.equal("hello");
      expect((await it3.next()).value.fin).to.equal(true);
      expect(E.ICAP_ENTETES_MAX_OCTETS).to.equal(262144);
      expect(E.ICAP_CHUNK_MAX_OCTETS).to.equal(16777216);
      expect(E.ICAP_CONNEXIONS_MAX).to.equal(1000);
    });

    it("une connexion ICAP admise qui n'envoie rien est détruite au délai d'inactivité (model.idle_timeout_ms), consignée icap_request_refused inactivite", async function () {
      const journal = journalMemoire();
      const moteur = { config: { limits: LIMITES, model: { icap: { listen: "127.0.0.1:0", tls_listen: null, allowed_sources: [], client_ca: null }, idle_timeout_ms: 300, first_byte_timeout_ms: 1000 }, mcp: { drain_timeout_ms: 500 } }, journal, registre: {}, monotone: chrono, murale: Date.now };
      const s = new ServeurIcap({ coeur: {}, moteur });
      await s.ecouter();
      try {
        const [adr] = s.adresses();
        const c = net.createConnection(adr.port, "127.0.0.1");
        c.on("error", () => {});
        c.resume();
        const t0 = Date.now();
        await new Promise((r) => c.once("close", r));
        expect(Date.now() - t0).to.be.within(200, 2000);
        expect(journal.trouver("icap_request_refused").map((l) => l.data.reason)).to.include("inactivite");
      } finally {
        await s.arreter();
      }
    });
  });

  describe("CT-2 EX-5.6 : mode miroir", function () {
    it("la prise du démon fermée est une perte dite et rendue par lancerAdaptateur (perte, perdue()) ; la copie n'est plus acceptée ; RecepteurMiroir.arreter() avec un adaptateur connecté rend en moins d'une seconde", async function () {
      const dir = repertoireTemporaire("noortrace-revue-miroir-");
      try {
        const socket = path.join(dir, "d.sock");
        const connexions = [];
        const demon = net.createServer((c) => connexions.push(c));
        await new Promise((r) => demon.listen(socket, r));
        const sortie = [];
        const x = await lancerAdaptateur({ socket, ecoute: "127.0.0.1:0", sortie: { write: (t) => sortie.push(t) } });
        expect(x.perte, "promesse de perte rendue").to.be.a("promise");
        expect(x.perdue()).to.equal(false);
        const port = x.serveur.address().port;
        // Le démon ferme la prise (redémarrage) : perte dite, copie refusée.
        await new Promise((r) => setTimeout(r, 30));
        for (const c of connexions) c.destroy();
        const perte = await Promise.race([x.perte, new Promise((r) => setTimeout(() => r("silence"), 2000))]);
        expect(perte).to.deep.equal({ raison: "prise_demon_fermee" });
        expect(x.perdue()).to.equal(true);
        expect(sortie.some((t) => /prise du demon fermee/.test(t))).to.equal(true);
        await new Promise((r) => setTimeout(r, 50));
        const refus = await new Promise((res) => {
          const c = net.createConnection(port, "127.0.0.1");
          c.once("error", (e) => res(e.code));
          c.once("connect", () => res("connecte"));
        });
        expect(refus).to.equal("ECONNREFUSED");
        await new Promise((r) => demon.close(() => r()));
        // Récepteur du démon : arrêt non retenu par un adaptateur connecté.
        const journal = journalMemoire();
        const sock2 = path.join(dir, "p", "miroir.sock");
        fs.mkdirSync(path.dirname(sock2), { recursive: true });
        const moteur = { config: { limits: LIMITES, model: { mirror: { socket: sock2 } } }, journal, registre: {}, monotone: chrono, murale: Date.now, preparer: async () => { throw new Error("preparer en panne"); } };
        const r = new RecepteurMiroir({ coeur: {}, moteur });
        await r.ecouter();
        const adaptateur = net.createConnection(sock2);
        adaptateur.on("error", () => {});
        await new Promise((res) => adaptateur.once("connect", res));
        const t0 = Date.now();
        const issue = await Promise.race([r.arreter().then(() => "arrete"), new Promise((res) => setTimeout(() => res("retenu"), 3000))]);
        expect(issue).to.equal("arrete");
        expect(Date.now() - t0).to.be.below(1000);
        adaptateur.destroy();
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it("un couple dont le traitement lève reçoit une réponse ok:false (exchange_lost consigné) et les couples suivants de la connexion sont traités ; un sens illisible (HTTP/2) jette ses octets en temps linéaire ; connexions suivies et longueur de trame bornées", async function () {
      const dir = repertoireTemporaire("noortrace-revue-miroir-");
      try {
        // (d) couple qui lève.
        const journal = journalMemoire();
        const sock = path.join(dir, "m.sock");
        // `model.hosts` non itérable : la résolution de l'hôte lève dans `_couple` (exception du traitement d'un couple).
        const moteur = { config: { limits: LIMITES, model: { mirror: { socket: sock }, hosts: { pas: "un tableau" }, routes: [] } }, journal, registre: {}, monotone: chrono, murale: Date.now, preparer: async () => { throw new Error("preparer en panne"); } };
        const r = new RecepteurMiroir({ coeur: {}, moteur });
        await r.ecouter();
        const reponses = [];
        const c = net.createConnection(sock);
        c.on("error", () => {});
        let tampon = "";
        c.on("data", (d) => {
          tampon += d;
          let k;
          while ((k = tampon.indexOf("\n")) >= 0) {
            reponses.push(JSON.parse(tampon.slice(0, k)));
            tampon = tampon.slice(k + 1);
          }
        });
        await new Promise((res) => c.once("connect", res));
        const couple = { version: 0, source: "127.0.0.1", t_requete: "2026-11-10T10:00:00.000Z", t_reponse: "2026-11-10T10:00:01.000Z", request: { method: "POST", target: "/v1/messages", headers: [["content-type", "application/json"]], body: Buffer.from("{}").toString("base64") }, response: { status: 200, headers: [], body: Buffer.from("{}").toString("base64"), body_length: 2, complete: true } };
        c.write(`${JSON.stringify(couple)}\n${JSON.stringify(couple)}\n`);
        await new Promise((res) => setTimeout(res, 300));
        expect(reponses, "deux réponses, aucune connexion figée").to.have.length(2);
        expect(reponses.every((x) => x.ok === false && x.reason === "erreur_interne"), JSON.stringify(reponses)).to.equal(true);
        expect(journal.trouver("exchange_lost")).to.have.length(2);
        c.destroy();
        await r.arreter();
        // (c) sens illisible : octets jetés, temps linéaire, mémoire vide.
        const a = new AdaptateurMiroir({ remettre: () => {} });
        a.octets("c1", "client", Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), "127.0.0.1");
        const morceau = Buffer.alloc(65536, 0x20);
        const t0 = chrono();
        for (let k = 0; k < 128; k++) a.octets("c1", "client", morceau, "127.0.0.1"); // 8 Mio
        const duree = chrono() - t0;
        expect(duree, `${duree} ms`).to.be.below(500);
        const sens = a.connexions.get("c1").client;
        expect(sens.etat).to.equal("illisible");
        expect(sens.tampon.length, "rien n'est gardé").to.equal(0);
        // Connexions suivies bornées : la plus ancienne est close.
        for (let k = 0; k < E.MIROIR_CONNEXIONS_MAX + 5; k++) a.octets(`x${k}`, "client", Buffer.from("GET / HTTP/1.1\r\nHost: h\r\n\r\n"), "127.0.0.1");
        expect(a.connexions.size).to.be.at.most(E.MIROIR_CONNEXIONS_MAX);
        expect(a.connexions.has("x0")).to.equal(false);
        // Trame qui annonce 17 Mio : connexion de copie détruite sans accumulation.
        const socket = path.join(dir, "d2.sock");
        const demon = net.createServer(() => {});
        await new Promise((res) => demon.listen(socket, res));
        const x = await lancerAdaptateur({ socket, ecoute: "127.0.0.1:0" });
        try {
          const copie = net.createConnection(x.serveur.address().port, "127.0.0.1");
          copie.on("error", () => {});
          copie.resume();
          await new Promise((res) => copie.once("connect", res));
          copie.write(JSON.stringify({ connexion: "c", sens: "client", longueur: 17000000, source: "127.0.0.1" }) + "\n");
          const ferme = await Promise.race([new Promise((res) => copie.once("close", () => res("fermee"))), new Promise((res) => setTimeout(() => res("ouverte"), 1500))]);
          expect(ferme).to.equal("fermee");
      expect(E.MIROIR_TRAME_MAX_OCTETS).to.equal(16777216);
      expect(E.MIROIR_CONNEXIONS_MAX).to.equal(10000);
        } finally {
          await x.arreter();
          await new Promise((res) => demon.close(() => res()));
        }
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  });

  describe("CT-2 EX-5.11, CT-2 EX-14.12 : corrélation et scellement d'un échange", function () {
    const hote = { id: "hote-m", host_group: "g", quota: { max_concurrent: 4, piece_bytes_per_minute: 268435456, received_bytes_per_minute: 268435456, redaction_ms_per_minute: 30000 } };
    const forme = { id: "msg_1", type: "message", role: "assistant", model: "m", content: [{ type: "text", text: "Je paie." }, { type: "tool_use", id: "tu_1", name: "payer", input: { montant: 1 } }], stop_reason: "tool_use" };

    it("CT-2 EX-5.11 : correler n'attend la réponse rédigée d'un échange inscrit qu'au plus attenteMaxMs (5 s par défaut) : au-delà, corrélation sans intention, consignée correlation_sans_intention ; une réponse rédigée disponible donne l'intention", async function () {
      const journal = journalMemoire();
      let t = 1000;
      const registre = new RegistreCorrelation({ fenetreMs: 600000, monotone: () => t, ecrirePiece: async () => ({}), journal, attenteMaxMs: 250 });
      const e = registre.inscrire({ host: hote, host_group: "g", run_id: null, format: "anthropic-messages", formeClair: forme, interpose: true });
      t = 1500;
      const t0 = Date.now();
      const r = await registre.correler({ host: hote, host_group: "g", run_id: null, tool_announced: "payer", arguments: { montant: 1 }, t_recu: t });
      expect(Date.now() - t0).to.be.within(200, 2000);
      expect(r).to.be.an("object");
      expect(r.intent).to.equal(null);
      expect(r.seq).to.equal("inscription:1");
      expect(journal.trouver("correlation_sans_intention")).to.have.length(1);
      // Réponse rédigée connue : l'intention est rendue sans attente.
      const e2 = registre.inscrire({ host: hote, host_group: "g", run_id: null, format: "anthropic-messages", formeClair: forme, interpose: true, t_complet: 1600 });
      registre.completer(e2, { formeRedigee: forme, code: { model: "m", prompt_version: null } });
      const r2 = await registre.correler({ host: hote, host_group: "g", run_id: null, tool_announced: "payer", arguments: { montant: 1 }, t_recu: 1700 });
      expect(r2.intent).to.not.equal(null);
      expect(r2.code.model).to.equal("m");
      expect(E.CORRELATION_ATTENTE_MAX_MS).to.equal(5000);
      void e;
    });

    it("CT-2 EX-14.12 : un scellement qui lève avant la réponse rédigée rend la place de max_concurrent, résout l'entrée du registre (l'appel corrélé n'attend plus) et consigne exchange_lost", async function () {
      const journal = journalMemoire();
      const coeur = { horlogeBrute: { monotone: chrono, murale: Date.now }, journal, metriques: { compter() {}, observer() {} }, config: { limits: LIMITES, policy: { approval: { mode: "erreur" } }, model: { correlation_window_ms: 600000 } }, ecrirePiece: async () => ({}), scellerEchange: async () => ({ seq: 1 }), versionPolitique: "v", nomRedaction: null, o: {} };
      const registre = new RegistreCorrelation({ fenetreMs: 600000, monotone: chrono, ecrirePiece: async () => ({}), journal });
      const redacteur = { redigerPiece: async () => { throw new Error("redacteur en panne"); } };
      const moteur = new MoteurEchanges({ coeur, redacteur, registre });
      const entree = registre.inscrire({ host: hote, host_group: "g", run_id: null, format: "anthropic-messages", formeClair: forme, interpose: true });
      const route = { format: "anthropic-messages", path: "/v1/messages", provider_label: "p" };
      const etat = { route, hote, delegation: { run_id: null }, pr: { attendue: false, prompt: null, requete: { reference: {} }, requeteRedigee: {}, nonRedigeable: null }, pieces: [], enMemoire: false, mode: "passerelle", t_recu: 0, t_envoi: 0, label: "p", statut: 200, contentType: "application/json", corps: new Uint8Array(0), flux: false, entree };
      moteur.quotas(hote).enCours = 1;
      let erreur = null;
      try {
        await moteur.sceller(etat, { genre: "reponse" });
      } catch (e) {
        erreur = e;
      }
      expect(erreur?.message).to.equal("redacteur en panne");
      expect(moteur.quotas(hote).enCours, "place rendue").to.equal(0);
      const resolue = await Promise.race([entree.redigee.then(() => "resolue"), new Promise((r) => setTimeout(() => r("en attente"), 500))]);
      expect(resolue).to.equal("resolue");
      expect(journal.trouver("exchange_lost")).to.have.length(1);
      expect(journal.trouver("exchange_lost")[0].data).to.include({ mode: "passerelle", reason: "redacteur en panne" });
    });
  });

  describe("CT-2 EX-5.33 : décompression d'une réponse", function () {
    it("au-delà de la borne de capture, le décompresseur est arrêté (le volume décomprimé n'est plus payé) ; un corps comprimé marqué coupé est vidé avant l'inscription (corps capturé non vide)", async function () {
      const journal = journalMemoire();
      const hote = { id: "hote-m", host_group: "g", quota: {} };
      const route = { format: "anthropic-messages", path: "/v1/messages", provider_label: "p" };
      const moteur = { config: { limits: LIMITES }, bornes: { profondeurMax: 128, membresMax: 100000 }, journal, monotone: chrono, murale: Date.now, registre: { inscrire: () => ({ redigee: Promise.resolve() }) } };
      // 64 Mio de zéros : un gzip de quelques dizaines de Kio.
      const comprime = zlib.gzipSync(Buffer.alloc(64 * 1048576, 0));
      const etat = { route, hote, delegation: { run_id: null }, pr: { requete: { reference: {} }, requeteRedigee: {} } };
      const c = new CaptureReponse(moteur, etat, { statut: 200, entetes: { "content-type": "application/json", "content-encoding": "gzip" } });
      const t0 = chrono();
      for (let i = 0; i < comprime.length; i += 4096) c.ecrire(new Uint8Array(comprime.subarray(i, i + 4096)));
      await new Promise((r) => setTimeout(r, 200));
      await c.terminer({ coupe: false });
      const duree = chrono() - t0;
      expect(c.tronque).to.equal(true);
      expect(c.decompArretee, "décompresseur arrêté à la borne").to.equal(true);
      expect(c.decomp.destroyed).to.equal(true);
      expect(c.recues, `octets comptés : ${c.recues}`).to.be.below(4 * 1048576);
      expect(duree, `${duree} ms`).to.be.below(1500);
      expect(etat.corps.length).to.equal(LIMITES.model_response_max_bytes);
      // Corps coupé : le décompresseur est vidé avant l'inscription.
      const etat2 = { route, hote, delegation: { run_id: null }, pr: { requete: { reference: {} }, requeteRedigee: {} } };
      const c2 = new CaptureReponse(moteur, etat2, { statut: 200, entetes: { "content-type": "application/json", "content-encoding": "gzip" } });
      c2.ecrire(new Uint8Array(zlib.gzipSync(Buffer.from('{"content":[{"type":"text","text":"bonjour"}]}'))));
      await c2.terminer({ coupe: true });
      expect(Buffer.from(etat2.corps).toString("utf8")).to.include("bonjour");
      expect(etat2.tronque).to.equal(null);
    });
  });
});
