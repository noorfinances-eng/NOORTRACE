// Exigences du frontal modèle (CT-2 §5, EX-8.5 à EX-8.7, §13.5, EX-14.12,
// lignes « frontal modèle » de §14 et §17), chacune en réussite et en échec,
// sur la passerelle réelle (HTTP, 127.0.0.1) et un fournisseur simulé. Les
// modes ICAP et miroir (EX-5.3 à EX-5.6, EX-14.12) ne sont pas servis par ce
// lot : le démon refuse de démarrer dans ces modes (vérifié ici).

import { expect } from "chai";
import fs from "node:fs";
import net from "node:net";
import http from "node:http";
import zlib from "node:zlib";
import * as N from "@noortrace/noyau";
import {
  PasserelleModele, RegistreCorrelation, demarrerFrontalModele, controleModele, lireEvenements, piecesRequete, Redacteur, ErreurEnregistreur,
  normaliserCible, examinerRequeteGemini, nomVuParLeModele, CLE_INCOMPLET,
} from "@noortrace/enregistreur";
import { repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { configurationModele, valider, demarrerCoeur, JETON_MODELE, politiquePii } from "./fixtures/enregistreur-modele/outils.mjs";
import { FournisseurSimule, evenementsFlux, reponseEntiere } from "./fixtures/enregistreur-modele/fournisseur.mjs";

const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const MSG = { model: "modele-messages-simule", max_tokens: 64, system: "Tu es un agent de test.", messages: [{ role: "user", content: "Statut ?" }] };
const CHAT = { model: "modele-chat-simule", messages: [{ role: "system", content: "Agent de test." }, { role: "user", content: "Statut ?" }] };
const RESP = { model: "modele-responses-simule", instructions: "Agent de test.", input: "Statut ?" };
const GEM = { contents: [{ role: "user", parts: [{ text: "Statut ?" }] }] };
const BASE = { "content-type": "application/json", "x-noortrace-token": JETON_MODELE };

describe("enregistreur, frontal modèle : exigences (§5, EX-8.5 à EX-8.7, §13.5, §14, §17)", function () {
  this.timeout(60000);
  let dir;
  let fournisseur;
  let coeur;
  let config;
  let secrets;
  let principale;
  const ouvertes = [];
  let obs = { echanges: [], refus: [] };

  async function ouvrir(sur = () => {}) {
    const c = structuredClone(config);
    sur(c);
    const p = new PasserelleModele({ coeur, secrets, config: c, observateur: { echange: (x) => obs.echanges.push(x), refus: (x) => obs.refus.push(x) } });
    await p.ecouter();
    ouvertes.push(p);
    return p;
  }

  async function envoyer(p, cible, o = {}) {
    obs = { echanges: [], refus: [] };
    const corps = o.brut ?? (o.corps === undefined ? undefined : JSON.stringify(o.corps));
    const r = await fetch(`http://127.0.0.1:${p.adresse().port}${cible}`, { method: o.methode ?? "POST", headers: o.entetes ?? BASE, body: corps });
    const octets = Buffer.from(await r.arrayBuffer());
    for (let i = 0; i < 300 && !obs.echanges.length && !obs.refus.length; i++) await pause(10);
    return { statut: r.status, entetes: r.headers, octets, texte: octets.toString("utf8"), echange: obs.echanges[0] ?? null, refus: obs.refus[0] ?? null };
  }

  async function attendre() {
    for (let i = 0; i < 300 && !obs.echanges.length && !obs.refus.length; i++) await pause(10);
  }

  /** Requête HTTP brute (chemin non normalisé, corps non décomprimé), échange attendu. */
  async function brut(p, chemin, o = {}) {
    obs = { echanges: [], refus: [] };
    const r = await new Promise((res, rej) => {
      const q = http.request({ host: "127.0.0.1", port: p.adresse().port, path: chemin, method: o.methode ?? "POST", headers: o.entetes ?? BASE }, (rep) => {
        const m = [];
        rep.on("data", (c) => m.push(c));
        rep.on("end", () => res({ statut: rep.statusCode, entetes: rep.headers, octets: Buffer.concat(m) }));
        rep.on("error", () => res({ statut: rep.statusCode, entetes: rep.headers, octets: Buffer.concat(m), coupe: true }));
      });
      q.on("error", rej);
      q.end(o.corps);
    });
    await attendre();
    return { ...r, texte: r.octets.toString("utf8"), echange: obs.echanges[0] ?? null };
  }

  const ops = () => fs.readFileSync(config.supervision.ops_log.path, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const derniere = (evenement) => ops().filter((l) => l.event === evenement).pop();
  const nbEvenements = async () => (await lireEvenements(coeur.repertoire)).length;
  const piece = async (ref) => Buffer.from(await coeur.pieces.lire(ref.sha256)).toString("utf8");

  before(async function () {
    dir = repertoireTemporaire("noortrace-modele-exigences-");
    fournisseur = await new FournisseurSimule({ pauseMs: 2 }).demarrer();
    const c = configurationModele(dir, fournisseur.url);
    ({ config, secrets } = valider(c.config, c.env));
    ({ coeur } = await demarrerCoeur(config, secrets));
    principale = await ouvrir();
  });

  after(async function () {
    for (const p of ouvertes) await p.arreter();
    await coeur?.arreter();
    await fournisseur?.arreter();
  });

  afterEach(function () {
    fournisseur.scenarios.length = 0;
    fournisseur.surRequete = null;
  });

  describe("EX-5.1 : modes du frontal modèle", function () {
    it("passerelle, icap, miroir : le frontal du mode écoute et offre le registre de corrélation ; désactivé : rien", async function () {
      const m = await demarrerFrontalModele(coeur, secrets);
      expect(m.passerelle.adresse().port).to.be.greaterThan(0);
      expect(m.correlateur).to.be.instanceOf(RegistreCorrelation);
      expect([m.icap, m.miroir]).to.deep.equal([null, null]);
      await m.arreter();
      // Même cœur, autre mode : seule la configuration change.
      const autre = (model) => Object.assign(Object.create(coeur), { config: { ...config, model: { ...config.model, ...model } } });
      expect(await demarrerFrontalModele(autre({ mode: "desactive" }), secrets)).to.include({ correlateur: null, passerelle: null, icap: null, miroir: null });
      const i = await demarrerFrontalModele(autre({ mode: "icap", listen: null, icap: { listen: "127.0.0.1:0", tls_listen: null, client_ca: null, allowed_sources: ["127.0.0.1/32"], client_address_header: null } }), secrets);
      expect(i.icap.adresses()[0].port).to.be.greaterThan(0);
      expect([i.passerelle, i.miroir]).to.deep.equal([null, null]);
      expect(i.correlateur).to.be.instanceOf(RegistreCorrelation);
      await i.arreter();
      const prise = `${dir}/prise-ex51/miroir.sock`;
      const r = await demarrerFrontalModele(autre({ mode: "miroir", listen: null, mirror: { socket: prise } }), secrets);
      expect(fs.lstatSync(prise).isSocket()).to.equal(true);
      expect([r.passerelle, r.icap]).to.deep.equal([null, null]);
      expect(r.correlateur).to.be.instanceOf(RegistreCorrelation);
      await r.arreter();
    });

    it("validation (EX-15.4 pas 3) : listen exigé en passerelle, icap et mirror selon le mode, au moins une connexion d'hôte (EX-7.3)", function () {
      expect(controleModele(config).erreurs).to.deep.equal([]);
      const c = structuredClone(config);
      c.model.listen = null;
      c.model.hosts = [];
      expect(controleModele(c).erreurs.map((e) => e.pointeur)).to.deep.equal(["/model/listen", "/model/hosts"]);
      c.model.mode = "icap";
      c.model.icap = null;
      expect(controleModele(c).erreurs.map((e) => e.pointeur)).to.include("/model/icap");
      c.model.mode = "miroir";
      expect(controleModele(c).erreurs.map((e) => e.pointeur)).to.include("/model/mirror");
    });
  });

  describe("EX-5.2 : routes exactes, normalisation, passthrough", function () {
    it("couples passthrough relayés sans événement avec l'amont et les identifiants de la route ; tout autre couple : 404", async function () {
      const n = await nbEvenements();
      const a = await envoyer(principale, "/v1/messages/count_tokens", { corps: MSG });
      expect(a.statut).to.equal(200);
      expect(JSON.parse(a.texte)).to.deep.equal({ input_tokens: 42 });
      expect(fournisseur.requetes.at(-1).entetes["x-api-key"]).to.equal("cle-fournisseur-fictive-de-test");
      const b = await envoyer(principale, "/v1/models", { methode: "GET", entetes: { "x-noortrace-token": JETON_MODELE } });
      expect(b.statut).to.equal(200);
      expect(derniere("model_passthrough").data).to.include({ route: "/v1/messages", method: "GET", status: 200 });
      expect(await nbEvenements()).to.equal(n);
      const avant = fournisseur.requetes.length;
      for (const [m, c] of [["GET", "/v1/messages"], ["POST", "/v1/messages/x"], ["POST", "/v1/embeddings"], ["POST", "/v1/message"]]) {
        const r = await envoyer(principale, c, { methode: m, corps: m === "POST" ? MSG : undefined });
        expect(r.statut, `${m} ${c}`).to.equal(404);
      }
      expect(fournisseur.requetes.length).to.equal(avant);
      expect(derniere("model_route_not_found").data).to.deep.equal({ method: "POST", path_length: 11 });
    });

    it("chemin normalisé : non réservés décodés, chemin de la route envoyé à l'amont ; %2F, ., .., // et octets non imprimables : 400", async function () {
      const r = await envoyer(principale, "/v1/%6Dessages?beta=true", { corps: MSG });
      expect(r.statut).to.equal(200);
      expect(fournisseur.requetes.at(-1).cible).to.equal("/v1/messages?beta=true");
      expect(derniere("model_exchange_relayed").data.query_sha256).to.equal(N.sha256Hex(N.utf8("beta=true")));
      const avant = fournisseur.requetes.length;
      for (const c of ["/v1%2Fmessages", "/v1/./messages", "/v1/../v1/messages", "//v1/messages", "/v1/%2E%2E/v1/messages", "/v1/messages/."]) {
        expect((await brut(principale, c, { corps: JSON.stringify(MSG) })).statut, c).to.equal(400);
      }
      expect(normaliserCible("/v1/méssages").ok).to.equal(false);
      expect(normaliserCible("/v1/%7Ex").chemin).to.equal("/v1/~x");
      expect(normaliserCible("/v1beta/models/a%3AgenerateContent").chemin).to.equal("/v1beta/models/a%3AgenerateContent");
      expect(fournisseur.requetes.length).to.equal(avant);
    });
  });

  describe("EX-5.7 : requête comprimée, non analysable, forme inattendue", function () {
    it("Content-Encoding autre qu'identity : 415, rien n'est relayé, aucun événement", async function () {
      const n = await nbEvenements();
      const avant = fournisseur.requetes.length;
      const r = await envoyer(principale, "/v1/messages", { brut: zlib.gzipSync(JSON.stringify(MSG)), entetes: { ...BASE, "content-encoding": "gzip" } });
      expect(r.statut).to.equal(415);
      const g = await envoyer(principale, "/v1beta/models/gemini-x:generateContent", { brut: JSON.stringify(GEM), entetes: { ...BASE, "content-encoding": "br" } });
      expect(g.texte).to.equal('{"error":{"code":415,"message":"noortrace: requete comprimee refusee","status":"INVALID_ARGUMENT"}}');
      const id = await envoyer(principale, "/v1/messages", { brut: JSON.stringify(MSG), entetes: { ...BASE, "content-encoding": "identity" } });
      expect(id.statut).to.equal(200);
      expect(fournisseur.requetes.length).to.equal(avant + 1);
      expect(await nbEvenements()).to.equal(n + 1);
    });

    it("JSON non strict : 400 au format du fournisseur, consigné sans le corps", async function () {
      const n = await nbEvenements();
      const avant = fournisseur.requetes.length;
      const cas = ['{"model":"a","model":"b","messages":[]}', '﻿{"messages":[]}', '{"messages":["\\ud800"]}', '{"messages":[1e400]}', `{"messages":${"[".repeat(200)}${"]".repeat(200)}}`, "pas du json"];
      for (const brut of cas) {
        const r = await envoyer(principale, "/v1/messages", { brut });
        expect(r.statut).to.equal(400);
        expect(JSON.parse(r.texte)).to.deep.equal({ type: "error", error: { type: "invalid_request_error", message: "noortrace: corps de requete non analysable" } });
      }
      const chat = await envoyer(principale, "/v1/chat/completions", { brut: cas[0] });
      expect(chat.texte).to.equal('{"error":{"message":"noortrace: corps de requete non analysable","type":"invalid_request_error","param":null,"code":"noortrace_requete_invalide"}}');
      const resp = await envoyer(principale, "/v1/responses", { brut: "[" });
      expect(JSON.parse(resp.texte).error.code).to.equal("noortrace_requete_invalide");
      expect(fournisseur.requetes.length).to.equal(avant);
      expect(await nbEvenements()).to.equal(n);
      const l = derniere("model_request_refused");
      expect(l.data).to.deep.equal({ route: "/v1/responses", raison: "corps_non_analysable", length: 1, content_type: "application/json" });
      // Analyse réussie : relayée.
      expect((await envoyer(principale, "/v1/messages", { corps: MSG })).statut).to.equal(200);
    });

    it("forme inattendue : relayée telle quelle, sans pièce « prompt système » ; code.model jamais tiré de la requête", async function () {
      fournisseur.prochaine({ statut: 400, entetes: { "content-type": "application/json" }, morceaux: ['{"error":{"message":"messages manquant"}}'] });
      const r = await envoyer(principale, "/v1/chat/completions", { corps: { model: "modele-de-la-requete", prompt: "x" } });
      expect(r.statut).to.equal(400);
      const e = r.echange.evenement;
      expect(e.code).to.include({ model: null, prompt_version: null });
      expect(r.echange.pieces.prompt).to.equal(null);
      expect(JSON.parse(await piece(e.execution.arguments))).to.deep.equal({ model: "modele-de-la-requete", prompt: "x" });
      // Forme attendue : le modèle de la requête sert de repli (5.5, « Si absent »).
      fournisseur.prochaine({ statut: 500, entetes: { "content-type": "application/json" }, morceaux: ['{"error":{"message":"panne"}}'] });
      const r2 = await envoyer(principale, "/v1/chat/completions", { corps: CHAT });
      expect(r2.echange.evenement.code.model).to.equal("openai/modele-chat-simule");
    });
  });

  describe("EX-5.8 : connexion d'hôte et identifiants du fournisseur", function () {
    it("credentials propre : jeton par X-Noortrace-Token ou par l'en-tête de la route, clé de l'hôte retirée, secret de la route posé", async function () {
      await envoyer(principale, "/v1/messages", { corps: MSG, entetes: { ...BASE, "x-api-key": "cle-de-l-hote" } });
      expect(fournisseur.requetes.at(-1).entetes["x-api-key"]).to.equal("cle-fournisseur-fictive-de-test");
      const r = await envoyer(principale, "/v1/messages", { corps: MSG, entetes: { "content-type": "application/json", "x-api-key": JETON_MODELE } });
      expect(r.statut).to.equal(200);
      expect(fournisseur.requetes.at(-1).entetes["x-api-key"]).to.equal("cle-fournisseur-fictive-de-test");
      const b = await envoyer(principale, "/v1/responses", { corps: RESP, entetes: { "content-type": "application/json", authorization: `Bearer ${JETON_MODELE}` } });
      expect(b.statut).to.equal(200);
      expect(fournisseur.requetes.at(-1).entetes.authorization).to.equal("Bearer cle-fournisseur-fictive-de-test");
      expect(JSON.stringify(fournisseur.requetes.map((x) => x.entetes))).to.not.include(JETON_MODELE);
    });

    it("credentials relayer : seul l'en-tête de la route traverse ; le jeton doit être dans X-Noortrace-Token", async function () {
      const r = await envoyer(principale, "/v1/chat/completions", { corps: CHAT, entetes: { ...BASE, authorization: "Bearer cle-de-l-hote-fictive", "x-api-key": "autre" } });
      expect(r.statut).to.equal(200);
      const recus = fournisseur.requetes.at(-1).entetes;
      expect(recus.authorization).to.equal("Bearer cle-de-l-hote-fictive");
      expect(recus).to.not.have.property("x-api-key");
      expect(recus).to.not.have.property("x-noortrace-token");
      const sans = await envoyer(principale, "/v1/chat/completions", { corps: CHAT, entetes: { "content-type": "application/json", authorization: `Bearer ${JETON_MODELE}` } });
      expect(sans.statut).to.equal(401);
    });

    it("hôte inconnu : 401 au format de la route, aucun relais, aucun événement, auth_failed consigné", async function () {
      const n = await nbEvenements();
      const avant = fournisseur.requetes.length;
      const r = await envoyer(principale, "/v1/messages", { corps: MSG, entetes: { "content-type": "application/json", "x-noortrace-token": "jeton-faux" } });
      expect(r.statut).to.equal(401);
      expect(JSON.parse(r.texte).error.message).to.equal("noortrace: hote non authentifie");
      const g = await envoyer(principale, "/v1beta/models/gemini-x:streamGenerateContent?alt=sse", { corps: GEM, entetes: { "content-type": "application/json" } });
      expect(g.entetes.get("content-type")).to.equal("text/event-stream");
      expect(fournisseur.requetes.length).to.equal(avant);
      expect(await nbEvenements()).to.equal(n);
      expect(derniere("auth_failed").data).to.include({ transport: "passerelle", reason: "hote_inconnu", status: 401 });
    });

    it("délégation déclarée par en-têtes (EX-7.2) : admise dans les bornes, refusée sinon ; jamais relayée", async function () {
      const ok = await envoyer(principale, "/v1/messages", { corps: MSG, entetes: { ...BASE, "x-noortrace-run-id": "run-modele-0001", "x-noortrace-on-behalf-of": "service-sinistres" } });
      expect(ok.echange.evenement.delegation).to.deep.equal({ launched_by: "agent-modele", on_behalf_of: "service-sinistres", scope: "sinistres:lecture", run_id: "run-modele-0001" });
      expect(Object.keys(fournisseur.requetes.at(-1).entetes).filter((k) => k.startsWith("x-noortrace"))).to.deep.equal([]);
      const ko = await envoyer(principale, "/v1/messages", { corps: MSG, entetes: { ...BASE, "x-noortrace-run-id": "jean@example.ch", "x-noortrace-on-behalf-of": "inconnu" } });
      expect(ko.echange.evenement.delegation).to.deep.equal({ launched_by: "agent-modele", on_behalf_of: "service-sinistres", scope: "sinistres:lecture", run_id: null });
      const refus = ops().filter((l) => l.event === "delegation_refused").slice(-2).map((l) => [l.data.field, l.data.reason]);
      expect(refus).to.deep.equal([["on_behalf_of", "hors_liste"], ["run_id", "motif"]]);
      const det = await envoyer(principale, "/v1/messages", { corps: MSG, entetes: { ...BASE, "x-noortrace-run-id": "run-4111111111111111" } });
      expect(det.echange.evenement.delegation.run_id).to.equal(null);
      expect(derniere("delegation_refused").data).to.include({ field: "run_id", reason: "detecteur" });
    });
  });

  describe("EX-5.9 : réponse non comprimée demandée, réponse comprimée quand même", function () {
    it("Accept-Encoding: identity vers l'amont ; gzip décomprimé pour la pièce, relayé comprimé à l'hôte", async function () {
      const corps = JSON.stringify(reponseEntiere("anthropic-messages", MSG, 1));
      fournisseur.prochaine({ statut: 200, entetes: { "content-type": "application/json" }, morceaux: [corps], gzip: true });
      const r = await brut(principale, "/v1/messages", { corps: JSON.stringify(MSG) });
      expect(fournisseur.requetes.at(-1).entetes["accept-encoding"]).to.equal("identity");
      expect(r.entetes["content-encoding"]).to.equal("gzip");
      expect(zlib.gunzipSync(r.octets).toString("utf8")).to.equal(corps);
      const e = r.echange.evenement;
      expect(JSON.parse(await piece(e.execution.result))).to.deep.equal(JSON.parse(corps));
      expect(e.execution.is_error).to.equal(false);
    });

    it("flux SSE comprimé : forme consolidée sur les octets décomprimés", async function () {
      fournisseur.prochaine({ statut: 200, entetes: { "content-type": "text/event-stream" }, morceaux: evenementsFlux("openai-chat", CHAT, 2), gzip: true });
      const r = await envoyer(principale, "/v1/chat/completions", { corps: { ...CHAT, stream: true } });
      expect(r.echange.incomplet).to.equal(false);
      expect(r.echange.consolidee.forme.choices[0].message.content).to.equal("Je consulte le dossier.");
    });

    it("codage inconnu ou décompression en échec : pièce non rédigeable codage_inconnu (EX-8.7 règle 3)", async function () {
      for (const [ce, octets] of [["zstd", "abc"], ["gzip", "pas du gzip"]]) {
        fournisseur.prochaine({ statut: 200, entetes: { "content-type": "application/json", "content-encoding": ce }, morceaux: [octets] });
        const r = await brut(principale, "/v1/messages", { corps: JSON.stringify(MSG) });
        expect(r.octets.toString("utf8")).to.equal(octets);
        const e = r.echange.evenement;
        expect(e.execution.is_error, ce).to.equal(true);
        expect(JSON.parse(await piece(e.execution.result))).to.deep.equal({ noortrace_non_redigeable: { content_type: "application/json", length: octets.length, reason: "codage_inconnu" } });
        expect(e.execution.result.redacted).to.equal(true);
      }
    });
  });

  describe("EX-5.10, EX-5.11, EX-5.12 : ordre, flux sans tampon, inscription avant les derniers octets", function () {
    it("pièces « requête » et « prompt système » durables avant l'envoi au fournisseur", async function () {
      const pr = await piecesRequete({ format: "anthropic-messages", valeur: MSG, prompt_in_request: "reference", prompt_system: "redige", redacteur: new Redacteur({ politique: politiquePii(), fils: 0 }) });
      let vu = null;
      fournisseur.surRequete = async () => {
        vu = { requete: fs.existsSync(coeur.pieces.chemin(pr.requete.sha256)), prompt: fs.existsSync(coeur.pieces.chemin(pr.prompt.sha256)), evenements: await nbEvenements() };
      };
      const n = await nbEvenements();
      await envoyer(principale, "/v1/messages", { corps: MSG });
      expect(vu).to.deep.equal({ requete: true, prompt: true, evenements: n });
    });

    it("chaque octet relayé dès réception, en-têtes d'abord ; forme close inscrite au registre avant la fin de la réponse", async function () {
      const ev = evenementsFlux("anthropic-messages", MSG, 7);
      fournisseur.prochaine({ statut: 200, entetes: { "content-type": "text/event-stream" }, morceaux: [": commentaire\n\n", ...ev.slice(0, 3), ...ev.slice(3)], pauseMs: 60 });
      const t0 = Date.now();
      obs = { echanges: [], refus: [] };
      const r = await new Promise((res) => {
        const q = http.request({ host: "127.0.0.1", port: principale.adresse().port, path: "/v1/messages", method: "POST", headers: BASE }, (rep) => {
          const tEntetes = Date.now() - t0;
          let tPremier = null;
          const m = [];
          rep.on("data", (c) => {
            if (tPremier === null) tPremier = Date.now() - t0;
            m.push(c);
          });
          rep.on("end", () => {
            // À la fin du corps reçu par l'hôte, l'échange est déjà au registre (5.6).
            const inscrit = principale.registre.entrees.some((x) => x.appels.some((a) => a.id === "toolu_simule_7"));
            res({ tEntetes, tPremier, tFin: Date.now() - t0, octets: Buffer.concat(m), inscrit, type: rep.headers["content-type"] });
          });
        });
        q.end(JSON.stringify({ ...MSG, stream: true }));
      });
      expect(r.type).to.equal("text/event-stream");
      expect(r.tFin - r.tPremier, "le premier octet n'attend pas la fin du flux").to.be.greaterThan(400);
      expect(r.octets.toString("utf8")).to.equal([": commentaire\n\n", ...ev].join(""));
      expect(r.inscrit).to.equal(true);
      await attendre();
      // Commentaires et ping relayés, ignorés par l'analyseur et comptés (EX-5.12).
      expect(derniere("model_exchange_relayed").data.ignored_events).to.equal(1);
    });
  });

  describe("EX-5.13, EX-5.25 : coupures, aucune relance", function () {
    it("flux coupé par le fournisseur : forme incomplète, is_error ; aucune réémission", async function () {
      const ev = evenementsFlux("anthropic-messages", MSG, 8);
      fournisseur.prochaine({ statut: 200, entetes: { "content-type": "text/event-stream" }, morceaux: ev.slice(0, 4), couper: true });
      const avant = fournisseur.requetes.length;
      const r = await brut(principale, "/v1/messages", { corps: JSON.stringify({ ...MSG, stream: true }) }).catch((e) => ({ erreur: e }));
      await attendre();
      const x = obs.echanges[0];
      expect(x.evenement.execution.is_error).to.equal(true);
      expect(x.consolidee.forme[CLE_INCOMPLET]).to.equal(true);
      expect(fournisseur.requetes.length).to.equal(avant + 1);
      void r;
      for (const statut of [429, 500, 529]) {
        fournisseur.prochaine({ statut, entetes: { "content-type": "application/json", "retry-after": "2", "x-should-retry": "true" }, morceaux: ['{"type":"error","error":{"type":"overloaded_error","message":"x"}}'] });
        const e = await envoyer(principale, "/v1/messages", { corps: MSG });
        expect(e.statut).to.equal(statut);
        expect(e.entetes.get("retry-after")).to.equal("2");
        expect(e.entetes.get("x-should-retry")).to.equal("true");
        expect(e.echange.evenement.execution.is_error).to.equal(true);
      }
      expect(fournisseur.requetes.length).to.equal(avant + 4);
    });

    it("l'hôte ferme pendant le flux : connexion amont fermée, forme incomplète, host_disconnected", async function () {
      const ev = evenementsFlux("openai-chat", CHAT, 9);
      const s = { statut: 200, entetes: { "content-type": "text/event-stream" }, morceaux: ev, pauseMs: 150 };
      fournisseur.prochaine(s);
      obs = { echanges: [], refus: [] };
      await new Promise((res) => {
        const q = http.request({ host: "127.0.0.1", port: principale.adresse().port, path: "/v1/chat/completions", method: "POST", headers: BASE }, (rep) => {
          rep.once("data", () => {
            q.destroy();
            res();
          });
        });
        q.on("error", () => {});
        q.end(JSON.stringify({ ...CHAT, stream: true }));
      });
      for (let i = 0; i < 300 && !obs.echanges.length; i++) await pause(10);
      await pause(400);
      expect(fournisseur.requetes.at(-1).fermeParClient).to.equal(true);
      const x = obs.echanges[0];
      expect(x.evenement.execution.is_error).to.equal(true);
      expect(x.incomplet).to.equal(true);
      expect(derniere("host_disconnected").data).to.deep.equal({ route: "/v1/chat/completions" });
    });
  });

  describe("EX-5.19, EX-5.20, EX-5.21 : code.model, usage, intention", function () {
    it("code.model = libellé/modèle de la réponse, tronqué à 256 caractères ; usage hors de l'événement, au journal et aux métriques", async function () {
      const long = "m".repeat(300);
      fournisseur.prochaine({ statut: 200, entetes: { "content-type": "application/json" }, morceaux: [JSON.stringify({ ...reponseEntiere("anthropic-messages", MSG, 3), model: long })] });
      const avant = coeur.metriques.valeur("noortrace_model_tokens_total", { provider: "anthropic", direction: "entree" }) ?? 0;
      const r = await envoyer(principale, "/v1/messages", { corps: MSG });
      expect(r.echange.evenement.code.model).to.equal(`anthropic/${long}`.slice(0, 256));
      expect(JSON.stringify(r.echange.evenement)).to.not.include("input_tokens");
      expect(derniere("model_exchange_relayed").data.usage).to.deep.equal({ input_tokens: 120, output_tokens: 30 });
      expect(coeur.metriques.valeur("noortrace_model_tokens_total", { provider: "anthropic", direction: "entree" })).to.equal(avant + 120);
    });

    it("intention au-delà de 4096 caractères : pièce text/plain non rédigée ; intention rédigée : pièce redacted", async function () {
      const texte = "x".repeat(5000);
      fournisseur.prochaine({ statut: 200, entetes: { "content-type": "application/json" }, morceaux: [JSON.stringify({ ...reponseEntiere("openai-chat", CHAT, 4), choices: [{ index: 0, message: { role: "assistant", content: texte }, finish_reason: "stop" }] })] });
      const r = await envoyer(principale, "/v1/chat/completions", { corps: CHAT });
      expect(r.echange.evenement.intent).to.deep.include({ length: 5000, redacted: false, media_type: "text/plain" });
      expect(await piece(r.echange.evenement.intent)).to.equal(texte);
      fournisseur.prochaine({ statut: 200, entetes: { "content-type": "application/json" }, morceaux: [JSON.stringify({ ...reponseEntiere("openai-chat", CHAT, 5), choices: [{ index: 0, message: { role: "assistant", content: "Ecrire a j.dupont@example.ch." }, finish_reason: "stop" }] })] });
      const r2 = await envoyer(principale, "/v1/chat/completions", { corps: CHAT });
      expect(r2.echange.evenement.intent.redacted).to.equal(true);
      expect(await piece(r2.echange.evenement.intent)).to.equal("Ecrire a [REDIGE:email].");
      expect(r2.echange.evenement.policy.redaction).to.equal("pii-v1");
    });
  });

  describe("EX-5.22 : corrélation", function () {
    const reponse = (n) => reponseEntiere("anthropic-messages", MSG, n);
    let t = 1000;
    function registre() {
      const r = new RegistreCorrelation({ fenetreMs: 600000, monotone: () => t, ecrirePiece: async () => {} });
      return r;
    }
    const code = { model: "anthropic/m", prompt_version: null };
    const entree = (r, o = {}) => {
      const e = r.inscrire({ host: {}, host_group: o.groupe ?? "g", run_id: o.run ?? null, format: o.format ?? "anthropic-messages", formeClair: o.forme ?? reponse(o.n ?? 1), interpose: o.interpose, t_complet: o.t ?? t });
      r.completer(e, { formeRedigee: o.forme ?? reponse(o.n ?? 1), code: o.code ?? code });
      return e;
    };
    const hote = { tool_name_template: "{tool_announced}", tool_name_sanitize: true };
    const appel = (o = {}) => ({ host: o.hote ?? hote, host_group: o.groupe ?? "g", run_id: o.run ?? null, tool_announced: o.nom ?? "demo__claims.get", arguments: o.args ?? { claim_id: "2026-81044" }, t_recu: o.t ?? t });

    it("même groupe, même run_id, dans la fenêtre, nom par gabarit et normalisation, arguments égaux en JCS intégral : intent et code de l'échange", async function () {
      const r = registre();
      const e = entree(r, { run: "run-1" });
      r.sceller(e, 42);
      expect(await r.correler(appel({ run: "run-1" }))).to.deep.equal({ intent: "Je consulte le dossier du sinistre 2026-81044.", code, seq: 42, declaree: false });
      expect(nomVuParLeModele("demo__claims.get", { tool_name_template: "mcp__noortrace__{tool_announced}", tool_name_sanitize: true }, { alias: "demo", nom: "claims.get" })).to.equal("mcp__noortrace__demo__claims_get");
    });

    it("échecs : autre groupe, run_id différents, hors fenêtre, arguments ou nom différents, bloc déjà consommé, chaîne arguments non JSON", async function () {
      const r = registre();
      entree(r, { run: "run-1" });
      expect(await r.correler(appel({ groupe: "autre" }))).to.equal(null);
      expect(await r.correler(appel({ run: "run-2" }))).to.equal(null);
      expect(await r.correler(appel({ args: { claim_id: "2026-81045" } }))).to.equal(null);
      expect(await r.correler(appel({ nom: "demo__claims.search" }))).to.equal(null);
      expect(await r.correler(appel({ hote: { tool_name_template: "{tool_announced}", tool_name_sanitize: false } }))).to.equal(null);
      expect(await r.correler(appel({ t: t + 700000 }))).to.equal(null);
      expect(await r.correler(appel({ t: t - 1 }))).to.equal(null);
      expect(await r.correler(appel())).to.not.equal(null);
      expect(await r.correler(appel()), "un bloc ne sert qu'à un appel").to.equal(null);
      const r2 = registre();
      const forme = reponseEntiere("openai-chat", CHAT, 1);
      forme.choices[0].message.tool_calls[0].function.arguments = "{non json";
      entree(r2, { format: "openai-chat", forme });
      expect(await r2.correler(appel())).to.equal(null);
    });

    it("le plus récent d'abord ; un échange interposé est préféré à un échange déclaré, consigné sinon (correlation_declaree)", async function () {
      const r = registre();
      const ancien = entree(r, { n: 1, t: t - 10, code: { model: "a/ancien", prompt_version: null } });
      const recent = entree(r, { n: 2, t: t - 5, code: { model: "a/recent", prompt_version: null } });
      void ancien;
      void recent;
      expect((await r.correler(appel())).code.model).to.equal("a/recent");
      const r2 = registre();
      entree(r2, { n: 1, t: t - 1, interpose: false, code: { model: "sdk/declare", prompt_version: null } });
      entree(r2, { n: 2, t: t - 50, code: { model: "a/interpose", prompt_version: null } });
      expect((await r2.correler(appel())).code.model).to.equal("a/interpose");
      const d = await r2.correler(appel());
      expect(d).to.include({ declaree: true });
      expect(d.code.model).to.equal("sdk/declare");
    });
  });

  describe("EX-5.24 : délais du fournisseur", function () {
    it("connexion impossible : 504 au format de la route, événement is_error, pièce noortrace_timeout phase connexion", async function () {
      const s = net.createServer();
      await new Promise((r) => s.listen(0, "127.0.0.1", r));
      const port = s.address().port;
      await new Promise((r) => s.close(r));
      const p = await ouvrir((c) => {
        for (const r of c.policy.model.routes) r.upstream = `http://127.0.0.1:${port}`;
      });
      const r = await envoyer(p, "/v1/messages", { corps: MSG });
      expect(r.statut).to.equal(504);
      expect(r.texte).to.equal('{"type":"error","error":{"type":"noortrace_timeout","message":"noortrace: delai du fournisseur depasse"}}');
      expect(JSON.parse(await piece(r.echange.evenement.execution.result))).to.deep.equal({ noortrace_http_error: { status: 504, content_type: null, body: { noortrace_timeout: { phase: "connexion", timeout_ms: 2000 } } } });
      const g = await envoyer(p, "/v1beta/models/gemini-x:generateContent", { corps: GEM });
      expect(g.texte).to.equal('{"error":{"code":504,"message":"noortrace: delai du fournisseur depasse","status":"DEADLINE_EXCEEDED"}}');
      expect(derniere("provider_error").data).to.include({ phase: "connexion" });
    });

    it("premier octet au-delà du délai : 504 ; silence au-delà d'idle_timeout_ms pendant un flux : flux clos, forme incomplète", async function () {
      const p = await ouvrir((c) => {
        c.model.first_byte_timeout_ms = 300;
        c.model.idle_timeout_ms = 300;
      });
      fournisseur.prochaine({ avantEntetesMs: 800, statut: 200, entetes: { "content-type": "application/json" }, morceaux: ["{}"] });
      const r = await envoyer(p, "/v1/messages", { corps: MSG });
      expect(r.statut).to.equal(504);
      expect(JSON.parse(await piece(r.echange.evenement.execution.result)).noortrace_http_error.body).to.deep.equal({ noortrace_timeout: { phase: "premier_octet", timeout_ms: 300 } });
      const ev = evenementsFlux("anthropic-messages", MSG, 10);
      fournisseur.prochaine({ statut: 200, entetes: { "content-type": "text/event-stream" }, morceaux: ev.slice(0, 3), silenceMs: 900 });
      await brut(p, "/v1/messages", { corps: JSON.stringify({ ...MSG, stream: true }) }).catch(() => null);
      await attendre();
      const x = obs.echanges[0];
      expect(x.evenement.execution.is_error).to.equal(true);
      expect(x.consolidee.forme[CLE_INCOMPLET]).to.equal(true);
      expect(derniere("provider_error").data).to.include({ phase: "inactivite" });
      await pause(700);
    });
  });

  describe("EX-5.26 : cadrage et en-têtes saut par saut", function () {
    it("Content-Length et Transfer-Encoding ensemble : 400, sans relais", async function () {
      const avant = fournisseur.requetes.length;
      const ligne = await new Promise((res) => {
        const c = net.connect(principale.adresse().port, "127.0.0.1", () => c.write(`POST /v1/messages HTTP/1.1\r\nHost: x\r\nX-Noortrace-Token: ${JETON_MODELE}\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n`));
        c.on("data", (d) => {
          res(String(d).split("\r\n")[0]);
          c.destroy();
        });
      });
      expect(ligne).to.equal("HTTP/1.1 400 Bad Request");
      expect(fournisseur.requetes.length).to.equal(avant);
      expect(derniere("model_request_refused").data.raison).to.equal("cadrage");
    });

    it("liste autorisée : relayés, notés, retirés ; Connection, champs saut par saut, Cookie, strip_headers jamais relayés ; cadrage calculé", async function () {
      const corps = JSON.stringify(MSG);
      obs = { echanges: [], refus: [] };
      const r = await new Promise((res) => {
        const q = http.request(
          {
            host: "127.0.0.1",
            port: principale.adresse().port,
            path: "/v1/messages",
            method: "POST",
            headers: { ...BASE, connection: "keep-alive, x-perso", "x-perso": "1", "keep-alive": "timeout=5", te: "trailers", cookie: "s=1", "proxy-authorization": "Basic eA==", "x-trace-id": "t-1", "x-a-retirer": "1", "anthropic-beta": "outils-2026", "x-claude-code-session": "s-1", "x-inconnu": "1" },
          },
          (rep) => {
            rep.resume();
            rep.on("end", () => res(rep.headers));
          },
        );
        q.end(corps);
      });
      const recus = fournisseur.requetes.at(-1).entetes;
      for (const k of ["x-perso", "keep-alive", "te", "cookie", "proxy-authorization", "x-a-retirer", "x-inconnu"]) expect(recus, k).to.not.have.property(k);
      expect(recus).to.include({ "x-trace-id": "t-1", "anthropic-beta": "outils-2026", "x-claude-code-session": "s-1", "content-length": String(Buffer.byteLength(corps)) });
      expect(recus.host).to.equal(new URL(fournisseur.url).host);
      expect(r).to.have.property("request-id");
      expect(r).to.not.have.property("x-fournisseur-interne");
      await attendre();
      const l = derniere("model_exchange_relayed").data;
      expect(l.headers).to.include({ "anthropic-beta": "outils-2026", "x-claude-code-session": "s-1" });
      expect(l.headers_removed).to.include.members(["x-a-retirer", "x-inconnu", "x-perso"]);
    });
  });

  describe("EX-5.28, EX-5.29, EX-5.30 : routes et chaîne de requête Gemini", function () {
    it("seuls <path>/<modèle>:generateContent et :streamGenerateContent ; cible amont reconstruite", async function () {
      const avant = fournisseur.requetes.length;
      for (const c of ["/v1beta/models/gemini-x:countTokens", "/v1beta/models/Gemini-X:generateContent", "/v1beta/models/gemini-x%3AgenerateContent", "/v1beta/models/gemini-x", "/v1beta/models/a/b:generateContent", "/v1beta/tunedModels/m:generateContent", "/v1beta/projects/p/locations/l/models/g:generateContent", "/v1beta"]) {
        expect((await envoyer(principale, c, { corps: GEM })).statut, c).to.equal(404);
      }
      expect((await envoyer(principale, "/v1beta/models/gemini-x:generateContent", { methode: "GET", entetes: { "x-noortrace-token": JETON_MODELE } })).statut).to.equal(404);
      expect(fournisseur.requetes.length).to.equal(avant);
      const ok = await envoyer(principale, "/v1/models/gemini-x:generateContent?alt=json", { corps: GEM });
      expect(ok.statut).to.equal(200);
      expect(fournisseur.requetes.at(-1).cible).to.equal("/v1/models/gemini-x:generateContent");
      expect(ok.echange.evenement.code.model).to.equal("gemini/gemini-simule-001");
    });

    it("chaîne de requête : cle_dans_url d'abord, flux_sans_sse, parametre_non_admis ; noms consignés, jamais les valeurs", async function () {
      expect(examinerRequeteGemini("streamGenerateContent", "alt=sse&x=1")).to.include({ raison: "parametre_non_admis" });
      expect(examinerRequeteGemini("streamGenerateContent", "alt=json")).to.include({ raison: "flux_sans_sse" });
      expect(examinerRequeteGemini("generateContent", "alt=json&alt=json")).to.include({ raison: "parametre_non_admis" });
      expect(examinerRequeteGemini("generateContent", "alt=sse")).to.include({ raison: "parametre_non_admis" });
      expect(examinerRequeteGemini("generateContent", "x=1&key=k")).to.include({ raison: "cle_dans_url" });
      expect(examinerRequeteGemini("generateContent", null)).to.deep.equal({ ok: true, amont: "" });
      expect(examinerRequeteGemini("streamGenerateContent", "%61lt=%73se")).to.deep.equal({ ok: true, amont: "?alt=sse" });
      const r = await envoyer(principale, "/v1beta/models/gemini-x:streamGenerateContent?alt=sse&secretcolle", { corps: GEM });
      expect(r.statut).to.equal(400);
      expect(r.entetes.get("content-type")).to.equal("text/event-stream");
      const l = derniere("model_request_refused");
      expect(l.data).to.deep.equal({ route: "/v1beta/models", raison: "parametre_non_admis", params: ["alt", "[autre:11]"] });
      expect(JSON.stringify(l)).to.not.include("secretcolle");
    });

    it("corps AIP-193 de la passerelle (413, 503) et pièce noortrace_http_error d'un statut amont ≥ 400 lu quel que soit le Content-Type", async function () {
      const p = await ouvrir((c) => {
        c.limits.model_request_max_bytes = 1024;
      });
      const g = await envoyer(p, "/v1beta/models/gemini-x:generateContent", { corps: { contents: [{ role: "user", parts: [{ text: "x".repeat(2000) }] }] } });
      expect(g.statut).to.equal(413);
      expect(g.texte).to.equal('{"error":{"code":413,"message":"noortrace: corps de requete trop grand","status":"INVALID_ARGUMENT"}}');
      coeur.degrade.entrer("cle");
      try {
        const b = await envoyer(principale, "/v1beta/models/gemini-x:generateContent", { corps: GEM });
        expect(b.statut).to.equal(503);
        expect(b.texte).to.equal('{"error":{"code":503,"message":"noortrace: echange bloque, enregistreur en mode degrade","status":"UNAVAILABLE"}}');
      } finally {
        coeur.degrade.sortir("cle");
      }
      fournisseur.prochaine({ statut: 403, entetes: { "content-type": "text/html" }, morceaux: ['{"error":{"code":403,"message":"interdit","status":"PERMISSION_DENIED"}}'] });
      const e = await envoyer(principale, "/v1beta/models/gemini-x:generateContent", { corps: GEM });
      expect(JSON.parse(await piece(e.echange.evenement.execution.result)).noortrace_http_error.body.error.status).to.equal("PERMISSION_DENIED");
    });
  });

  describe("EX-5.32 : serveurs MCP et contenu en cache déclarés au fournisseur", function () {
    it("refuser (défaut) : 400 ; relayer : relayés et consignés ; null et [] ne comptent pas ; noms snake_case compris", async function () {
      const avant = fournisseur.requetes.length;
      const mcp = { ...GEM, tools: [{ mcp_servers: [{ name: "x" }] }] };
      expect((await envoyer(principale, "/v1beta/models/gemini-x:generateContent", { corps: mcp })).statut).to.equal(400);
      expect((await envoyer(principale, "/v1beta/models/gemini-x:generateContent", { corps: { ...GEM, cached_content: "cachedContents/c1" } })).statut).to.equal(400);
      expect(fournisseur.requetes.length).to.equal(avant);
      expect((await envoyer(principale, "/v1beta/models/gemini-x:generateContent", { corps: { ...GEM, tools: [{ mcpServers: [] }, { mcpServers: null }], cachedContent: null } })).statut).to.equal(200);
      const p = await ouvrir((c) => {
        for (const r of c.policy.model.routes) if (r.format === "gemini") Object.assign(r, { provider_mcp: "relayer", provider_cache: "relayer" });
      });
      const r = await envoyer(p, "/v1beta/models/gemini-x:generateContent", { corps: { ...mcp, cachedContent: "cachedContents/c1" } });
      expect(r.statut).to.equal(200);
      expect(derniere("provider_mcp_bypass").data).to.deep.equal({ route: "/v1beta/models", entries: 1 });
      expect(derniere("provider_cache_reference").data).to.deep.equal({ route: "/v1beta/models" });
      expect(JSON.parse(await piece(r.echange.evenement.execution.arguments)).cachedContent).to.equal("cachedContents/c1");
    });

    it("validation : passthrough POST vers cachedContents ou /upload/ refusé, relayer averti, couple en double refusé", function () {
      const c = structuredClone(config);
      const g = c.policy.model.routes.find((r) => r.path === "/v1beta/models");
      g.passthrough = [{ method: "POST", path: "/v1beta/cachedContents" }, { method: "POST", path: "/upload/v1beta/files" }, { method: "GET", path: "/v1beta/models" }];
      g.provider_mcp = "relayer";
      c.policy.model.routes[0].passthrough.push({ method: "POST", path: "/v1/messages" });
      const r = controleModele(c);
      expect(r.erreurs.map((e) => e.pointeur)).to.include.members(["/policy/model/routes/4/passthrough/0/path", "/policy/model/routes/4/passthrough/1/path", "/policy/model/routes/0/passthrough/2"]);
      expect(r.avertissements.map((e) => e.pointeur)).to.include("/policy/model/routes/4/provider_mcp");
    });
  });

  describe("EX-5.33 : bornes de taille", function () {
    it("requête au-delà de la borne : 413 au format de chaque fournisseur ; réponse au-delà : relayée entière, pièce taille ou forme incomplète", async function () {
      const p = await ouvrir((c) => {
        c.limits.model_request_max_bytes = 1024;
        c.limits.model_response_max_bytes = 1024;
      });
      const gros = { ...MSG, messages: [{ role: "user", content: "x".repeat(2000) }] };
      const a = await envoyer(p, "/v1/messages", { corps: gros });
      expect([a.statut, a.texte]).to.deep.equal([413, '{"type":"error","error":{"type":"noortrace_taille","message":"noortrace: corps de requete trop grand"}}']);
      const o = await envoyer(p, "/v1/chat/completions", { corps: { ...CHAT, messages: gros.messages } });
      expect(o.texte).to.equal('{"error":{"message":"noortrace: corps de requete trop grand","type":"invalid_request_error","param":null,"code":"noortrace_taille"}}');
      expect(derniere("model_request_refused").data).to.include({ raison: "taille" });
      const corps = JSON.stringify({ ...reponseEntiere("openai-chat", CHAT, 11), pad: "y".repeat(3000) });
      fournisseur.prochaine({ statut: 200, entetes: { "content-type": "application/json" }, morceaux: [corps.slice(0, 1500), corps.slice(1500)] });
      const r = await envoyer(p, "/v1/chat/completions", { corps: CHAT });
      expect(r.texte).to.equal(corps);
      expect(JSON.parse(await piece(r.echange.evenement.execution.result))).to.deep.equal({ noortrace_non_redigeable: { content_type: "application/json", length: Buffer.byteLength(corps), reason: "taille" } });
      expect(r.echange.evenement.execution.is_error).to.equal(true);
      expect(derniere("model_response_truncated").data).to.deep.equal({ route: "/v1/chat/completions", bytes: Buffer.byteLength(corps) });
      const ev = evenementsFlux("anthropic-messages", MSG, 12);
      fournisseur.prochaine({ statut: 200, entetes: { "content-type": "text/event-stream" }, morceaux: ev });
      const f = await envoyer(p, "/v1/messages", { corps: { ...MSG, stream: true } });
      expect(f.texte).to.equal(ev.join(""));
      expect(f.echange.consolidee.forme[CLE_INCOMPLET]).to.equal(true);
      expect(f.echange.evenement.execution.is_error).to.equal(true);
    });
  });

  describe("EX-5.36 : segment de modèle en repli de code.model", function () {
    it("segment admis par les détecteurs : gemini/<segment> ; segment qu'un détecteur vise : null et model_segment_refused, sans la valeur", async function () {
      const sans = (n) => {
        const r = reponseEntiere("gemini", GEM, n);
        delete r.modelVersion;
        return JSON.stringify(r);
      };
      fournisseur.prochaine({ statut: 200, entetes: { "content-type": "application/json" }, morceaux: [sans(13)] });
      expect((await envoyer(principale, "/v1beta/models/gemini-x:generateContent", { corps: GEM })).echange.evenement.code.model).to.equal("gemini/gemini-x");
      fournisseur.prochaine({ statut: 200, entetes: { "content-type": "application/json" }, morceaux: [sans(14)] });
      const r = await envoyer(principale, "/v1beta/models/m-4111111111111111:generateContent", { corps: GEM });
      expect(r.echange.evenement.code.model).to.equal(null);
      const l = derniere("model_segment_refused");
      expect(l.data).to.deep.equal({ route: "/v1beta/models", raison: "detecteur", length: 18 });
      expect(JSON.stringify(ops().filter((x) => x.event === "model_segment_refused"))).to.not.include("4111111111111111");
    });
  });

  describe("EX-8.5 à EX-8.7 : prompt système et pièces non JSON", function () {
    it("prompt_system named : pièce [PROMPT:<nom>] de la connexion d'hôte, ou de X-Noortrace-Prompt-Version admis", async function () {
      const p = await ouvrir((c) => {
        c.model.prompt_system = "named";
        c.model.hosts[0].prompt_version_name = "sinistres-v3";
      });
      const a = await envoyer(p, "/v1/messages", { corps: MSG });
      expect(await piece({ sha256: a.echange.evenement.code.prompt_version })).to.equal("[PROMPT:sinistres-v3]");
      const b = await envoyer(p, "/v1/messages", { corps: MSG, entetes: { ...BASE, "x-noortrace-prompt-version": "sinistres-v4" } });
      expect(await piece({ sha256: b.echange.evenement.code.prompt_version })).to.equal("[PROMPT:sinistres-v4]");
      const c = await envoyer(p, "/v1/messages", { corps: MSG, entetes: { ...BASE, "x-noortrace-prompt-version": "x@exemple.ch" } });
      expect(await piece({ sha256: c.echange.evenement.code.prompt_version })).to.equal("[PROMPT:sinistres-v3]");
      expect(JSON.parse(await piece(a.echange.evenement.execution.arguments)).system).to.equal("[REDIGE:prompt-systeme]");
    });

    it("réponse 2xx non UTF-8 : pièce non rédigeable non_utf8 ; texte avec marque d'ordre d'octets : octets reçus, marque comprise", async function () {
      fournisseur.prochaine({ statut: 200, entetes: { "content-type": "Application/Octet-Stream" }, morceaux: [Buffer.from([0xff, 0xfe, 0x00, 0x41])] });
      const a = await envoyer(principale, "/v1/messages", { corps: MSG });
      expect(JSON.parse(await piece(a.echange.evenement.execution.result))).to.deep.equal({ noortrace_non_redigeable: { content_type: "Application/Octet-Stream", length: 4, reason: "non_utf8" } });
      const texte = "﻿service indisponible";
      fournisseur.prochaine({ statut: 200, entetes: { "content-type": "text/plain; charset=utf-8" }, morceaux: [texte] });
      const b = await envoyer(principale, "/v1/messages", { corps: MSG });
      expect(b.echange.evenement.execution.result).to.deep.include({ media_type: "text/plain", redacted: false, length: Buffer.byteLength(texte) });
      expect(await piece(b.echange.evenement.execution.result)).to.equal(texte);
    });
  });

  describe("§14 (colonne M), EX-14.16, §13.5 : pannes et arrêt", function () {
    it("mode dégradé « clé » : 503 au format de la route, rien n'est relayé, call_blocked compté", async function () {
      const avant = fournisseur.requetes.length;
      coeur.degrade.entrer("cle");
      try {
        const a = await envoyer(principale, "/v1/messages", { corps: MSG });
        expect([a.statut, a.texte]).to.deep.equal([503, '{"type":"error","error":{"type":"noortrace_degrade","message":"noortrace: echange bloque, enregistreur en mode degrade"}}']);
        const o = await envoyer(principale, "/v1/responses", { corps: RESP });
        expect(o.texte).to.equal('{"error":{"message":"noortrace: echange bloque, enregistreur en mode degrade","type":"noortrace_degrade","param":null,"code":"noortrace_degrade"}}');
      } finally {
        coeur.degrade.sortir("cle");
      }
      expect(fournisseur.requetes.length).to.equal(avant);
      expect(derniere("call_blocked").data).to.include({ code: 503, reason: "cle", class: "modele" });
      expect(coeur.metriques.valeur("noortrace_calls_blocked_total", { code: "503", reason: "cle", class: "modele" })).to.be.greaterThan(1);
      expect((await envoyer(principale, "/v1/messages", { corps: MSG })).statut).to.equal(200);
    });

    it("panne après l'envoi : réponse déjà relayée, événement gardé en attente puis scellé avec son instant de capture", async function () {
      const sceller = coeur.scellerEchange.bind(coeur);
      coeur.scellerEchange = async () => {
        throw new ErreurEnregistreur("cle", "panne de test");
      };
      let r;
      try {
        r = await envoyer(principale, "/v1/messages", { corps: MSG });
      } finally {
        coeur.scellerEchange = sceller;
      }
      expect(r.statut).to.equal(200);
      expect(r.echange.evenement).to.equal(null);
      expect(r.echange.pendingId).to.match(/^p-/);
      expect(coeur.attente.length).to.equal(1);
      const n = await nbEvenements();
      await coeur.viderAttente();
      const e = (await lireEvenements(coeur.repertoire)).at(-1);
      expect(await nbEvenements()).to.equal(n + 1);
      expect(e.execution.tool).to.equal("noortrace.modele.echange");
      expect(derniere("call_executed_not_durable").data).to.include({ kind: "echange_modele" });
    });

    it("stockage indisponible avec failure.modele passant : relayé, pièces gardées en mémoire, événement en attente ; bloquant sinon", async function () {
      const ecrire = coeur.pieces.ecrire.bind(coeur.pieces);
      coeur.pieces.ecrire = async () => {
        throw new ErreurEnregistreur("stockage", "panne de test");
      };
      try {
        const b = await envoyer(principale, "/v1/messages", { corps: MSG });
        expect(b.statut).to.equal(503);
        coeur.degrade.sortir("stockage");
        const p = await ouvrir((c) => {
          c.policy.failure.modele = "passant";
        });
        const a = await envoyer(p, "/v1/messages", { corps: MSG });
        expect(a.statut).to.equal(200);
        expect(a.echange.pendingId).to.match(/^p-/);
      } finally {
        coeur.pieces.ecrire = ecrire;
      }
      coeur.degrade.sortir("stockage");
      const n = await nbEvenements();
      await coeur.viderAttente();
      expect(await nbEvenements()).to.equal(n + 1);
      const e = (await lireEvenements(coeur.repertoire)).at(-1);
      expect(fs.existsSync(coeur.pieces.chemin(e.execution.arguments.sha256))).to.equal(true);
    });

    it("mode observation (EX-14.16, EX-14.17) : aucun 503 noortrace_degrade, échange relayé, observation_would_block", async function () {
      const p = await ouvrir((c) => {
        c.policy.approval.mode = "observation";
      });
      coeur.degrade.entrer("cle");
      let r;
      try {
        r = await envoyer(p, "/v1/messages", { corps: MSG });
      } finally {
        coeur.degrade.sortir("cle");
      }
      expect(r.statut).to.equal(200);
      expect(derniere("observation_would_block").data).to.include({ reason: "cle", class: "modele" });
      await coeur.viderAttente();
    });

    it("arrêt propre (13.5) : l'échange en cours finit et est scellé, aucun échange nouveau n'est accepté", async function () {
      const p = await ouvrir();
      const ev = evenementsFlux("openai-chat", CHAT, 15);
      fournisseur.prochaine({ statut: 200, entetes: { "content-type": "text/event-stream" }, morceaux: ev, pauseMs: 40 });
      obs = { echanges: [], refus: [] };
      const enCours = fetch(`http://127.0.0.1:${p.adresse().port}/v1/chat/completions`, { method: "POST", headers: BASE, body: JSON.stringify({ ...CHAT, stream: true }) }).then((x) => x.text());
      await pause(60);
      const arret = p.arreter();
      const texte = await enCours;
      await arret;
      expect(texte).to.equal(ev.join(""));
      expect(obs.echanges[0].evenement.execution.is_error).to.equal(false);
      let refuse = false;
      await fetch(`http://127.0.0.1:${p.adresse()?.port ?? 1}/v1/chat/completions`, { method: "POST", headers: BASE, body: "{}" }).catch(() => (refuse = true));
      expect(refuse).to.equal(true);
    });
  });

  describe("§17 : journal d'exploitation et métriques", function () {
    it("ni jeton, ni clé, ni corps, ni prompt, ni valeur rédigée dans les lignes du frontal modèle (EX-17.3) ; métriques du fournisseur", async function () {
      const lignes = ops().filter((l) => l.component === "frontal_modele").map((l) => JSON.stringify(l));
      expect(lignes.length).to.be.greaterThan(20);
      for (const l of lignes) {
        for (const interdit of [JETON_MODELE, "cle-fournisseur-fictive-de-test", "cle-de-l-hote", "Tu es un agent de test", "Statut ?", "j.dupont@example.ch", "noortrace_degrade"]) expect(l, interdit).to.not.include(interdit);
      }
      expect(coeur.metriques.valeur("noortrace_upstream_latency_ms", { provider: "anthropic" })).to.be.greaterThan(5);
      expect(coeur.metriques.valeur("noortrace_upstream_errors_total", { provider: "anthropic", kind: "http_5xx" })).to.be.greaterThan(0);
    });
  });
});
