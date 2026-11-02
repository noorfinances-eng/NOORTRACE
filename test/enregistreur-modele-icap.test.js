// Mode ICAP du frontal modèle (CT-2 §5.1.2, EX-5.3 à EX-5.5, EX-5.8,
// EX-14.12 ; RFC 3507), en réussite, en échec et contre des entrées
// hostiles : un client ICAP simulé fidèlement (messages construits octet par
// octet : `Encapsulated`, sections HTTP, corps `chunked`, Preview, `ieof`)
// parle au serveur ICAP réel du démon (127.0.0.1), un mandataire HTTP fait
// traverser les quatre formats.

import { expect } from "chai";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { ServeurIcap, lireEvenements, controleModele, ErreurEnregistreur, piecesRequete, Redacteur, CLE_INCOMPLET } from "@noortrace/enregistreur";
import { repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { configurationIcap, valider, demarrerCoeur, politiquePii } from "./fixtures/enregistreur-modele/outils.mjs";
import { FournisseurSimule, evenementsFlux, reponseEntiere } from "./fixtures/enregistreur-modele/fournisseur.mjs";
import { transaction, enteteRequete, lireEntete, connecter, demarrerMandataire } from "./fixtures/enregistreur-modele/client-icap.mjs";
import { genererCertificats, opensslDisponible } from "./fixtures/enregistreur-modele/certificats.mjs";

const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const MSG = { model: "modele-icap", max_tokens: 32, system: "Agent ICAP de test.", messages: [{ role: "user", content: "Statut ?" }] };
const reqHdr = (corps, extra = []) => enteteRequete("POST https://api.fournisseur.example/v1/messages HTTP/1.1", [["Host", "api.fournisseur.example"], ["Content-Type", "application/json"], ["Content-Length", String(corps.length)], ...extra]);
const IDENT = { "X-Client-IP": "127.0.0.1" };

describe("enregistreur, frontal modèle : mode ICAP (EX-5.3 à EX-5.5, EX-14.12)", function () {
  this.timeout(60000);
  let dir;
  let fournisseur;
  let coeur;
  let config;
  let secrets;
  let serveur;
  let adresse;
  const ouverts = [];
  let obs = { echanges: [], refus: [] };

  async function ouvrir(sur = () => {}) {
    const c = structuredClone(config);
    sur(c);
    const s = new ServeurIcap({ coeur, config: c, observateur: { echange: (x) => obs.echanges.push(x), refus: (x) => obs.refus.push(x) } });
    await s.ecouter();
    ouverts.push(s);
    return s;
  }

  const ad = (s, k = 0) => ({ address: "127.0.0.1", port: s.adresses()[k].port });
  const ops = () => fs.readFileSync(config.supervision.ops_log.path, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const derniere = (ev) => ops().filter((l) => l.event === ev).pop();
  const nb = async () => (await lireEvenements(coeur.repertoire)).length;
  const attendre = async () => {
    for (let i = 0; i < 300 && !obs.echanges.length; i++) await pause(10);
    return obs.echanges[0];
  };

  /** REQMOD puis RESPMOD d'un échange Messages ; rend les deux réponses et l'échange observé. */
  async function echange(s, o = {}) {
    obs = { echanges: [], refus: [] };
    const corps = Buffer.from(JSON.stringify(o.requete ?? MSG));
    const r1 = await transaction(ad(s), { methode: "REQMOD", service: "/noortrace/reqmod", entetes: { ...IDENT, Allow: "204", ...(o.icap ?? {}) }, req: reqHdr(corps, o.entetesReq ?? []), corps: [corps] });
    if (!r1.sections["req-hdr"]) return { r1 };
    const adaptee = r1.sections["req-hdr"];
    const reponse = o.reponse ?? Buffer.from(JSON.stringify(reponseEntiere("anthropic-messages", MSG, 1)));
    const reqR = o.reqRespmod === undefined ? adaptee : o.reqRespmod;
    const r2 = await transaction(ad(s), {
      methode: "RESPMOD",
      service: "/noortrace/respmod",
      entetes: { ...IDENT, Allow: "204", ...(o.icapRespmod ?? {}) },
      req: reqR,
      res: `HTTP/1.1 ${o.statut ?? 200} OK\r\nContent-Type: ${o.type ?? "application/json"}\r\nrequest-id: req-icap\r\n\r\n`,
      corps: o.morceaux ?? [reponse],
      preview: o.preview,
      pauseMs: o.pauseMs,
      surMorceau: o.surMorceau,
    });
    return { r1, r2, adaptee, echange: await attendre() };
  }

  before(async function () {
    dir = repertoireTemporaire("noortrace-modele-icap-");
    fournisseur = await new FournisseurSimule({ pauseMs: 2 }).demarrer();
    const c = configurationIcap(dir, fournisseur.url);
    ({ config, secrets } = valider(c.config, c.env));
    ({ coeur } = await demarrerCoeur(config, secrets));
    serveur = await ouvrir();
    adresse = ad(serveur);
  });

  after(async function () {
    for (const s of ouverts) await s.arreter();
    await coeur?.arreter();
    await fournisseur?.arreter();
  });

  describe("EX-5.3 : services, OPTIONS, ISTag, authentification des clients ICAP", function () {
    it("OPTIONS : Methods, ISTag, Encapsulated: null-body=0, Options-TTL, aucun Preview annoncé", async function () {
      for (const [service, methode] of [["/noortrace/reqmod", "REQMOD"], ["/noortrace/respmod", "RESPMOD"]]) {
        const r = await transaction(adresse, { methode: "OPTIONS", service, entetes: { Encapsulated: "null-body=0" } });
        expect(r.statut).to.equal(200);
        expect(r.entetes).to.include({ methods: methode, encapsulated: "null-body=0" });
        expect(r.entetes.istag).to.match(/^"noortrace-[0-9.]+"$/);
        expect(Number(r.entetes["options-ttl"])).to.be.greaterThan(0);
        expect(r.entetes).to.not.have.property("preview");
        expect(r.entetes).to.not.have.property("allow");
      }
    });

    it("service inconnu (404), méthode du mauvais service (405), méthode inconnue (501), version (505) : toujours avec ISTag", async function () {
      const corps = Buffer.from("{}");
      for (const [m, s, statut] of [["REQMOD", "/autre", 404], ["RESPMOD", "/noortrace/reqmod", 405], ["REQMOD", "/noortrace/respmod", 405], ["PATCH", "/noortrace/reqmod", 501]]) {
        const r = await transaction(adresse, { methode: m, service: s, entetes: IDENT, req: reqHdr(corps), corps: [corps] });
        expect(r.statut, `${m} ${s}`).to.equal(statut);
        expect(r.entetes.istag).to.match(/^"noortrace/);
      }
      const s = await connecter(adresse);
      const recu = await new Promise((res) => {
        let x = "";
        s.on("data", (d) => (x += d));
        s.on("close", () => res(x));
        s.write("OPTIONS icap://127.0.0.1/noortrace/reqmod ICAP/2.0\r\n\r\n");
      });
      expect(recu.split("\r\n")[0]).to.equal("ICAP/1.0 505 ICAP Version not supported");
      expect(recu).to.match(/ISTag: "noortrace/);
    });

    it("adresse source hors de allowed_sources : 403, connexion fermée, auth_failed", async function () {
      const s = await ouvrir((c) => {
        c.model.icap.allowed_sources = ["192.0.2.0/24"];
      });
      const r = await transaction(ad(s), { methode: "OPTIONS", service: "/noortrace/reqmod" });
      expect(r.statut).to.equal(403);
      expect(derniere("auth_failed").data).to.include({ transport: "icap", reason: "client_icap_refuse" });
    });

    it("ICAPS avec certificat client (client_ca) : certificat de l'autorité admis ; sans certificat ou d'une autre autorité : poignée de main refusée", async function () {
      if (!opensslDisponible()) this.skip();
      const certs = genererCertificats(path.join(dir, "certs"));
      const s = await ouvrir((c) => {
        c.model.tls = { cert_file: certs.serveurCert, key_file: certs.serveurCle };
        c.model.icap.tls_listen = "127.0.0.1:0";
        c.model.icap.client_ca = certs.ca;
        c.model.icap.allowed_sources = [];
      });
      const tlsOk = { ca: fs.readFileSync(certs.ca), cert: fs.readFileSync(certs.clientCert), key: fs.readFileSync(certs.clientCle) };
      const r = await transaction(ad(s, 1), { methode: "OPTIONS", service: "/noortrace/reqmod", tls: tlsOk });
      expect(r.statut).to.equal(200);
      for (const t of [{ ca: fs.readFileSync(certs.ca) }, { ca: fs.readFileSync(certs.ca), cert: fs.readFileSync(certs.etrangerCert), key: fs.readFileSync(certs.etrangerCle) }]) {
        const x = await transaction(ad(s, 1), { methode: "OPTIONS", service: "/noortrace/reqmod", tls: t }).catch((e) => ({ erreur: e }));
        expect(x.erreur !== undefined || x.statut === 0, "refusé").to.equal(true);
      }
      // Le port ICAP en clair n'admet personne quand l'authentification est le certificat client.
      expect((await transaction(ad(s, 0), { methode: "OPTIONS", service: "/noortrace/reqmod" })).statut).to.equal(403);
    });

    it("validation (EX-15.4) : icap exigé, ICAPS sans certificat serveur, client_ca sans ICAPS, production sans authentification", function () {
      const c = structuredClone(config);
      expect(controleModele(c).erreurs).to.deep.equal([]);
      c.model.icap = { ...c.model.icap, tls_listen: "127.0.0.1:0", client_ca: null };
      c.model.tls = null;
      expect(controleModele(c).erreurs.map((e) => e.pointeur)).to.include("/model/tls");
      c.model.icap = { ...c.model.icap, tls_listen: null, client_ca: "/etc/ca.pem" };
      expect(controleModele(c).erreurs.map((e) => e.pointeur)).to.include("/model/icap/client_ca");
      c.model.icap = { ...c.model.icap, client_ca: null, allowed_sources: [] };
      c.recorder.environment = "production";
      expect(controleModele(c).erreurs.map((e) => e.pointeur)).to.include("/model/icap");
      c.model.icap = null;
      expect(controleModele(c).erreurs.map((e) => e.pointeur)).to.include("/model/icap");
    });
  });

  describe("EX-5.4 : REQMOD", function () {
    it("requête modifiée (200, jamais 204) : X-Noortrace-* retirés, X-Noortrace-Exchange <i>.<m>, corps inchangé ; pièces durables avant la réponse, aucun événement encore", async function () {
      const n = await nb();
      const corps = Buffer.from(JSON.stringify(MSG));
      const r = await transaction(adresse, { methode: "REQMOD", service: "/noortrace/reqmod", entetes: { ...IDENT, Allow: "204" }, req: reqHdr(corps, [["X-Noortrace-Run-Id", "run-icap-1"], ["X-Noortrace-Autre", "x"], ["Authorization", "Bearer cle-hote-fictive"]]), corps: [corps] });
      expect(r.statut).to.equal(200);
      expect(r.entetes.encapsulated).to.match(/^req-hdr=0, req-body=[0-9]+$/);
      const h = lireEntete(r.sections["req-hdr"]);
      expect(h.depart).to.equal("POST https://api.fournisseur.example/v1/messages HTTP/1.1");
      const noms = h.entetes.map(([x]) => x.toLowerCase());
      expect(noms).to.not.include.members(["x-noortrace-run-id", "x-noortrace-autre"]);
      expect(noms).to.include("authorization");
      const id = h.entetes.find(([x]) => x === "X-Noortrace-Exchange")[1];
      expect(id).to.match(/^[0-9a-f]{32}\.[0-9a-f]{32}$/);
      expect(r.corps.equals(corps)).to.equal(true);
      const pr = await piecesRequete({ format: "anthropic-messages", valeur: MSG, prompt_in_request: "reference", prompt_system: "redige", redacteur: new Redacteur({ politique: politiquePii(), fils: 0 }) });
      expect(fs.existsSync(coeur.pieces.chemin(pr.requete.sha256))).to.equal(true);
      expect(fs.existsSync(coeur.pieces.chemin(pr.prompt.sha256))).to.equal(true);
      expect(await nb()).to.equal(n);
      // RESPMOD avec la requête adaptée : l'échange est retrouvé par son identifiant, délégation déclarée comprise.
      obs = { echanges: [], refus: [] };
      const rep = Buffer.from(JSON.stringify(reponseEntiere("anthropic-messages", MSG, 2)));
      const r2 = await transaction(adresse, { methode: "RESPMOD", service: "/noortrace/respmod", entetes: IDENT, req: r.sections["req-hdr"], res: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n", corps: [rep] });
      expect(r2.statut).to.equal(200);
      expect(r2.entetes.encapsulated).to.match(/^res-hdr=0, res-body=[0-9]+$/);
      expect(r2.corps.equals(rep)).to.equal(true);
      const x = await attendre();
      expect(x.evenement.execution.arguments.sha256).to.equal(pr.requete.sha256);
      expect(x.evenement.delegation.run_id).to.equal("run-icap-1");
      expect(x.evenement.code.model).to.equal("anthropic/modele-icap");
      expect(x.mode).to.equal("icap");
    });

    it("identifiant au MAC faux : refusé (icap_exchange_refused) ; corrélation par méthode, URI et en-têtes ; sinon pièce noortrace_requete_inconnue", async function () {
      const a = await echange(serveur, { reqRespmod: null });
      void a;
      const corps = Buffer.from(JSON.stringify(MSG));
      // Identifiant forgé (forme valide, MAC faux), en-têtes de la requête d'origine : corrélation heuristique.
      obs = { echanges: [], refus: [] };
      const r1 = await transaction(adresse, { methode: "REQMOD", service: "/noortrace/reqmod", entetes: IDENT, req: reqHdr(corps, [["X-Trace", "t-1"]]), corps: [corps] });
      expect(r1.statut).to.equal(200);
      const forge = `${"a".repeat(32)}.${"b".repeat(32)}`;
      await transaction(adresse, { methode: "RESPMOD", service: "/noortrace/respmod", entetes: IDENT, req: reqHdr(corps, [["X-Trace", "t-1"], ["X-Noortrace-Exchange", forge]]), res: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n", corps: [Buffer.from(JSON.stringify(reponseEntiere("anthropic-messages", MSG, 3)))] });
      const x = await attendre();
      expect(derniere("icap_exchange_refused").data).to.deep.equal({ reason: "mac" });
      expect(derniere("icap_correlation_heuristique")).to.not.equal(undefined);
      expect(x.pieces.requete.sha256).to.not.equal(undefined);
      expect(JSON.parse(Buffer.from(await coeur.pieces.lire(x.evenement.execution.arguments.sha256)).toString("utf8")).messages).to.deep.equal(MSG.messages);
      // RESPMOD sans REQMOD retrouvé (en-têtes différents) : requête inconnue (EX-5.4).
      obs = { echanges: [], refus: [] };
      await transaction(adresse, { methode: "RESPMOD", service: "/noortrace/respmod", entetes: IDENT, req: reqHdr(corps, [["X-Trace", "jamais-vu"]]), res: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n", corps: [Buffer.from("{}")] });
      const y = await attendre();
      expect(JSON.parse(Buffer.from(await coeur.pieces.lire(y.evenement.execution.arguments.sha256)).toString("utf8"))).to.deep.equal({ noortrace_requete_inconnue: true });
      expect(derniere("icap_requete_inconnue")).to.not.equal(undefined);
      // Sans req-hdr, aucun moyen de connaître la route : rendue inchangée, non capturée, consignée.
      const n = await nb();
      const r3 = await transaction(adresse, { methode: "RESPMOD", service: "/noortrace/respmod", entetes: IDENT, res: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n", corps: [Buffer.from('{"a":1}')] });
      expect(r3.corps.toString()).to.equal('{"a":1}');
      await pause(100);
      expect(await nb()).to.equal(n);
      expect(derniere("icap_respmod_non_capture").data).to.deep.equal({ reason: "req_hdr_absent" });
    });

    it("blocages en REQMOD, réponse HTTP encapsulée et aucun événement : corps non analysable (400), comprimé (415), hôte inconnu (401), mode dégradé (503)", async function () {
      const n = await nb();
      const casse = Buffer.from('{"messages":[],"messages":[]}');
      const a = await transaction(adresse, { methode: "REQMOD", service: "/noortrace/reqmod", entetes: IDENT, req: reqHdr(casse), corps: [casse] });
      expect(a.entetes.encapsulated).to.match(/^res-hdr=0, res-body=[0-9]+$/);
      expect(lireEntete(a.sections["res-hdr"]).depart).to.equal("HTTP/1.1 400 Bad Request");
      expect(JSON.parse(a.corps.toString())).to.deep.equal({ type: "error", error: { type: "invalid_request_error", message: "noortrace: corps de requete non analysable" } });
      const corps = Buffer.from(JSON.stringify(MSG));
      const b = await transaction(adresse, { methode: "REQMOD", service: "/noortrace/reqmod", entetes: IDENT, req: reqHdr(corps, [["Content-Encoding", "gzip"]]), corps: [corps] });
      expect(lireEntete(b.sections["res-hdr"]).depart).to.equal("HTTP/1.1 415 Unsupported Media Type");
      const c = await transaction(adresse, { methode: "REQMOD", service: "/noortrace/reqmod", entetes: { "X-Client-IP": "192.0.2.7" }, req: reqHdr(corps), corps: [corps] });
      expect(lireEntete(c.sections["res-hdr"]).depart).to.equal("HTTP/1.1 401 Unauthorized");
      coeur.degrade.entrer("cle");
      try {
        const d = await transaction(adresse, { methode: "REQMOD", service: "/noortrace/reqmod", entetes: IDENT, req: reqHdr(corps), corps: [corps] });
        expect(lireEntete(d.sections["res-hdr"]).depart).to.equal("HTTP/1.1 503 Service Unavailable");
        expect(JSON.parse(d.corps.toString()).error.type).to.equal("noortrace_degrade");
      } finally {
        coeur.degrade.sortir("cle");
      }
      expect(await nb()).to.equal(n);
      expect(derniere("model_request_refused").data).to.include({ mode: "icap" });
      // Entrée « inconnu » déclarée : l'hôte sans adresse reconnue lui est rattaché (EX-5.8).
      const s = await ouvrir((cfg) => {
        cfg.model.hosts.push({ ...cfg.model.hosts[0], id: "inconnu", match: { source_addresses: ["192.0.2.0/24"] } });
        cfg.model.hosts[1].match = { source_addresses: ["198.51.100.0/24"] };
      });
      const r = await echange(s, { icap: { "X-Client-IP": "203.0.113.9" } });
      expect(r.r1.sections["req-hdr"]).to.match(/X-Noortrace-Exchange/);
      expect(r.echange.evenement).to.not.equal(null);
    });

    it("route gemini : chaîne de requête refusée (EX-5.29) et serveurs MCP ou cache déclarés au fournisseur (EX-5.32) bloqués en REQMOD, aucun événement ; « relayer » : consignés, échange capturé", async function () {
      const n = await nb();
      const g = (cible, corps) => enteteRequete(`POST https://api.fournisseur.example${cible} HTTP/1.1`, [["Host", "api.fournisseur.example"], ["Content-Type", "application/json"], ["Content-Length", String(corps.length)]]);
      const simple = Buffer.from(JSON.stringify({ contents: [{ role: "user", parts: [{ text: "x" }] }] }));
      const k = await transaction(adresse, { methode: "REQMOD", service: "/noortrace/reqmod", entetes: IDENT, req: g("/v1beta/models/gemini-x:generateContent?key=secret-colle", simple), corps: [simple] });
      expect(lireEntete(k.sections["res-hdr"]).depart).to.equal("HTTP/1.1 400 Bad Request");
      expect(JSON.parse(k.corps.toString()).error.status).to.equal("INVALID_ARGUMENT");
      expect(derniere("model_request_refused").data).to.deep.include({ raison: "cle_dans_url", mode: "icap", params: ["key"] });
      expect(k.corps.toString()).to.not.include("secret-colle");
      const f = await transaction(adresse, { methode: "REQMOD", service: "/noortrace/reqmod", entetes: IDENT, req: g("/v1beta/models/gemini-x:streamGenerateContent", simple), corps: [simple] });
      expect(lireEntete(f.sections["res-hdr"]).depart).to.equal("HTTP/1.1 400 Bad Request");
      expect(derniere("model_request_refused").data).to.include({ raison: "flux_sans_sse" });
      const mcp = Buffer.from(JSON.stringify({ contents: [{ role: "user", parts: [{ text: "x" }] }], tools: [{ mcpServers: [{ name: "s", streamableHttpTransport: { url: "https://mcp.exemple.test" } }] }] }));
      const m = await transaction(adresse, { methode: "REQMOD", service: "/noortrace/reqmod", entetes: IDENT, req: g("/v1beta/models/gemini-x:generateContent", mcp), corps: [mcp] });
      expect(lireEntete(m.sections["res-hdr"]).depart).to.equal("HTTP/1.1 400 Bad Request");
      expect(derniere("model_request_refused").data).to.include({ raison: "serveurs_mcp_fournisseur", entries: 1 });
      const cache = Buffer.from(JSON.stringify({ contents: [{ role: "user", parts: [{ text: "x" }] }], cachedContent: "cachedContents/abc" }));
      const c = await transaction(adresse, { methode: "REQMOD", service: "/noortrace/reqmod", entetes: IDENT, req: g("/v1beta/models/gemini-x:generateContent", cache), corps: [cache] });
      expect(lireEntete(c.sections["res-hdr"]).depart).to.equal("HTTP/1.1 400 Bad Request");
      expect(derniere("model_request_refused").data).to.include({ raison: "cache_fournisseur" });
      expect(await nb()).to.equal(n);
      // Route qui relaie : la déclaration est consignée, la requête modifiée porte l'identifiant.
      const s = await ouvrir((cfg) => {
        for (const r of cfg.policy.model.routes) if (r.format === "gemini") Object.assign(r, { provider_mcp: "relayer", provider_cache: "relayer" });
      });
      const r = await transaction(ad(s), { methode: "REQMOD", service: "/noortrace/reqmod", entetes: IDENT, req: g("/v1beta/models/gemini-x:generateContent", mcp), corps: [mcp] });
      expect(r.sections["req-hdr"]).to.match(/X-Noortrace-Exchange: [0-9a-f]{32}\.[0-9a-f]{32}/);
      expect(derniere("provider_mcp_bypass").data).to.include({ entries: 1, mode: "icap" });
      obs = { echanges: [], refus: [] };
      const rep = Buffer.from(JSON.stringify(reponseEntiere("gemini", {}, 1)));
      await transaction(ad(s), { methode: "RESPMOD", service: "/noortrace/respmod", entetes: IDENT, req: r.sections["req-hdr"], res: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n", corps: [rep] });
      const e = await attendre();
      expect(e.evenement.execution.is_error).to.equal(false);
      expect(await nb()).to.equal(n + 1);
    });

    it("quota de la connexion d'hôte atteint (EX-4.47 ; 14.2, ligne « Mémoire », colonne M) : 503 encapsulé en REQMOD, aucun événement", async function () {
      const n = await nb();
      const s = await ouvrir((cfg) => {
        cfg.model.hosts[0].quota.received_bytes_per_minute = 64;
      });
      const corps = Buffer.from(JSON.stringify(MSG));
      const r = await transaction(ad(s), { methode: "REQMOD", service: "/noortrace/reqmod", entetes: IDENT, req: reqHdr(corps), corps: [corps] });
      expect(lireEntete(r.sections["res-hdr"]).depart).to.equal("HTTP/1.1 503 Service Unavailable");
      expect(JSON.parse(r.corps.toString()).error.type).to.equal("noortrace_degrade");
      expect(derniere("call_blocked").data).to.deep.include({ code: 503, reason: "quota", class: "modele", limit_bytes: 64 });
      expect(await nb()).to.equal(n);
    });

    it("chemin hors des routes : requête rendue sans X-Noortrace-* ni identifiant, aucun événement", async function () {
      const corps = Buffer.from("{}");
      const r = await transaction(adresse, { methode: "REQMOD", service: "/noortrace/reqmod", entetes: IDENT, req: enteteRequete("POST https://ailleurs.example/v1/embeddings HTTP/1.1", [["Host", "ailleurs.example"], ["X-Noortrace-Run-Id", "r"], ["Content-Length", "2"]]), corps: [corps] });
      expect(r.statut).to.equal(200);
      expect(r.sections["req-hdr"]).to.not.match(/X-Noortrace/i);
      expect(derniere("model_route_not_found").data).to.include({ mode: "icap" });
    });

    it("une requête partie sans RESPMOD dans le délai du premier octet : échange is_error, pièce noortrace_timeout", async function () {
      const s = await ouvrir((c) => {
        c.model.first_byte_timeout_ms = 300;
      });
      obs = { echanges: [], refus: [] };
      const corps = Buffer.from(JSON.stringify(MSG));
      await transaction(ad(s), { methode: "REQMOD", service: "/noortrace/reqmod", entetes: IDENT, req: reqHdr(corps), corps: [corps] });
      const x = await attendre();
      expect(x.evenement.execution.is_error).to.equal(true);
      expect(JSON.parse(Buffer.from(await coeur.pieces.lire(x.evenement.execution.result.sha256)).toString()).noortrace_http_error.body).to.deep.equal({ noortrace_timeout: { phase: "premier_octet", timeout_ms: 300 } });
    });
  });

  describe("EX-5.5 : RESPMOD", function () {
    it("Preview : 100 Continue, puis la réponse entière ; Preview avec ieof : réponse directe ; jamais 204", async function () {
      const rep = Buffer.from(JSON.stringify(reponseEntiere("anthropic-messages", MSG, 5)));
      const a = await echange(serveur, { preview: 16, reponse: rep });
      expect(a.r2.statut).to.equal(200);
      expect(a.r2.corps.equals(rep)).to.equal(true);
      expect(a.echange.evenement.execution.is_error).to.equal(false);
      const b = await echange(serveur, { preview: 1 << 20, reponse: rep });
      expect(b.r2.statut).to.equal(200);
      expect(b.r2.corps.equals(rep)).to.equal(true);
    });

    it("flux SSE rendu morceau par morceau au fil de la réception, forme consolidée, inscrite au registre avant la fin", async function () {
      const ev = evenementsFlux("anthropic-messages", { ...MSG, stream: true }, 6).map((e) => Buffer.from(e));
      const temps = [];
      const t0 = Date.now();
      const r = await echange(serveur, { requete: { ...MSG, stream: true }, type: "text/event-stream", morceaux: ev, pauseMs: 40, surMorceau: () => temps.push(Date.now() - t0) });
      expect(r.r2.corps.toString()).to.equal(Buffer.concat(ev).toString());
      expect(temps.length).to.be.greaterThan(5);
      expect(temps[temps.length - 1] - temps[0], "le premier morceau n'attend pas la fin").to.be.greaterThan(300);
      expect(r.echange.consolidee.incomplet).to.equal(false);
      expect(r.echange.appels.map((a) => a.name)).to.deep.equal(["demo__claims_get"]);
    });

    it("le mandataire coupe au milieu d'un flux : forme incomplète, is_error (EX-5.13)", async function () {
      obs = { echanges: [], refus: [] };
      const corps = Buffer.from(JSON.stringify({ ...MSG, stream: true }));
      const r1 = await transaction(adresse, { methode: "REQMOD", service: "/noortrace/reqmod", entetes: IDENT, req: reqHdr(corps), corps: [corps] });
      const ev = evenementsFlux("anthropic-messages", MSG, 7).map((e) => Buffer.from(e));
      await transaction(adresse, { methode: "RESPMOD", service: "/noortrace/respmod", entetes: IDENT, req: r1.sections["req-hdr"], res: "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n", corps: ev.slice(0, 3), sansFin: true, couper: true }).catch(() => null);
      const x = await attendre();
      expect(x.evenement.execution.is_error).to.equal(true);
      expect(x.consolidee.forme[CLE_INCOMPLET]).to.equal(true);
    });

    it("statut d'erreur du fournisseur : réponse inchangée, événement is_error avec noortrace_http_error", async function () {
      const corpsErr = Buffer.from('{"type":"error","error":{"type":"overloaded_error","message":"x"}}');
      const r = await echange(serveur, { statut: 529, reponse: corpsErr });
      expect(r.r2.corps.equals(corpsErr)).to.equal(true);
      expect(r.echange.evenement.execution.is_error).to.equal(true);
    });
  });

  describe("EX-14.12 : pannes en mode ICAP", function () {
    it("colonne M en REQMOD (503 encapsulé, aucun événement) ; panne après le REQMOD : événement en attente, scellé ensuite", async function () {
      const sceller = coeur.scellerEchange.bind(coeur);
      coeur.scellerEchange = async () => {
        throw new ErreurEnregistreur("stockage", "panne de test");
      };
      let r;
      try {
        r = await echange(serveur);
      } finally {
        coeur.scellerEchange = sceller;
      }
      expect(r.r2.statut).to.equal(200);
      expect(r.echange.pendingId).to.match(/^p-/);
      const n = await nb();
      await coeur.viderAttente();
      expect(await nb()).to.equal(n + 1);
    });
  });

  describe("entrées hostiles", function () {
    async function brut(texte) {
      const s = await connecter(adresse);
      return new Promise((res) => {
        let x = "";
        s.on("data", (d) => (x += d));
        s.on("close", () => res(x));
        s.on("error", () => res(x));
        s.write(texte);
        setTimeout(() => s.destroy(), 1500);
      });
    }

    it("Encapsulated mal formé (décalages décroissants, entité inconnue, corps non dernier), en-tête de 64 Kio, chunk invalide, ligne invalide : 400 et connexion fermée", async function () {
      const debut = "REQMOD icap://127.0.0.1/noortrace/reqmod ICAP/1.0\r\nHost: x\r\n";
      for (const enc of ["req-hdr=10, req-body=5", "req-hdr=0, autre=5", "req-body=0, req-hdr=5", "req-hdr=0"]) {
        const r = await brut(`${debut}Encapsulated: ${enc}\r\n\r\n`);
        expect(r.split("\r\n")[0], enc).to.equal("ICAP/1.0 400 Bad Request");
        expect(r).to.match(/ISTag/);
      }
      expect((await brut(`${debut}X-Long: ${"a".repeat(70000)}\r\n\r\n`)).split("\r\n")[0]).to.equal("ICAP/1.0 400 Bad Request");
      const h = "POST /v1/messages HTTP/1.1\r\nHost: x\r\n\r\n";
      expect((await brut(`${debut}Encapsulated: req-hdr=0, req-body=${h.length}\r\n\r\n${h}zz\r\n`)).split("\r\n")[0]).to.equal("ICAP/1.0 400 Bad Request");
      expect((await brut("pas une requete icap\r\n\r\n")).split("\r\n")[0]).to.equal("ICAP/1.0 400 Bad Request");
    });

    it("connexion coupée au milieu d'un message, octets nuls : aucune réponse, le serveur reste disponible ; deux transactions sur une même connexion", async function () {
      await brut("REQMOD icap://127.0.0.1/noortrace/reqmod ICAP/1.0\r\nEncapsulated: req-hdr=0, req-body=500\r\n\r\nPOST");
      await brut(Buffer.alloc(100, 0).toString("latin1"));
      const s = await connecter(adresse);
      const a = await transaction(adresse, { prise: s, methode: "OPTIONS", service: "/noortrace/reqmod" });
      const b = await transaction(adresse, { prise: s, methode: "OPTIONS", service: "/noortrace/respmod" });
      expect([a.statut, b.entetes.methods]).to.deep.equal([200, "RESPMOD"]);
      s.end();
    });

    it("corps de requête au-delà de model_request_max_bytes : 413 encapsulé, connexion fermée", async function () {
      const s = await ouvrir((c) => {
        c.limits.model_request_max_bytes = 1024;
      });
      const corps = Buffer.from(JSON.stringify({ ...MSG, messages: [{ role: "user", content: "x".repeat(4000) }] }));
      const r = await transaction(ad(s), { methode: "REQMOD", service: "/noortrace/reqmod", entetes: IDENT, req: reqHdr(corps), corps: [corps] });
      expect(lireEntete(r.sections["res-hdr"]).depart).to.equal("HTTP/1.1 413 Payload Too Large");
    });
  });

  describe("mandataire du client : les quatre formats à travers REQMOD et RESPMOD", function () {
    it("chaque échange (flux et hors flux) est scellé, réponse rendue inchangée à l'agent", async function () {
      const m = await demarrerMandataire({ icap: adresse, fournisseur: fournisseur.url });
      const n = await nb();
      const cas = [
        ["/v1/messages", { ...MSG, stream: true }],
        ["/v1/chat/completions", { model: "m", messages: [{ role: "user", content: "x" }], stream: true }],
        ["/v1/responses", { model: "m", input: "x" }],
        ["/v1beta/models/gemini-x:streamGenerateContent?alt=sse", { contents: [{ role: "user", parts: [{ text: "x" }] }] }],
      ];
      for (const [chemin, corps] of cas) {
        const r = await fetch(`${m.url}${chemin}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(corps) });
        expect(r.status, chemin).to.equal(200);
        await r.text();
      }
      for (let i = 0; i < 100 && (await nb()) < n + 4; i++) await pause(20);
      const evts = (await lireEvenements(coeur.repertoire)).slice(n);
      expect(evts.map((e) => e.code.model)).to.deep.equal(["anthropic/modele-icap", "openai/m", "openai/m", "gemini/gemini-simule-001"]);
      expect(m.journal.every((t) => t.statut === 200)).to.equal(true);
      await m.arreter();
      void net;
    });
  });
});
