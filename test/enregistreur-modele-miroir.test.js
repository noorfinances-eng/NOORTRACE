// Mode miroir du frontal modèle (CT-2 §5.1.3, EX-5.6, EX-5.8, EX-14.12), en
// réussite, en échec et contre des entrées hostiles : l'adaptateur de
// capture réassemble les transactions HTTP/1.1 d'une copie du trafic (flux
// de chaque sens d'une connexion, au fil de l'eau, découpé n'importe où) et
// remet chaque couple (requête, réponse) au démon par la prise locale ; le
// démon ne bloque rien, met en attente pendant un mode dégradé, et consigne
// ce qu'il perd.

import { expect } from "chai";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { RecepteurMiroir, AdaptateurMiroir, lancerAdaptateur, lireEvenements, CLE_INCOMPLET } from "@noortrace/enregistreur";
import { RACINE, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { configurationMiroir, valider, demarrerCoeur } from "./fixtures/enregistreur-modele/outils.mjs";
import { FournisseurSimule, evenementsFlux, reponseEntiere } from "./fixtures/enregistreur-modele/fournisseur.mjs";
import { demarrerCopie } from "./fixtures/enregistreur-modele/copie-miroir.mjs";

const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const MSG = { model: "modele-miroir", max_tokens: 32, system: "Agent miroir.", messages: [{ role: "user", content: "Statut ?" }] };
const b64 = (x) => Buffer.from(typeof x === "string" ? x : JSON.stringify(x)).toString("base64");
const BIN_MIROIR = path.join(RACINE, "paquets", "enregistreur", "bin", "noortrace-miroir");

function couple(o = {}) {
  return {
    version: 0,
    source: o.source ?? "127.0.0.1",
    t_requete: "2026-11-10T10:00:00.000Z",
    t_reponse: "2026-11-10T10:00:00.420Z",
    request: { method: "POST", target: o.cible ?? "/v1/messages", headers: o.entetesReq ?? [["Content-Type", "application/json"]], body: b64(o.requete ?? MSG) },
    response:
      o.reponse === null
        ? null
        : { status: o.statut ?? 200, headers: o.entetesRep ?? [["Content-Type", o.type ?? "application/json"], ["request-id", "req-miroir"]], body: b64(o.reponse ?? reponseEntiere("anthropic-messages", MSG, 1)), body_length: o.longueur, complete: o.complet ?? true },
  };
}

describe("enregistreur, frontal modèle : mode miroir (EX-5.6, EX-14.12)", function () {
  this.timeout(60000);
  let dir;
  let fournisseur;
  let coeur;
  let config;
  let recepteur;
  let obs = [];

  /** Envoie des lignes à la prise du démon et rend les réponses, une par couple. */
  async function envoyer(lignes, o = {}) {
    obs = [];
    const s = net.connect(o.socket ?? config.model.mirror.socket);
    await new Promise((r) => s.once("connect", r));
    const reponses = [];
    let tampon = "";
    s.on("data", (d) => {
      tampon += d;
      let k;
      while ((k = tampon.indexOf("\n")) >= 0) {
        reponses.push(JSON.parse(tampon.slice(0, k)));
        tampon = tampon.slice(k + 1);
      }
    });
    const ferme = new Promise((r) => s.on("close", r));
    s.on("error", () => {});
    for (const l of lignes) s.write(typeof l === "string" ? l : `${JSON.stringify(l)}\n`);
    for (let i = 0; i < 300 && reponses.length < (o.attendues ?? lignes.length); i++) await pause(10);
    s.end();
    if (o.fermeture) await ferme;
    return reponses;
  }

  const ops = () => fs.readFileSync(config.supervision.ops_log.path, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const derniere = (ev) => ops().filter((l) => l.event === ev).pop();
  const evts = () => lireEvenements(coeur.repertoire);

  before(async function () {
    dir = repertoireTemporaire("noortrace-modele-miroir-");
    fournisseur = await new FournisseurSimule({ pauseMs: 2 }).demarrer();
    const c = configurationMiroir(dir, fournisseur.url);
    const v = valider(c.config, c.env);
    config = v.config;
    ({ coeur } = await demarrerCoeur(config, v.secrets));
    recepteur = new RecepteurMiroir({ coeur, observateur: { echange: (x) => obs.push(x) } });
    await recepteur.ecouter();
  });

  after(async function () {
    await recepteur?.arreter();
    await coeur?.arreter();
    await fournisseur?.arreter();
  });

  describe("EX-5.6 : couples remis par l'adaptateur", function () {
    it("couple complet : échange scellé comme en passerelle, connexion d'hôte par l'adresse source, délégation déclarée lue sans pouvoir être retirée", async function () {
      const [r] = await envoyer([couple({ entetesReq: [["Content-Type", "application/json"], ["X-Noortrace-Run-Id", "run-miroir-1"]] })]);
      expect(r.ok).to.equal(true);
      const e = (await evts()).at(-1);
      expect(e.seq).to.equal(r.seq);
      expect(e.execution.tool).to.equal("noortrace.modele.echange");
      expect(e.code.model).to.equal("anthropic/modele-miroir");
      expect(e.execution.duration_ms).to.equal(420);
      expect(e.delegation).to.deep.include({ launched_by: "agent-modele", run_id: "run-miroir-1" });
      expect(e.execution.is_error).to.equal(false);
      expect(derniere("model_exchange_relayed").data.mode).to.equal("miroir");
    });

    it("is_error selon le statut HTTP observé ; réponse tronquée dans la copie : forme incomplète ; corps au-delà de la borne : pièce taille", async function () {
      const [a] = await envoyer([couple({ statut: 529, reponse: { type: "error", error: { type: "overloaded_error", message: "x" } } })]);
      const ea = (await evts()).find((x) => x.seq === a.seq);
      expect(ea.execution.is_error).to.equal(true);
      const flux = evenementsFlux("anthropic-messages", MSG, 2).slice(0, 4).join("");
      const [b] = await envoyer([couple({ type: "text/event-stream", reponse: flux, complet: false })]);
      const eb = (await evts()).find((x) => x.seq === b.seq);
      expect(eb.execution.is_error).to.equal(true);
      expect(JSON.parse(Buffer.from(await coeur.pieces.lire(eb.execution.result.sha256)).toString())[CLE_INCOMPLET]).to.equal(true);
      const [c] = await envoyer([couple({ longueur: 50000000 })]);
      const ec = (await evts()).find((x) => x.seq === c.seq);
      expect(JSON.parse(Buffer.from(await coeur.pieces.lire(ec.execution.result.sha256)).toString()).noortrace_non_redigeable.reason).to.equal("taille");
      // Aucune réponse dans la copie : échange en erreur, réponse vide.
      const [d] = await envoyer([couple({ reponse: null })]);
      const ed = (await evts()).find((x) => x.seq === d.seq);
      expect(ed.execution).to.deep.include({ is_error: true });
    });

    it("route gemini : serveurs MCP et cache déclarés au fournisseur (EX-5.32) et clé dans l'URL (EX-5.29) : rien n'est bloqué, déclarations consignées, échange scellé", async function () {
      const corps = { contents: [{ role: "user", parts: [{ text: "x" }] }], tools: [{ mcpServers: [{ name: "s" }] }], cachedContent: "cachedContents/abc" };
      const [r] = await envoyer([couple({ cible: "/v1beta/models/gemini-x:generateContent?key=secret-colle", requete: corps, reponse: reponseEntiere("gemini", corps, 1) })]);
      expect(r.ok).to.equal(true);
      const e = (await evts()).find((x) => x.seq === r.seq);
      expect(e.code.model).to.equal("gemini/gemini-simule-001");
      expect(derniere("provider_mcp_bypass").data).to.include({ entries: 1, mode: "miroir" });
      expect(derniere("provider_cache_reference").data).to.include({ mode: "miroir" });
      expect(fs.readFileSync(config.supervision.ops_log.path, "utf8")).to.not.include("secret-colle");
    });

    it("échecs sans événement, consignés : hôte inconnu, route inconnue, requête non analysable ou comprimée ; entrée « inconnu » déclarée", async function () {
      const n = (await evts()).length;
      const r = await envoyer([
        couple({ source: "192.0.2.4" }),
        couple({ cible: "/v1/embeddings" }),
        { ...couple(), request: { ...couple().request, body: b64('{"a":1,"a":2}') } },
        couple({ entetesReq: [["Content-Encoding", "gzip"]] }),
      ]);
      expect(r).to.deep.equal([
        { ok: false, reason: "hote_inconnu" },
        { ok: false, reason: "route_inconnue" },
        { ok: false, reason: "corps_non_analysable" },
        { ok: false, reason: "content_encoding" },
      ]);
      expect((await evts()).length).to.equal(n);
      expect(derniere("auth_failed").data).to.include({ transport: "miroir", reason: "hote_inconnu" });
      expect(derniere("model_request_refused").data).to.include({ mode: "miroir", raison: "content_encoding" });
      const s = new RecepteurMiroir({
        coeur,
        config: { ...config, model: { ...config.model, mirror: { socket: path.join(dir, "prise", "miroir-2.sock") }, hosts: [...config.model.hosts, { ...config.model.hosts[0], id: "inconnu", match: { source_addresses: ["198.51.100.0/24"] } }] } },
      });
      await s.ecouter();
      const [x] = await envoyer([couple({ source: "192.0.2.4" })], { socket: path.join(dir, "prise", "miroir-2.sock") });
      expect(x.ok).to.equal(true);
      await s.arreter();
    });
  });

  describe("EX-14.12 : le miroir ne bloque rien", function () {
    it("pendant un mode dégradé « clé », l'échange observé est mis en attente, puis scellé à la sortie", async function () {
      coeur.degrade.entrer("cle");
      let r;
      try {
        [r] = await envoyer([couple()]);
      } finally {
        coeur.degrade.sortir("cle");
      }
      expect(r).to.deep.equal({ ok: true, seq: null });
      expect(coeur.attente.length).to.equal(1);
      const n = (await evts()).length;
      await coeur.viderAttente();
      expect((await evts()).length).to.equal(n + 1);
    });

    it("au-delà des bornes de 14.5, l'échange est perdu et consigné (exchange_lost)", async function () {
      const max = coeur.config.policy.failure.pending_max_events;
      coeur.config.policy.failure.pending_max_events = 1;
      coeur.degrade.entrer("cle");
      try {
        await envoyer([couple(), couple()]);
      } finally {
        coeur.degrade.sortir("cle");
        coeur.config.policy.failure.pending_max_events = max;
      }
      expect(derniere("exchange_lost").data).to.deep.equal({ route: "/v1/messages", mode: "miroir" });
      coeur.degrade.sortir("attente");
      await coeur.viderAttente();
    });
  });

  describe("EX-4.47 en mode miroir", function () {
    it("un quota atteint ne bloque rien : l'échange observé est scellé (EX-5.6 : « Rien n'est bloqué »)", async function () {
      const sock = path.join(dir, "prise", "miroir-quota.sock");
      const s = new RecepteurMiroir({ coeur, config: { ...config, model: { ...config.model, mirror: { socket: sock }, hosts: config.model.hosts.map((h) => ({ ...h, quota: { ...h.quota, received_bytes_per_minute: 1, piece_bytes_per_minute: 1 } })) } } });
      await s.ecouter();
      const [a, b] = await envoyer([couple(), couple()], { socket: sock });
      expect([a.ok, b.ok]).to.deep.equal([true, true]);
      expect((await evts()).filter((x) => x.seq === a.seq || x.seq === b.seq).length).to.equal(2);
      await s.arreter();
    });
  });

  describe("entrées hostiles de la prise", function () {
    it("ligne illisible ou mal formée : refus ; ligne au-delà de la borne : connexion fermée ; le récepteur reste disponible", async function () {
      const r = await envoyer(["pas du json\n", { version: 1 }, { ...couple(), request: { ...couple().request, body: "pas_du_base64!" } }, { ...couple(), t_requete: "hier" }]);
      expect(r.map((x) => x.reason)).to.deep.equal(["couple_illisible", "couple_mal_forme", "couple_mal_forme", "couple_mal_forme"]);
      // Borne d'une ligne : corps des deux bornes en base64, plus 64 Kio (ici, bornes de 1 Kio).
      const sockBorne = path.join(dir, "prise", "miroir-borne.sock");
      const petit = new RecepteurMiroir({ coeur, config: { ...config, limits: { ...config.limits, model_request_max_bytes: 1024, model_response_max_bytes: 1024 }, model: { ...config.model, mirror: { socket: sockBorne } } } });
      await petit.ecouter();
      const s = net.connect(sockBorne);
      await new Promise((x) => s.once("connect", x));
      const ferme = new Promise((x) => s.on("close", x));
      s.on("error", () => {});
      const bloc = Buffer.alloc(1 << 16, 0x61);
      for (let i = 0; i < 4; i++) s.write(bloc);
      await ferme;
      await petit.arreter();
      expect(derniere("mirror_line_refused").data).to.deep.equal({ reason: "taille" });
      expect((await envoyer([couple()]))[0].ok).to.equal(true);
    });

    it("relecture B, R-B-11 (EX-18.1) : la prise du miroir a le mode 0660 dès sa création, sans fenêtre où elle serait plus ouverte", async function () {
      const sock = path.join(dir, "prise", "miroir-mode.sock");
      const r2 = new RecepteurMiroir({ coeur, config: { ...config, model: { ...config.model, mirror: { socket: sock } } } });
      // Mode relevé juste après la liaison de la prise, avant tout rappel (masque du processus ouvert).
      const origine = net.Server.prototype.listen;
      const modes = [];
      net.Server.prototype.listen = function (...a) {
        const x = origine.apply(this, a);
        if (a[0] === sock) modes.push(fs.statSync(sock).mode & 0o777);
        return x;
      };
      const masque = process.umask(0o000);
      try {
        await r2.ecouter();
      } finally {
        process.umask(masque);
        net.Server.prototype.listen = origine;
      }
      expect(modes).to.deep.equal([0o660]);
      expect(fs.statSync(sock).mode & 0o777).to.equal(0o660);
      await r2.arreter();
    });
  });

  describe("adaptateur de capture : réassemblage HTTP/1.1 de la copie", function () {
    function rejouer(flux, decoupe) {
      const couples = [];
      const a = new AdaptateurMiroir({ remettre: (c) => couples.push(c), borneReponse: 1 << 20 });
      for (const [sens, octets] of flux) {
        const o = Buffer.from(octets);
        for (let i = 0; i < o.length; i += decoupe) a.octets("c1", sens, o.subarray(i, i + decoupe), "127.0.0.1");
      }
      a.fin("c1");
      return couples;
    }

    const req = (corps) => `POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(corps)}\r\n\r\n${corps}`;
    const sse = evenementsFlux("anthropic-messages", MSG, 3).join("");
    const flux = [
      ["client", req(JSON.stringify(MSG))],
      ["serveur", "HTTP/1.1 100 Continue\r\n\r\n"],
      ["serveur", `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n{"ok":"oui"}`],
      ["client", req(JSON.stringify({ ...MSG, stream: true }))],
      ["serveur", `HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n${Buffer.byteLength(sse).toString(16)};ext=1\r\n${sse}\r\n0\r\nX-Remorque: 1\r\n\r\n`],
      ["client", "HEAD /v1/models HTTP/1.1\r\nHost: x\r\n\r\n"],
      ["serveur", "HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n"],
      ["client", req("{}")],
      ["serveur", "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: x\n\n"],
    ];

    it("Content-Length, chunked (extensions, remorque), réponse 100 ignorée, HEAD sans corps, corps jusqu'à la fermeture ; même résultat découpé à l'octet", function () {
      const entier = rejouer(flux, 1 << 20);
      expect(entier.map((c) => [c.request.method, c.response.status, Buffer.from(c.response.body, "base64").toString(), c.response.complete])).to.deep.equal([
        ["POST", 200, '{"ok":"oui"}', true],
        ["POST", 200, sse, true],
        ["HEAD", 200, "", true],
        ["POST", 200, "data: x\n\n", true],
      ]);
      expect(JSON.parse(Buffer.from(entier[1].request.body, "base64").toString()).stream).to.equal(true);
      expect(JSON.stringify(rejouer(flux, 1).map((c) => [c.request, c.response]))).to.equal(JSON.stringify(entier.map((c) => [c.request, c.response])));
    });

    it("copie coupée au milieu d'une réponse : couple incomplet ; requête sans réponse : couple sans réponse ; octets illisibles : aucun couple", function () {
      const coupe = rejouer([["client", req("{}")], ["serveur", "HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n{\"a\":"]], 1 << 20);
      expect(coupe[0].response.complete).to.equal(false);
      const seule = rejouer([["client", req("{}")]], 1 << 20);
      expect(seule[0].response).to.equal(null);
      expect(rejouer([["client", "\x00\x01\x02\r\n\r\n"], ["serveur", "n'importe quoi\r\n\r\n"]], 3)).to.deep.equal([]);
    });

    it("processus bin/noortrace-miroir : usage incorrect (code 2), prise du démon injoignable (code 1)", function () {
      expect(spawnSync(process.execPath, [BIN_MIROIR], { encoding: "utf8" }).status).to.equal(2);
      const r = spawnSync(process.execPath, [BIN_MIROIR, "--socket", path.join(dir, "absente.sock"), "--ecoute", "127.0.0.1:0"], { encoding: "utf8" });
      expect(r.status).to.equal(1);
      expect(r.stderr).to.match(/prise du démon injoignable/);
    });

    it("de bout en bout : agent → copie de l'équipement → adaptateur → démon, les quatre formats", async function () {
      const ad = await lancerAdaptateur({ socket: config.model.mirror.socket, ecoute: "127.0.0.1:0" });
      const copie = await demarrerCopie({ amont: fournisseur.url, adaptateur: { host: "127.0.0.1", port: ad.serveur.address().port } });
      const n = (await evts()).length;
      const cas = [
        ["/v1/messages", { ...MSG, stream: true }],
        ["/v1/chat/completions", { model: "m", messages: [{ role: "user", content: "x" }] }],
        ["/v1/responses", { model: "m", input: "x", stream: true }],
        ["/v1beta/models/gemini-x:generateContent", { contents: [{ role: "user", parts: [{ text: "x" }] }] }],
      ];
      for (const [chemin, corps] of cas) {
        const r = await fetch(`${copie.url}${chemin}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(corps) });
        expect(r.status).to.equal(200);
        await r.text();
      }
      for (let i = 0; i < 200 && (await evts()).length < n + 4; i++) await pause(20);
      const e = (await evts()).slice(n);
      expect(e.map((x) => x.code.model)).to.deep.equal(["anthropic/modele-miroir", "openai/m", "openai/m", "gemini/gemini-simule-001"]);
      expect(e.every((x) => x.execution.is_error === false)).to.equal(true);
      await copie.arreter();
      await ad.arreter();
    });
  });
});
