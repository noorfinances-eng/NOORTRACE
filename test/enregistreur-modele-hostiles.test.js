// Entrées hostiles du frontal modèle (CT-2 §5.4, EX-5.7, EX-5.13, EX-5.14,
// EX-5.18, EX-5.27, EX-7.1) : flux tronqués ou découpés à l'octet, événements
// SSE mal formés, index hors bornes, tailles et imbrications extrêmes,
// encodages invalides, en-têtes en double, fournisseur qui coupe ou répond
// n'importe quoi, client qui se déconnecte. Une donnée d'entrée n'est jamais
// une erreur de l'enregistreur : elle est ignorée et comptée, refusée avant
// relais, ou scellée comme échange en erreur.

import { expect } from "chai";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import http from "node:http";
import {
  AnalyseurSse, consoliderFlux, reassemblagePour, consoliderMorceauxGemini, indexAdmis, jcsIntegral, PasserelleModele, lireEvenements,
  CLE_INCOMPLET, CLE_ERREUR_FLUX, CLE_INPUT_INVALIDE,
} from "@noortrace/enregistreur";
import { VECTEURS_CT2, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { configurationModele, valider, demarrerCoeur, JETON_MODELE } from "./fixtures/enregistreur-modele/outils.mjs";
import { FournisseurSimule, evenementsFlux } from "./fixtures/enregistreur-modele/fournisseur.mjs";

const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const octets = (s) => new Uint8Array(Buffer.from(s, "utf8"));
const sse = (...donnees) => donnees.map((d) => `data: ${typeof d === "string" ? d : JSON.stringify(d)}\n\n`).join("");

function analyser(texte, o = {}) {
  const sortie = [];
  const comptes = [];
  const a = new AnalyseurSse({ final: o.final, distribuer: (t, d) => sortie.push([t, d]), compter: (q) => comptes.push(q) });
  for (const morceau of o.morceaux ?? [texte]) a.ecrire(typeof morceau === "string" ? octets(morceau) : morceau);
  a.terminer();
  return { sortie, comptes };
}

/** Clés `noortrace_*` d'une valeur, à toute profondeur (EX-5.18). */
function clesNoortrace(v, s = new Set()) {
  if (Array.isArray(v)) v.forEach((x) => clesNoortrace(x, s));
  else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) (k.startsWith("noortrace_") && s.add(k), clesNoortrace(x, s));
  return s;
}

describe("enregistreur, frontal modèle : entrées hostiles", function () {
  this.timeout(60000);

  describe("analyseur SSE (EX-5.14, EX-5.34)", function () {
    it("fins de ligne CRLF, LF, CR (y compris CR en fin de fragment), commentaires, champ sans « : », un seul espace retiré", function () {
      const { sortie, comptes } = analyser("", { morceaux: [": c\r\n", "event: a\r", "\ndata:  x\rdata:y\r", "\r", "id: 3\nretry: 9\ndata\n\nfoo: bar\n\n"] });
      // « data » seul ajoute une fin de ligne au tampon : l'événement porte une donnée vide.
      expect(sortie).to.deep.equal([["a", " x\ny"], ["message", ""]]);
      expect(comptes).to.include("commentaire");
    });

    it("un tampon `data` vide ne distribue rien ; type par défaut message ; données sur plusieurs lignes", function () {
      expect(analyser("event: e\n\nid: 1\n\ndata: a\ndata: b\n\n").sortie).to.deep.equal([["message", "a\nb"]]);
    });

    it("hors Gemini, une dernière ligne sans fin de ligne et un data sans ligne vide ne sont pas distribués ; Gemini les distribue (compté)", function () {
      expect(analyser('data: {"a":1}\n\ndata: {"b"').sortie).to.deep.equal([["message", '{"a":1}']]);
      expect(analyser('data: {"a":1}\ndata: {"b":2}', { final: true })).to.deep.equal({ sortie: [["message", '{"a":1}\n{"b":2}']], comptes: ["sse_data_final_sans_ligne_vide"] });
    });

    it("marque d'ordre d'octets initiale retirée, une seule ; UTF-8 invalide remplacé, jamais une erreur", function () {
      const bom = Buffer.from([0xef, 0xbb, 0xbf]);
      expect(analyser("", { morceaux: [bom, octets("data: x\n\n")] }).sortie).to.deep.equal([["message", "x"]]);
      expect(analyser("", { morceaux: [bom, octets("﻿data: x\n\n")] }).sortie).to.deep.equal([]);
      expect(analyser("", { morceaux: [Buffer.from([0x64, 0x61, 0x74, 0x61, 0x3a, 0x20, 0xff, 0xc3, 0x0a, 0x0a])] }).sortie).to.deep.equal([["message", "��"]]);
    });

    it("chaque transcription publiée, découpée à l'octet ou en morceaux arbitraires, donne la même forme consolidée", function () {
      const dirs = fs.readdirSync(path.join(VECTEURS_CT2, "pieces-modele")).filter((d) => fs.existsSync(path.join(VECTEURS_CT2, "pieces-modele", d, "reponse.sse")));
      expect(dirs.length).to.be.greaterThan(20);
      for (const d of dirs) {
        const a = JSON.parse(fs.readFileSync(path.join(VECTEURS_CT2, "pieces-modele", d, "attendu.json"), "utf8"));
        const o = new Uint8Array(fs.readFileSync(path.join(VECTEURS_CT2, "pieces-modele", d, "reponse.sse")));
        const entier = consoliderFlux(a.format, o);
        for (const taille of [1, 2, 7, 64]) {
          const r = reassemblagePour(a.format);
          const an = new AnalyseurSse({ final: a.format === "gemini", distribuer: (t, x) => r.donnee(t, x) });
          for (let i = 0; i < o.length; i += taille) an.ecrire(o.subarray(i, i + taille));
          an.terminer();
          expect(jcsIntegral(r.clore().forme), `${d}, morceaux de ${taille}`).to.equal(jcsIntegral(entier.forme));
        }
      }
    });
  });

  describe("réassemblages : événements mal formés, index hors bornes (EX-5.15 à EX-5.17, EX-5.27, EX-5.35)", function () {
    const debut = { type: "message_start", message: { id: "m", type: "message", role: "assistant", model: "x", content: [], stop_reason: null, usage: { input_tokens: 1 } } };

    it("index admis : nombre entier de 0 à 2^53 (1.0 admis, chaîne, négatif, fraction et 2^53+2 refusés)", function () {
      expect([0, 1.0, 2 ** 53, "0", -1, 1.5, 2 ** 53 + 2, null, true].map(indexAdmis)).to.deep.equal([0, 1, 2 ** 53, null, null, null, null, null, null]);
    });

    it("Anthropic : index au-delà de la longueur ignoré (pas d'amplification), bloc absent, delta mal typé, types inconnus comptés", function () {
      const c = consoliderFlux(
        "anthropic-messages",
        octets(sse(debut, { type: "content_block_start", index: 9007199254740992, content_block: { type: "text", text: "" } }, { type: "content_block_start", index: "0", content_block: {} }, { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "x" } }, { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }, { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: 5 } }, { type: "content_block_delta", index: 0, delta: { type: "inconnu" } }, { type: "nouveau_type" }, [1, 2], "pas du json", { type: "message_stop" })),
      );
      expect(c.forme.content).to.deep.equal([{ type: "text", text: "" }]);
      expect(c.ignores).to.equal(8);
      expect(c.incomplet).to.equal(false);
    });

    it("Anthropic : erreur avant message_start (forme réduite), objet avant message_start (incomplet), JSON d'outil invalide, citations, pensée, signature", function () {
      expect(consoliderFlux("anthropic-messages", octets(sse({ type: "error", error: { type: "overloaded_error" } }, debut))).forme).to.deep.equal({ [CLE_ERREUR_FLUX]: { type: "error", error: { type: "overloaded_error" } } });
      const avant = consoliderFlux("anthropic-messages", octets(sse({ type: "content_block_stop", index: 0 }, debut, { type: "message_stop" })));
      expect(avant.forme[CLE_INCOMPLET]).to.equal(true);
      const c = consoliderFlux(
        "anthropic-messages",
        octets(
          sse(
            debut,
            { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "t", name: "n", input: {} } },
            { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: '{"a":' } },
            { type: "content_block_stop", index: 0 },
            { type: "content_block_start", index: 1, content_block: { type: "thinking", thinking: "" } },
            { type: "content_block_delta", index: 1, delta: { type: "thinking_delta", thinking: "p" } },
            { type: "content_block_delta", index: 1, delta: { type: "signature_delta", signature: "s1" } },
            { type: "content_block_delta", index: 1, delta: { type: "signature_delta", signature: "s2" } },
            { type: "content_block_start", index: 2, content_block: { type: "text", text: "" } },
            { type: "content_block_delta", index: 2, delta: { type: "citations_delta", citation: { cited_text: "c" } } },
            { type: "message_delta", delta: { stop_reason: "end_turn" }, usage: { output_tokens: 3 } },
            { type: "message_stop" },
            { type: "content_block_start", index: 3, content_block: {} },
          ),
        ),
      );
      expect(c.forme.content).to.deep.equal([
        { type: "tool_use", id: "t", name: "n", input: {}, [CLE_INPUT_INVALIDE]: '{"a":' },
        { type: "thinking", thinking: "p", signature: "s2" },
        { type: "text", text: "", citations: [{ cited_text: "c" }] },
      ]);
      expect(c.forme.usage).to.deep.equal({ input_tokens: 1, output_tokens: 3 });
      expect(c.forme.stop_reason).to.equal("end_turn");
      expect([...clesNoortrace(c.forme)]).to.deep.equal([CLE_INPUT_INVALIDE]);
    });

    it("Chat Completions : un autre id arrête le réassemblage ; un null ne fixe rien ; aucun morceau : pas de forme", function () {
      const b = { id: "c1", object: "chat.completion.chunk", model: "m" };
      const c = consoliderFlux(
        "openai-chat",
        octets(
          sse(
            { ...b, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: null, function: { name: null, arguments: "{" } }] } }] },
            { ...b, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "a", type: "function", function: { name: "f", arguments: "}" } }] } }] },
            { ...b, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "b", function: { name: "g" } }] } }] },
            { ...b, id: "c2", choices: [{ index: 0, delta: { content: "intrus" } }] },
            "[DONE]",
          ),
        ),
      );
      expect(c.forme.choices[0].message).to.deep.equal({ role: "assistant", content: null, tool_calls: [{ index: 0, id: "a", type: "function", function: { name: "f", arguments: "{}" } }] });
      expect(c.forme[CLE_INCOMPLET]).to.equal(true);
      expect(consoliderFlux("openai-chat", octets("data: [DONE]\n\n")).forme).to.equal(null);
    });

    it("Responses : failed est une erreur ; error sans response : forme réduite ; rien d'interprétable : pas de forme", function () {
      const r = { id: "r", object: "response", status: "failed", output: [] };
      expect(consoliderFlux("openai-responses", octets(sse({ type: "response.failed", response: r }))).is_error).to.equal(true);
      expect(consoliderFlux("openai-responses", octets(sse({ type: "error", message: "x" }))).forme).to.deep.equal({ [CLE_ERREUR_FLUX]: { code: null, message: "x" } });
      expect(consoliderFlux("openai-responses", octets(sse({ type: "response.created", response: "pas un objet" }, { type: "x" }))).forme).to.equal(null);
    });

    it("Gemini : réponse sans candidat avec promptFeedback (fin normale), candidates et parts mal typés ignorés", function () {
      expect(consoliderFlux("gemini", octets(sse({ promptFeedback: { blockReason: "SAFETY" } }))).incomplet).to.equal(false);
      const c = consoliderFlux("gemini", octets(sse({ candidates: "x" }, { candidates: [1, { content: "x" }, { content: { parts: "x" } }, { content: { parts: [2, { text: "a" }] }, finishReason: "STOP" }] })));
      expect(c.forme.candidates).to.deep.equal([{ index: 0, content: { parts: [{ text: "a" }] }, finishReason: "STOP" }]);
      expect(c.ignores).to.equal(5);
      expect(consoliderMorceauxGemini([])).to.deep.include({ is_error: true, forme: { [CLE_INCOMPLET]: true } });
    });

    it("imbrication et largeur extrêmes dans une donnée : ignorées dans les bornes ; donnée de 2 Mio : consolidée", function () {
      const profond = `{"type":"message_start","message":${"[".repeat(500)}${"]".repeat(500)}}`;
      const c = consoliderFlux("anthropic-messages", octets(`data: ${profond}\n\n`));
      expect(c.forme).to.equal(null);
      const large = consoliderFlux("openai-chat", octets(sse({ id: "x", choices: Array.from({ length: 50 }, () => 1) })), { bornes: { profondeurMax: 128, membresMax: 10 } });
      expect(large.forme).to.equal(null);
      const gros = "y".repeat(2 * 1024 * 1024);
      const g = consoliderFlux("gemini", octets(sse({ candidates: [{ content: { parts: [{ text: gros }] }, finishReason: "STOP" }] })));
      expect(g.forme.candidates[0].content.parts[0].text.length).to.equal(gros.length);
    });

    it("seules les clés noortrace_flux_incomplet, noortrace_erreur_flux et noortrace_input_json_invalide sont ajoutées (EX-5.18)", function () {
      const autorisees = new Set([CLE_INCOMPLET, CLE_ERREUR_FLUX, CLE_INPUT_INVALIDE]);
      for (const d of fs.readdirSync(path.join(VECTEURS_CT2, "pieces-modele"))) {
        const f = path.join(VECTEURS_CT2, "pieces-modele", d, "reponse.sse");
        if (!fs.existsSync(f)) continue;
        const a = JSON.parse(fs.readFileSync(path.join(VECTEURS_CT2, "pieces-modele", d, "attendu.json"), "utf8"));
        const forme = consoliderFlux(a.format, new Uint8Array(fs.readFileSync(f)), { coupe: true }).forme;
        for (const k of clesNoortrace(forme)) expect(autorisees.has(k), `${d} : ${k}`).to.equal(true);
      }
    });
  });

  describe("passerelle", function () {
    let dir;
    let fournisseur;
    let coeur;
    let passerelle;
    let obs = [];
    const BASE = { "content-type": "application/json", "x-noortrace-token": JETON_MODELE };
    const MSG = { model: "m", max_tokens: 10, messages: [{ role: "user", content: "x" }] };

    before(async function () {
      dir = repertoireTemporaire("noortrace-modele-hostiles-");
      fournisseur = await new FournisseurSimule({ pauseMs: 1 }).demarrer();
      const c = configurationModele(dir, fournisseur.url);
      const v = valider(c.config, c.env);
      v.config.limits.json_max_depth = 16;
      ({ coeur } = await demarrerCoeur(v.config, v.secrets));
      passerelle = new PasserelleModele({ coeur, secrets: v.secrets, observateur: { echange: (x) => obs.push(x) } });
      await passerelle.ecouter();
    });

    after(async function () {
      await passerelle?.arreter();
      await coeur?.arreter();
      await fournisseur?.arreter();
    });

    afterEach(function () {
      fournisseur.scenarios.length = 0;
    });

    /** Requête brute : lignes d'en-tête écrites telles quelles. */
    function brute(texte) {
      return new Promise((res) => {
        const c = net.connect(passerelle.adresse().port, "127.0.0.1", () => c.write(texte));
        let recu = "";
        c.on("data", (d) => (recu += d));
        c.on("end", () => res(recu));
        c.on("close", () => res(recu));
        setTimeout(() => c.destroy(), 1500);
      });
    }

    async function envoyer(cible, o = {}) {
      obs = [];
      const r = await new Promise((res, rej) => {
        const q = http.request({ host: "127.0.0.1", port: passerelle.adresse().port, path: cible, method: "POST", headers: o.entetes ?? BASE }, (rep) => {
          const m = [];
          rep.on("data", (c) => m.push(c));
          rep.on("end", () => res({ statut: rep.statusCode, texte: Buffer.concat(m).toString("utf8") }));
          rep.on("error", () => res({ statut: rep.statusCode, coupe: true }));
        });
        q.on("error", rej);
        q.end(o.corps ?? JSON.stringify(MSG));
      });
      for (let i = 0; i < 300 && !obs.length && !o.sansEchange; i++) await pause(10);
      return { ...r, echange: obs[0] ?? null };
    }

    it("en-têtes d'authentification, de cadrage ou de délégation en double : 400, rien n'est relayé", async function () {
      const avant = fournisseur.requetes.length;
      const corps = JSON.stringify(MSG);
      for (const doublon of [`X-Noortrace-Token: ${JETON_MODELE}`, "Content-Type: application/json", "X-Noortrace-Run-Id: a", "x-api-key: k"]) {
        const r = await brute(`POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nX-Noortrace-Token: ${JETON_MODELE}\r\nX-Noortrace-Run-Id: b\r\nx-api-key: j\r\n${doublon}\r\nContent-Length: ${corps.length}\r\nConnection: close\r\n\r\n${corps}`);
        expect(r.split("\r\n")[0], doublon).to.equal("HTTP/1.1 400 Bad Request");
      }
      expect(fournisseur.requetes.length).to.equal(avant);
    });

    it("corps de requête : UTF-8 invalide, imbrication au-delà de json_max_depth, vide : 400 ; aucun événement", async function () {
      const n = (await lireEvenements(coeur.repertoire)).length;
      for (const corps of [Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]), `{"messages":${"[".repeat(20)}${"]".repeat(20)}}`, ""]) {
        expect((await envoyer("/v1/messages", { corps, sansEchange: true })).statut).to.equal(400);
      }
      expect((await lireEvenements(coeur.repertoire)).length).to.equal(n);
    });

    it("chemin avec octets nuls ou non ASCII, cible absolue : refusés sans relais", async function () {
      const avant = fournisseur.requetes.length;
      for (const cible of ["/v1/messages%00", "http://127.0.0.1/v1/messages", "*"]) {
        const r = await brute(`POST ${cible} HTTP/1.1\r\nHost: x\r\nX-Noortrace-Token: ${JETON_MODELE}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}`);
        expect(r.split("\r\n")[0], cible).to.match(/^HTTP\/1\.1 (400|404) /);
      }
      expect(fournisseur.requetes.length).to.equal(avant);
    });

    it("fournisseur qui ferme avant toute réponse : 504, événement is_error ; réponse HTTP illisible : idem", async function () {
      fournisseur.prochaine({ detruire: true });
      const a = await envoyer("/v1/messages");
      expect(a.statut).to.equal(504);
      expect(a.echange.evenement.execution.is_error).to.equal(true);
      // Un faux fournisseur qui répond des octets qui ne sont pas du HTTP.
      const faux = net.createServer((s) => s.on("data", () => s.end("ceci n'est pas du HTTP\r\n\r\n")));
      await new Promise((r) => faux.listen(0, "127.0.0.1", r));
      const p = new PasserelleModele({
        coeur,
        secrets: passerelle.secrets,
        config: { ...coeur.config, policy: { ...coeur.config.policy, model: { routes: coeur.config.policy.model.routes.map((r) => ({ ...r, upstream: `http://127.0.0.1:${faux.address().port}` })) } } },
        observateur: { echange: (x) => obs.push(x) },
      });
      await p.ecouter();
      obs = [];
      const r = await fetch(`http://127.0.0.1:${p.adresse().port}/v1/messages`, { method: "POST", headers: BASE, body: JSON.stringify(MSG) });
      expect(r.status).to.equal(504);
      for (let i = 0; i < 100 && !obs.length; i++) await pause(10);
      expect(obs[0].evenement.execution.is_error).to.equal(true);
      await p.arreter();
      faux.close();
    });

    it("flux d'octets aléatoires annoncé text/event-stream : relayé tel quel, pièce = flux brut, is_error", async function () {
      const bruit = Buffer.from(Array.from({ length: 4096 }, (_, i) => (i * 131 + 7) % 256));
      fournisseur.prochaine({ statut: 200, entetes: { "content-type": "text/event-stream" }, morceaux: [bruit] });
      const r = await envoyer("/v1/chat/completions", { corps: JSON.stringify({ model: "m", messages: [], stream: true }) });
      const e = r.echange.evenement;
      expect(e.execution.is_error).to.equal(true);
      expect(r.echange.incomplet).to.equal(true);
      expect(e.execution.result.redacted).to.equal(true);
      expect(JSON.parse(Buffer.from(await coeur.pieces.lire(e.execution.result.sha256)).toString("utf8"))).to.deep.equal({ noortrace_non_redigeable: { content_type: "text/event-stream", length: 4096, reason: "non_utf8" } });
    });

    it("Content-Encoding hostile du fournisseur (nom d'un membre d'objet, codages enchaînés) : pièce codage_inconnu, jamais une erreur", async function () {
      for (const ce of ["constructor", "__proto__", "toString", "gzip, br"]) {
        fournisseur.prochaine({ statut: 200, entetes: { "content-type": "application/json", "content-encoding": ce }, morceaux: ["{}"] });
        const r = await envoyer("/v1/messages");
        expect(r.statut, ce).to.equal(200);
        expect(JSON.parse(Buffer.from(await coeur.pieces.lire(r.echange.evenement.execution.result.sha256)).toString("utf8")).noortrace_non_redigeable.reason, ce).to.equal("codage_inconnu");
      }
    });

    it("corps de requête de plusieurs Mio au-delà de la borne : 413 rendu avant la fin de l'envoi, connexion fermée", async function () {
      const avant = fournisseur.requetes.length;
      const statut = await new Promise((res) => {
        const q = http.request({ host: "127.0.0.1", port: passerelle.adresse().port, path: "/v1/messages", method: "POST", headers: BASE }, (rep) => {
          res(rep.statusCode);
          rep.resume();
        });
        q.on("error", () => res("coupure sans réponse"));
        q.end(Buffer.alloc(40 * 1024 * 1024, 0x20));
      });
      expect(statut).to.equal(413);
      expect(fournisseur.requetes.length).to.equal(avant);
    });

    it("réponse JSON déclarée mais imbriquée au-delà des bornes : pièce non JSON, is_error", async function () {
      const corps = `{"a":${"[".repeat(40)}${"]".repeat(40)}}`;
      fournisseur.prochaine({ statut: 200, entetes: { "content-type": "application/json" }, morceaux: [corps] });
      const r = await envoyer("/v1/messages");
      expect(r.echange.evenement.execution.result).to.deep.include({ media_type: "application/json", length: corps.length });
      expect(r.echange.evenement.execution.is_error).to.equal(true);
    });

    it("coupure au milieu d'un caractère UTF-8 et d'un événement : forme incomplète, rien de plus", async function () {
      const ev = evenementsFlux("gemini", { contents: [] }, 1).join("");
      const b = Buffer.from(`${ev}data: {"candidates":[{"content":{"parts":[{"text":"é`, "utf8");
      fournisseur.prochaine({ statut: 200, entetes: { "content-type": "text/event-stream" }, morceaux: [b.subarray(0, b.length - 1)], couper: true });
      const r = await envoyer("/v1beta/models/g:streamGenerateContent?alt=sse", { corps: JSON.stringify({ contents: [] }) });
      void r;
      for (let i = 0; i < 100 && !obs.length; i++) await pause(10);
      const x = obs[0];
      expect(x.incomplet).to.equal(true);
      expect(x.consolidee.forme.candidates[0].content.parts.length).to.equal(3);
    });

    it("le client qui se déconnecte avant la réponse : connexion amont fermée, échange scellé is_error sans réponse", async function () {
      fournisseur.prochaine({ avantEntetesMs: 600, statut: 200, entetes: { "content-type": "application/json" }, morceaux: ["{}"] });
      obs = [];
      await new Promise((res) => {
        const q = http.request({ host: "127.0.0.1", port: passerelle.adresse().port, path: "/v1/messages", method: "POST", headers: BASE });
        q.on("error", () => res());
        q.end(JSON.stringify(MSG));
        setTimeout(() => {
          q.destroy();
          res();
        }, 150);
      });
      for (let i = 0; i < 200 && !obs.length; i++) await pause(10);
      const e = obs[0].evenement;
      expect(e.execution.is_error).to.equal(true);
      expect(e.execution.result).to.deep.include({ length: 0, media_type: "application/octet-stream" });
      await pause(700);
    });
  });
});
