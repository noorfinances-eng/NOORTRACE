// Exigences du SDK JavaScript `noortrace-sdk` (CT-2 6.5, EX-6.9 à EX-6.15),
// en réussite et en échec : contre le démon en processus (point d'entrée SDK
// réel) et contre des démons simulés sur une prise (protocole de 6.2 et de
// 4.7.1 : défi d'identité, lignes JSON-RPC), pour les cas qu'un démon conforme
// ne produit pas à la demande (silence, coupure après écriture). Écrit
// d'après le seul texte de CT-2.

import { expect } from "chai";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { spawn } from "node:child_process";
import { Worker } from "node:worker_threads";
import {
  ClientNoortrace, AppelNonAutorise, ErreurNoortrace, ErreurNoortraceIndisponible, ErreurNoortraceConfiguration, ErreurNoortraceDegrade,
  ErreurNoortraceLimite, ErreurNoortraceNonDurable, ErreurNoortraceEntreeInvalide, delaiReprise, estValeurJson, texteNonAutorise, PRISE_DEFAUT,
} from "noortrace-sdk";
import { FileEchanges } from "noortrace-sdk/adaptateurs";
import { repertoireTemporaire, RACINE } from "./fixtures/enregistreur-coeur/outils.mjs";
import { demarrerDemonSdk } from "./fixtures/enregistreur-sdk/outils.mjs";

/**
 * Démon simulé : défi d'identité accepté, puis `repondre(m)` pour chaque
 * ligne (objet JSON-RPC) : `{ result }`, `{ error }`, `"silence"` ou `"couper"`.
 */
async function demonSimule(repondre) {
  const dir = repertoireTemporaire("noortrace-sdk-simule-");
  const socket = path.join(dir, "s.sock");
  const recues = [];
  const prises = new Set();
  const serveur = net.createServer((c) => {
    prises.add(c);
    c.on("error", () => {});
    c.write(JSON.stringify({ noortrace_defi: "a".repeat(32) }) + "\n");
    let tampon = "";
    let identifie = false;
    c.on("data", (x) => {
      tampon += x;
      let k;
      while ((k = tampon.indexOf("\n")) >= 0) {
        const l = tampon.slice(0, k);
        tampon = tampon.slice(k + 1);
        const m = JSON.parse(l);
        if (!identifie) {
          identifie = true;
          fs.rmSync(path.join(dir, ".noortrace-defi-" + "a".repeat(32)), { force: true });
          c.write('{"noortrace_identite":"acceptee"}\n');
          continue;
        }
        recues.push(m);
        const r = repondre(m, recues);
        if (r === "silence") continue;
        if (r === "couper") {
          c.destroy();
          continue;
        }
        c.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, ...r }) + "\n");
      }
    });
  });
  await new Promise((r) => serveur.listen(socket, r));
  return {
    socket,
    recues,
    couper: () => prises.forEach((c) => c.destroy()),
    fermer: () => new Promise((r) => (prises.forEach((c) => c.destroy()), serveur.close(() => r()))),
  };
}

const OUVRIR = { result: { session: "s-1", org_id: "0x0", journal_id: "0x0", policy_version: "v" } };

describe("noortrace-sdk : SDK JavaScript (6.5, EX-6.9 à EX-6.15)", function () {
  this.timeout(60000);

  describe("EX-6.5, EX-6.9 : paquet, noms, valeurs rendues", function () {
    it("paquet npm noortrace-sdk, module ECMAScript, types inclus, Node.js 22 ou plus, sans dépendance", function () {
      const p = JSON.parse(fs.readFileSync(path.join(RACINE, "paquets/sdk-js/package.json"), "utf8"));
      expect(p.name).to.equal("noortrace-sdk");
      expect(p.type).to.equal("module");
      expect(p.engines.node).to.equal(">=22");
      expect(p.exports["."].types).to.equal("./src/index.d.ts");
      expect(fs.existsSync(path.join(RACINE, "paquets/sdk-js/src/index.d.ts"))).to.equal(true);
      expect(p.dependencies ?? {}).to.deep.equal({});
    });

    it("Debut porte exactement call, decision, ticket, ticket_state ; Scelle seq et hash ; Reference sha256, length, redacted", async function () {
      const d = await demarrerDemonSdk({});
      try {
        const s = await d.client().ouvrir({});
        const r = await s.declarerContexte({ kind: "autre", octets: new Uint8Array([1, 2, 3]) });
        expect(Object.keys(r).sort()).to.deep.equal(["length", "redacted", "sha256"]);
        const debut = await s.debutAppel({ tool: "lire", arguments: {}, classe: "lecture", contexte: [r.sha256] });
        expect(Object.keys(debut).sort()).to.deep.equal(["call", "decision", "ticket", "ticket_state"]);
        const fin = await s.finAppel(debut, { resultat: null, isError: false, durationMs: 0 });
        expect(Object.keys(fin).sort()).to.deep.equal(["hash", "seq"]);
        await s.fermer();
      } finally {
        await d.arreter();
      }
    });

    it("appelOutil : résultat rendu après l'événement durable ; valeur non JSON et exception transmises sous leurs formes, message jamais transmis", async function () {
      const d = await demarrerDemonSdk({});
      try {
        const s = await d.client().ouvrir({});
        let instantDebut = null;
        const v = await s.appelOutil({ tool: "lire", arguments: { id: 3 }, classe: "lecture" }, async (args) => {
          instantDebut = (await d.evenements()).length;
          return { lu: args.id };
        });
        expect(v).to.deep.equal({ lu: 3 });
        const e1 = (await d.evenements()).at(-1);
        expect(JSON.parse(Buffer.from(await d.coeur.pieces.lire(e1.execution.result.sha256)).toString())).to.deep.equal({ lu: 3 });
        expect(instantDebut).to.equal((await d.evenements()).length - 1);
        await s.appelOutil({ tool: "lire", arguments: {}, classe: "lecture" }, () => new Map([[1, 2]]));
        const e2 = (await d.evenements()).at(-1);
        expect(JSON.parse(Buffer.from(await d.coeur.pieces.lire(e2.execution.result.sha256)).toString())).to.deep.equal({ noortrace_sdk_non_json: "Map" });
        let err = null;
        try {
          await s.appelOutil({ tool: "lire", arguments: {}, classe: "lecture" }, () => {
            throw new TypeError("secret 4111111111111111");
          });
        } catch (e) {
          err = e;
        }
        expect(err).to.be.instanceOf(TypeError);
        const e3 = (await d.evenements()).at(-1);
        expect(e3.execution.is_error).to.equal(true);
        const piece = Buffer.from(await d.coeur.pieces.lire(e3.execution.result.sha256)).toString();
        expect(JSON.parse(piece)).to.deep.equal({ noortrace_sdk_exception: "TypeError" });
        expect(piece).to.not.contain("secret");
        expect(estValeurJson({ a: [1, "x", null, true] })).to.equal(true);
        for (const x of [undefined, () => 1, NaN, Infinity, 1n, new Date(0), { a: undefined }, [1, , 2]]) expect(estValeurJson(x)).to.equal(false);
        await s.fermer();
      } finally {
        await d.arreter();
      }
    });
  });

  describe("EX-6.10 : connexion", function () {
    it("ordre : constructeur, puis environnement, puis /run/noortrace/sdk.sock ; chemin de plus de 103 octets refusé à la construction", function () {
      const avant = { ...process.env };
      try {
        delete process.env.NOORTRACE_SDK_SOCKET;
        delete process.env.NOORTRACE_SDK_TCP;
        expect(new ClientNoortrace()._adresse.socket).to.equal(PRISE_DEFAUT);
        process.env.NOORTRACE_SDK_SOCKET = "/run/noortrace/env.sock";
        expect(ClientNoortrace.depuisEnvironnement()._adresse.socket).to.equal("/run/noortrace/env.sock");
        expect(new ClientNoortrace({ socket: "/run/noortrace/param.sock" })._adresse.socket).to.equal("/run/noortrace/param.sock");
        delete process.env.NOORTRACE_SDK_SOCKET;
        process.env.NOORTRACE_SDK_TCP = "127.0.0.1:7777";
        process.env.NOORTRACE_SDK_TOKEN = "j";
        expect(ClientNoortrace.depuisEnvironnement()._adresse.tcp).to.deep.equal({ hote: "127.0.0.1", port: 7777 });
        expect(() => new ClientNoortrace({ socket: "/" + "x".repeat(103) })).to.throw(ErreurNoortraceConfiguration);
        expect(() => new ClientNoortrace({ socket: "/" + "x".repeat(102) })).to.not.throw();
        delete process.env.NOORTRACE_SDK_TOKEN;
        expect(() => new ClientNoortrace({ tcp: "127.0.0.1:7777" })).to.throw(ErreurNoortraceConfiguration);
        expect(() => new ClientNoortrace({ tcp: "pas une adresse", jeton: "j" })).to.throw(ErreurNoortraceConfiguration);
        expect(() => new ClientNoortrace({ delaiMs: 0 })).to.throw(ErreurNoortraceConfiguration);
        expect(() => new ClientNoortrace({ surIndisponibiliteLecture: "parfois" })).to.throw(ErreurNoortraceConfiguration);
      } finally {
        for (const k of Object.keys(process.env)) if (!(k in avant)) delete process.env[k];
        Object.assign(process.env, avant);
      }
    });

    it("prise TCP : première ligne {\"noortrace_token\": …} ; id entiers croissants à partir de 1 ; connexion ouverte au premier appel seulement", async function () {
      const lignes = [];
      const prises = new Set();
      const serveur = net.createServer((c) => {
        prises.add(c);
        let t = "";
        c.on("data", (x) => {
          t += x;
          let k;
          while ((k = t.indexOf("\n")) >= 0) {
            const m = JSON.parse(t.slice(0, k));
            t = t.slice(k + 1);
            lignes.push(m);
            if ("noortrace_token" in m) c.write('{"noortrace_identite":"acceptee"}\n');
            else c.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, ...(m.method.endsWith("ouvrir") ? OUVRIR : { result: {} }) }) + "\n");
          }
        });
      });
      await new Promise((r) => serveur.listen(0, "127.0.0.1", r));
      try {
        const client = new ClientNoortrace({ tcp: `127.0.0.1:${serveur.address().port}`, jeton: "jeton-x" });
        await new Promise((r) => setTimeout(r, 50));
        expect(lignes).to.deep.equal([]);
        const s = await client.ouvrir({ runId: "r" });
        await s.fermer();
        expect(lignes[0]).to.deep.equal({ noortrace_token: "jeton-x" });
        expect(lignes.slice(1).map((m) => [m.id, m.method, m.jsonrpc])).to.deep.equal([[1, "noortrace/sdk/ouvrir", "2.0"], [2, "noortrace/sdk/fermer", "2.0"]]);
        expect(lignes[1].params).to.deep.equal({ run_id: "r", on_behalf_of: null });
      } finally {
        prises.forEach((c) => c.destroy());
        await new Promise((r) => serveur.close(r));
      }
    });
  });

  describe("EX-6.11 : ce qui bloque l'agent et ce qui ne le bloque jamais", function () {
    it("(1) chaque méthode attend au plus delaiMs : ErreurNoortraceIndisponible, envoyee vrai", async function () {
      const sim = await demonSimule((m) => (m.method.endsWith("ouvrir") ? OUVRIR : "silence"));
      try {
        const s = await new ClientNoortrace({ socket: sim.socket, delaiMs: 200 }).ouvrir({});
        const t0 = Date.now();
        let err = null;
        try {
          await s.debutAppel({ tool: "x", arguments: {}, classe: "ecriture" });
        } catch (e) {
          err = e;
        }
        expect(err).to.be.instanceOf(ErreurNoortraceIndisponible);
        expect(err.envoyee).to.equal(true);
        expect(Date.now() - t0).to.be.lessThan(2000);
      } finally {
        await sim.fermer();
      }
    });

    it("(2) appelOutil n'exécute jamais l'outil avant « autorise » ; (3) file des échanges observés bornée, la plus récente abandonnée et comptée, jamais d'erreur vers l'agent", async function () {
      const sim = await demonSimule((m) => {
        if (m.method.endsWith("ouvrir")) return OUVRIR;
        if (m.method.endsWith("debutAppel")) return { result: { call: null, decision: "a_approuver", ticket: "apr-1", ticket_state: "en_attente" } };
        if (m.method.endsWith("echangeModele")) return "silence";
        return { result: {} };
      });
      try {
        const s = await new ClientNoortrace({ socket: sim.socket, delaiMs: 300 }).ouvrir({});
        let execute = false;
        let err = null;
        try {
          await s.appelOutil({ tool: "payer", arguments: {} }, () => (execute = true));
        } catch (e) {
          err = e;
        }
        expect(execute).to.equal(false);
        expect(err).to.be.instanceOf(AppelNonAutorise);
        expect(err.texte).to.equal("noortrace: appel soumis a approbation ; ticket=apr-1 ; state=en_attente");
        const sortie = [];
        const file = new FileEchanges(s, { fileMax: 2, sortie: { write: (x) => sortie.push(x) } });
        const p = { format: "autre", providerLabel: "local", request: {}, response: {}, status: 200, durationMs: 1, isError: false };
        expect(file.ajouter(p)).to.equal(true);
        expect(file.ajouter(p)).to.equal(true);
        expect(file.ajouter(p)).to.equal(false);
        expect(file.echangesPerdus).to.equal(1);
        expect(sortie.join("")).to.contain("file des echanges pleine");
        // La requête écrite sans réponse n'est jamais renvoyée : abandonnée et comptée.
        await file.vide();
        expect(file.echangesPerdus).to.equal(3);
        expect(sim.recues.filter((m) => m.method.endsWith("echangeModele"))).to.have.length(2);
      } finally {
        await sim.fermer();
      }
    });

    it("(3) un échange que le démon injoignable n'a pas reçu (envoyee faux) reste en tête et est remis après la reprise de connexion", async function () {
      const d = await demarrerDemonSdk({});
      try {
        const s = await d.client({ reprises: 0, delaiMs: 2000 }).ouvrir({});
        await d.sdk.arreter();
        // Le client a constaté la perte avant l'ajout : la requête n'est pas écrite (envoyee faux).
        await new Promise((r) => setTimeout(r, 100));
        const file = new FileEchanges(s, { sortie: { write: () => {} } });
        const sortieFile = [];
      file.sortie = { write: (x) => sortieFile.push(x) };
      file.ajouter({ format: "autre", providerLabel: "local", request: { model: "m" }, response: {}, status: 200, durationMs: 1, isError: false });
        await new Promise((r) => setTimeout(r, 300));
        expect(file.file).to.have.length(1);
        const { demarrerSdk } = await import("@noortrace/enregistreur");
        d.sdk = await demarrerSdk(d.coeur, new Map(), {});
        await file.vide();
        expect(file.echangesPerdus, sortieFile.join("")).to.equal(0);
        expect((await d.evenements()).at(-1).code.model).to.equal("local/m");
      } finally {
        await d.arreter();
      }
    });

    it("(4) à la sortie du processus, fermer est tenté (borné à 2 s)", async function () {
      const d = await demarrerDemonSdk({});
      try {
        const script = `import { ClientNoortrace } from "noortrace-sdk";
          const s = await new ClientNoortrace({ socket: ${JSON.stringify(d.config.sdk.socket)} }).ouvrir({ runId: "sortie" });
          await s.debutAppel({ tool: "lire", arguments: {}, classe: "lecture" });`;
        const p = spawn(process.execPath, ["--input-type=module", "-e", script], { cwd: RACINE, stdio: "pipe" });
        const code = await new Promise((r) => p.on("exit", r));
        expect(code).to.equal(0);
        for (let k = 0; k < 50 && !d.lignes("sdk_session_closed").length; k++) await new Promise((r) => setTimeout(r, 20));
        expect(d.lignes("sdk_session_closed").map((l) => l.data.reason)).to.include("fermer");
      } finally {
        await d.arreter();
      }
    });
  });

  describe("EX-6.12 : erreurs", function () {
    it("chaque code donne sa classe et ses attributs ; toutes dérivent de ErreurNoortrace", async function () {
      const erreurs = {
        a: { code: -31010, message: "noortrace: appel bloque, enregistreur en mode degrade", data: { reason: "stockage" } },
        b: { code: -31013, message: "noortrace: taille maximale depassee", data: { limit_requests: 4, direction: "quota" } },
        c: { code: -31017, message: "noortrace: appel execute, evenement non durable", data: { intent_id: "i-1", reason: "cle" } },
        d: { code: -32602, message: "Invalid params", data: { reason: "tool_hors_motif" } },
        e: { code: -32601, message: "Method not found" },
      };
      const sim = await demonSimule((m) => (m.method.endsWith("ouvrir") ? OUVRIR : { error: erreurs[m.params.tool] }));
      try {
        const s = await new ClientNoortrace({ socket: sim.socket }).ouvrir({});
        const prendre = async (tool) => {
          try {
            await s.debutAppel({ tool, arguments: {} });
          } catch (e) {
            return e;
          }
          return null;
        };
        const a = await prendre("a");
        expect(a).to.be.instanceOf(ErreurNoortraceDegrade);
        expect(a.raison).to.equal("stockage");
        const b = await prendre("b");
        expect(b).to.be.instanceOf(ErreurNoortraceLimite);
        expect([b.direction, b.limite]).to.deep.equal(["quota", 4]);
        const c = await prendre("c");
        expect(c).to.be.instanceOf(ErreurNoortraceNonDurable);
        expect(c.intent_id).to.equal("i-1");
        const dd = await prendre("d");
        expect(dd).to.be.instanceOf(ErreurNoortraceEntreeInvalide);
        expect(dd.raison).to.equal("tool_hors_motif");
        const e = await prendre("e");
        expect(e.constructor).to.equal(ErreurNoortrace);
        expect([e.code, e.message]).to.deep.equal([-32601, "Method not found"]);
        for (const x of [a, b, c, dd, e, new AppelNonAutorise({ decision: "refuse", ticket: null, ticket_state: null }), new ErreurNoortraceConfiguration("x"), new ErreurNoortraceIndisponible("x", false)]) {
          expect(x).to.be.instanceOf(ErreurNoortrace);
        }
        expect(texteNonAutorise(null, null)).to.equal("noortrace: appel refuse par la politique");
        expect(texteNonAutorise("apr-1192", "expire")).to.equal("noortrace: appel soumis a approbation ; ticket=apr-1192 ; state=expire");
      } finally {
        await sim.fermer();
      }
    });
  });

  describe("EX-6.13 : reprise de connexion", function () {
    it("délai entre tentatives : min(0,5 × 2^n, 8) × (1 − 0,25 × u) secondes", function () {
      expect(delaiReprise(0, 0)).to.equal(500);
      expect(delaiReprise(1, 0)).to.equal(1000);
      expect(delaiReprise(5, 0)).to.equal(8000);
      expect(Math.abs(delaiReprise(2, 0.999) - 2000 * 0.75)).to.be.lessThan(1);
    });

    it("connexion perdue : la session est close par le démon (reprise de l'écriture ouverte) ; au premier appel qui suit, nouvelle session de même run_id ; référence de contexte perdue refusée sans envoi ; finAppel d'une session perdue non envoyé", async function () {
      const d = await demarrerDemonSdk({});
      try {
        const s = await d.client({ delaiMs: 5000 }).ouvrir({ runId: "run-reprise", onBehalfOf: "service-sinistres" });
        const id1 = s._id;
        const ref = await s.declarerContexte({ kind: "document", octets: "doc" });
        const ouvert = await s.debutAppel({ tool: "ecrire", arguments: { a: 1 }, classe: "ecriture" });
        // Le démon perd la connexion (redémarrage du point d'entrée).
        await d.sdk.arreter();
        const { demarrerSdk } = await import("@noortrace/enregistreur");
        d.sdk = await demarrerSdk(d.coeur, new Map(), {});
        // Le client ne sait la connexion perdue qu'une fois traité l'événement
        // `close` de sa prise, dans un tour de boucle ultérieur dont l'ordre par
        // rapport à la fin de `arreter` dépend de la machine : sans cette
        // attente, finAppel peut être écrit sur la prise morte et rendre, à
        // raison, `envoyee: true` (EX-6.13). Le cas éprouvé ici est celui d'une
        // perte constatée avant l'appel.
        for (let k = 0; k < 500 && !s._client._connexion?.perdue; k++) await new Promise((r) => setTimeout(r, 10));
        expect(s._client._connexion.perdue, "perte constatée par le client").to.equal(true);
        let e1 = null;
        try {
          await s.finAppel(ouvert, { resultat: null, isError: false, durationMs: 1 });
        } catch (e) {
          e1 = e;
        }
        expect(e1).to.be.instanceOf(ErreurNoortraceIndisponible);
        expect(e1.envoyee).to.equal(false);
        let e2 = null;
        try {
          await s.debutAppel({ tool: "lire", arguments: {}, classe: "lecture", contexte: [ref.sha256] });
        } catch (e) {
          e2 = e;
        }
        expect(e2).to.be.instanceOf(ErreurNoortraceEntreeInvalide);
        expect(e2.raison).to.equal("context_session_perdue");
        expect(s._id).to.not.equal(id1);
        const debut = await s.debutAppel({ tool: "lire", arguments: {}, classe: "lecture" });
        await s.finAppel(debut, { resultat: null, isError: false, durationMs: 0 });
        await s.fermer();
        const evts = await d.evenements();
        expect(evts.at(-1).delegation.run_id).to.equal("run-reprise");
        expect(evts.at(-1).delegation.on_behalf_of).to.equal("service-sinistres");
        // Arrêt du point d'entrée : pas de reprise à chaud (EX-12.15), l'intention reste pour la relecture.
        expect(evts.filter((e) => e.execution.tool === "agent-local__ecrire")).to.have.length(0);
      } finally {
        await d.arreter();
      }
    });

    it("une requête écrite sans réponse n'est jamais renvoyée ; seuls la connexion et ouvrir sont retentés", async function () {
      let n = 0;
      const sim = await demonSimule((m) => {
        if (m.method.endsWith("ouvrir")) return OUVRIR;
        n++;
        return "couper";
      });
      try {
        const s = await new ClientNoortrace({ socket: sim.socket, delaiMs: 2000 }).ouvrir({});
        let err = null;
        try {
          await s.debutAppel({ tool: "x", arguments: {}, classe: "ecriture" });
        } catch (e) {
          err = e;
        }
        expect(err).to.be.instanceOf(ErreurNoortraceIndisponible);
        expect(err.envoyee).to.equal(true);
        expect(n).to.equal(1);
        expect(sim.recues.filter((m) => m.method.endsWith("debutAppel"))).to.have.length(1);
      } finally {
        await sim.fermer();
      }
    });

    it("au plus 1 + reprises tentatives d'établissement", async function () {
      const dir = repertoireTemporaire("noortrace-sdk-absent-");
      const t0 = Date.now();
      let err = null;
      try {
        await new ClientNoortrace({ socket: path.join(dir, "absent.sock"), reprises: 1, delaiMs: 500 }).ouvrir({});
      } catch (e) {
        err = e;
      }
      expect(err).to.be.instanceOf(ErreurNoortraceIndisponible);
      expect(err.envoyee).to.equal(false);
      // n = 0 : au moins 375 ms entre les deux tentatives de la connexion, puis d'ouvrir.
      expect(Date.now() - t0).to.be.at.least(375);
    });

    it("au plus 1 + reprises connexions en tout, établissement et ouvrir compris (EX-6.13 ; relecture du lot SDK Python)", async function () {
      const dir = repertoireTemporaire("noortrace-sdk-coupe-");
      const prise = path.join(dir, "coupe.sock");
      let connexions = 0;
      // Démon qui accepte puis ferme aussitôt : chaque tentative échoue.
      const serveur = net.createServer((c) => {
        connexions++;
        c.destroy();
      });
      await new Promise((r) => serveur.listen(prise, r));
      try {
        let err = null;
        try {
          await new ClientNoortrace({ socket: prise, reprises: 2, delaiMs: 500 }).ouvrir({});
        } catch (e) {
          err = e;
        }
        expect(err).to.be.instanceOf(ErreurNoortraceIndisponible);
        expect(connexions).to.equal(3);
      } finally {
        await new Promise((r) => serveur.close(r));
      }
    });
  });

  describe("EX-6.14 : fils et asynchrone", function () {
    it("chaque Worker a son propre client", async function () {
      const d = await demarrerDemonSdk({});
      try {
        const w = new Worker(
          `import { parentPort, workerData } from "node:worker_threads";
           import { ClientNoortrace } from "noortrace-sdk";
           const s = await new ClientNoortrace({ socket: workerData }).ouvrir({ runId: "worker" });
           const d = await s.debutAppel({ tool: "lire", arguments: {}, classe: "lecture" });
           const f = await s.finAppel(d, { resultat: null, isError: false, durationMs: 0 });
           await s.fermer();
           parentPort.postMessage(f.seq);`,
          { eval: true, workerData: d.config.sdk.socket },
        );
        const seq = await new Promise((r, x) => (w.once("message", r), w.once("error", x)));
        expect((await d.evenements()).find((e) => e.seq === seq).delegation.run_id).to.equal("worker");
      } finally {
        await d.arreter();
      }
    });
  });

  describe("EX-6.15 : démon injoignable", function () {
    it("écriture jamais exécutée ; lecture non exécutée par défaut (bloquer), exécutée sans événement avec « executer »", async function () {
      const sim = await demonSimule((m) => (m.method.endsWith("ouvrir") ? OUVRIR : { error: { code: -31010, message: "noortrace: appel bloque, enregistreur en mode degrade", data: { reason: "cle" } } }));
      const sortie = [];
      const ecrire = process.stderr.write;
      try {
        const bloquer = await new ClientNoortrace({ socket: sim.socket }).ouvrir({});
        const executer = await new ClientNoortrace({ socket: sim.socket, surIndisponibiliteLecture: "executer" }).ouvrir({});
        const executions = [];
        for (const [s, classe] of [[bloquer, "ecriture"], [executer, "ecriture"], [executer, undefined], [bloquer, "lecture"]]) {
          let err = null;
          try {
            await s.appelOutil({ tool: "t", arguments: {}, classe }, () => executions.push(classe));
          } catch (e) {
            err = e;
          }
          expect(err, String(classe)).to.be.instanceOf(ErreurNoortraceDegrade);
        }
        expect(executions).to.deep.equal([]);
        process.stderr.write = (x) => (sortie.push(String(x)), true);
        const v = await executer.appelOutil({ tool: "t", arguments: { k: 1 }, classe: "lecture" }, (a) => a.k + 1);
        process.stderr.write = ecrire;
        expect(v).to.equal(2);
        expect(sortie.join("")).to.contain("execute sans evenement");
        expect(sim.recues.filter((m) => m.method.endsWith("finAppel"))).to.have.length(0);
      } finally {
        process.stderr.write = ecrire;
        await sim.fermer();
      }
    });
  });
});
