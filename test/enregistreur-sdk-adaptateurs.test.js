// Adaptateurs de cadres JavaScript du SDK `noortrace-sdk` (CT-2 6.6) :
// LangChain JavaScript (`langchain` 1.5.19, `@langchain/core` 1.3.0,
// `@langchain/mcp-adapters` 2.0.1) et SDK Agents d'OpenAI TypeScript
// (`@openai/agents` 0.21.0), contre le démon réel `bin/noortrace` (banc de
// test/fixtures/enregistreur-sdk-python/banc.mjs : point d'entrée SDK, frontal
// MCP en Streamable HTTP devant le serveur d'outils de test, service
// d'approbation simulé, passerelle devant le fournisseur simulé).
//
// Pour chaque adaptateur : les cinq essais obligatoires d'EX-6.20 — (i) démon
// arrêté, outil d'écriture non exécuté, « noortrace: enregistreur
// injoignable » ; (ii) `a_approuver`, signal d'approbation exact ; (iii)
// `debutAppel` a répondu avant le premier effet de l'outil (horloge
// monotone) ; (iv) agent réel, outil local et outil MCP passé par le frontal,
// exactement un événement par appel, journal accepté par `N.verifierJournal`
// et dossier valide pour le noyau et, si go1.27.3 est présent, pour le binaire
// Go ; (v) exception injectée dans le code de l'adaptateur, outil non
// exécuté — et les échanges observés (`modele: "declarer"`).

import { expect } from "chai";
import { performance } from "node:perf_hooks";
import { ClientNoortrace } from "noortrace-sdk";
import { TEXTE_INJOIGNABLE, TEXTE_ENTREE_INVALIDE } from "noortrace-sdk/adaptateurs";
import { middlewareNoortrace } from "noortrace-sdk/adaptateurs/langchain";
import { adaptateurAgentsOpenAI, argumentsDeclares } from "noortrace-sdk/adaptateurs/openai-agents";
import { lancerBanc } from "./fixtures/enregistreur-sdk-python/pilote.mjs";

const ALIAS = "agent-py";
const ARGS = { sinistre: "2026-77812", montant: "7400.00", devise: "CHF" };

/** Espion : instant (horloge monotone) où `debutAppel` a répondu, et les décisions rendues. */
function espionner(session) {
  const reel = session.debutAppel.bind(session);
  const e = { reponses: [], debuts: [] };
  session.debutAppel = async (p) => {
    const r = await reel(p);
    e.reponses.push(performance.now());
    e.debuts.push(r);
    return r;
  };
  return e;
}

const outilsDe = (evts, nom) => evts.filter((e) => e.execution.tool === nom);

async function attendreEchanges(banc, avant, n) {
  const fin = Date.now() + 10000;
  for (;;) {
    const nouveaux = (await banc.evenements()).slice(avant);
    if (outilsDe(nouveaux, "noortrace.modele.echange").length >= n || Date.now() > fin) return nouveaux;
    await new Promise((r) => setTimeout(r, 50));
  }
}

async function verifierParcours(banc, seq, nom) {
  const r = await banc.commande({ cmd: "verifier", seq, dossier: `${banc.info.dir}/dossier-js-${nom}` });
  expect(r.journal.valide, JSON.stringify(r.journal)).to.equal(true);
  expect(r.dossier.verdict, JSON.stringify(r.dossier)).to.equal("valide");
  if (r.go) {
    expect(r.go.status, r.go.stderr).to.equal(0);
    expect(r.go.verdict).to.equal("valide");
    expect(r.go.failed_checks).to.deep.equal([]);
  }
  console.log(`      noortrace-parcours ${nom} : journal ${r.journal.evenements} evenements valide ; dossier noyau ${r.dossier.verdict} ; binaire Go ${r.go ? r.go.verdict : "absent (go1.27.3 introuvable)"}`);
  return r;
}

describe("enregistreur, SDK : adaptateurs JavaScript (CT-2 6.6, EX-6.20)", function () {
  this.timeout(120000);
  let banc;

  before(async function () {
    banc = await lancerBanc();
  });

  after(async function () {
    await banc?.fermer();
  });

  // ------------------------------------------------------------ LangChain JavaScript

  describe("LangChain JavaScript 1.5.19 : intergiciel wrapToolCall", function () {
    let L;
    before(async function () {
      L = await import("langchain");
    });

    function outils(trace) {
      const { tool } = L;
      return [
        tool(async ({ sinistre }) => (trace.push(["preparer_paiement", performance.now()]), `ORD-${sinistre}`), { name: "preparer_paiement", description: "Prépare un ordre de paiement.", schema: { type: "object", properties: { sinistre: { type: "string" }, montant: { type: "string" }, devise: { type: "string" } }, required: ["sinistre"] } }),
        tool(async () => (trace.push(["approuver_paiement", performance.now()]), "paye"), { name: "approuver_paiement", description: "Paiement soumis à approbation.", schema: { type: "object", properties: { montant: { type: "string" } } } }),
        tool(async ({ sinistre }) => (trace.push(["lire_sinistre", performance.now()]), `sinistre ${sinistre} ouvert`), { name: "lire_sinistre", description: "Lit un sinistre.", schema: { type: "object", properties: { sinistre: { type: "string" } } } }),
        tool(async () => (trace.push(["outil__double", performance.now()]), "x"), { name: "outil__double", description: "Nom hors motif.", schema: { type: "object", properties: {} } }),
      ];
    }

    function modele(appels) {
      return new L.FakeToolCallingModel({ toolCalls: [...appels.map(([name, args], k) => [{ name, args, id: `call_${k}` }]), []] });
    }

    async function lancer(session, appels, trace, o = {}) {
      const mw = o.mw ?? middlewareNoortrace(session, { classes: { preparer_paiement: "ecriture", lire_sinistre: "lecture" }, ...(o.reglages ?? {}) });
      const agent = L.createAgent({ model: modele(appels), tools: [...outils(trace), ...(o.extra ?? [])], middleware: [mw] });
      const r = await agent.invoke({ messages: [{ role: "user", content: "Traite le sinistre 2026-77812." }] }, o.config ?? {});
      return { r, mw };
    }

    const recu = (r, id) => r.messages.find((m) => m.getType?.() === "tool" && m.tool_call_id === id);

    it("(i) démon arrêté : outil d'écriture non exécuté, « noortrace: enregistreur injoignable »", async function () {
      const trace = [];
      const session = await new ClientNoortrace({ socket: banc.info.socket, delaiMs: 2000, reprises: 0 }).ouvrir({ runId: "run-lcjs-i" });
      await banc.commande({ cmd: "arreter" });
      let r;
      try {
        ({ r } = await lancer(session, [["preparer_paiement", ARGS]], trace));
      } finally {
        await banc.commande({ cmd: "demarrer" });
      }
      expect(trace).to.deep.equal([]);
      const m = recu(r, "call_0");
      expect(m.content).to.equal(TEXTE_INJOIGNABLE);
      expect(m.status).to.equal("error");
    });

    it("(ii) a_approuver : outil non exécuté, signal d'approbation exact", async function () {
      const trace = [];
      const session = await new ClientNoortrace({ socket: banc.info.socket }).ouvrir({ runId: "run-lcjs-ii" });
      const e = espionner(session);
      const { r } = await lancer(session, [["approuver_paiement", { montant: "9100.00" }]], trace);
      await session.fermer();
      expect(trace).to.deep.equal([]);
      const d = e.debuts[0];
      expect(d.decision).to.equal("a_approuver");
      expect(d.ticket_state).to.equal("nouveau");
      expect(recu(r, "call_0").content).to.equal(`noortrace: appel soumis a approbation ; ticket=${d.ticket} ; state=nouveau`);
    });

    it("(iii) debutAppel a répondu avant le premier effet de l'outil", async function () {
      const trace = [];
      const session = await new ClientNoortrace({ socket: banc.info.socket }).ouvrir({ runId: "run-lcjs-iii" });
      const e = espionner(session);
      await lancer(session, [["preparer_paiement", ARGS]], trace);
      await session.fermer();
      expect(trace.length).to.equal(1);
      expect(e.reponses.length).to.equal(1);
      expect(e.reponses[0]).to.be.at.most(trace[0][1]);
    });

    it("(iv) agent réel : outil local et outil MCP par le frontal, un événement par appel ; journal et dossier vérifiés", async function () {
      const { MCPAdapter } = await import("@langchain/mcp-adapters");
      const trace = [];
      const avant = (await banc.evenements()).length;
      const session = await new ClientNoortrace({ socket: banc.info.socket }).ouvrir({ runId: "run-lcjs-iv" });
      // Ère héritée (`mode: "legacy"`) : en mode « auto », le client de l'ère 2026-07-28
      // attend l'accusé de `subscriptions/listen`, que le frontal MCP ne rend pas (LISEZMOI de noortrace-sdk, lecture 163).
      const mcp = new MCPAdapter({ mcpServers: { noortrace: { url: banc.info.mcp_url, mode: "legacy", headers: { Authorization: `Bearer ${banc.info.mcp_jeton}` } } }, prefixToolNameWithServerName: false });
      let r;
      try {
        const outilsMcp = await mcp.listTools();
        const noms = outilsMcp.map((t) => t.name);
        const claims = noms.find((n) => n.endsWith("claims.get"));
        expect(claims, JSON.stringify(noms)).to.be.a("string");
        // @langchain/mcp-adapters 2.0.1 ne marque pas l'origine MCP : liste `ignorer` (EX-6.17 (b)).
        ({ r } = await lancer(session, [["preparer_paiement", ARGS], [claims, { claim_id: "2026-77812" }], ["lire_sinistre", { sinistre: "2026-77812" }]], trace, {
          extra: outilsMcp,
          reglages: { ignorer: noms },
        }));
      } finally {
        await mcp.close?.();
        await session.fermer();
      }
      expect(trace.map((t) => t[0])).to.deep.equal(["preparer_paiement", "lire_sinistre"]);
      expect(JSON.stringify(recu(r, "call_1").content)).to.include("Sinistre 2026-77812 : ouvert");
      const nouveaux = (await banc.evenements()).slice(avant);
      const outilsEvt = nouveaux.map((e) => e.execution.tool).filter((t) => !t.startsWith("noortrace."));
      expect(outilsEvt.sort()).to.deep.equal([`${ALIAS}__lire_sinistre`, `${ALIAS}__preparer_paiement`, "demo__claims.get"].sort());
      const local = outilsDe(nouveaux, `${ALIAS}__preparer_paiement`)[0];
      expect(local.execution.status).to.equal("executee");
      expect(local.delegation.run_id).to.equal("run-lcjs-iv");
      await verifierParcours(banc, local.seq, "langchain-js");
    });

    it("(v) exception injectée dans le code de l'adaptateur : outil non exécuté", async function () {
      const trace = [];
      const session = await new ClientNoortrace({ socket: banc.info.socket }).ouvrir({ runId: "run-lcjs-v" });
      const mw = middlewareNoortrace(session, { classes: { preparer_paiement: "ecriture" } });
      mw.interne.preparer = () => {
        throw new Error("exception injectee dans l'adaptateur");
      };
      const { r } = await lancer(session, [["preparer_paiement", ARGS]], trace, { mw });
      await session.fermer();
      expect(trace).to.deep.equal([]);
      expect(recu(r, "call_0").content).to.equal(TEXTE_INJOIGNABLE);
    });

    it("nom hors du motif de 6.2 : non exécuté (EX-6.18) ; échanges déclarés par handleLLMEnd (modele: declarer)", async function () {
      const trace = [];
      const avant = (await banc.evenements()).length;
      const session = await new ClientNoortrace({ socket: banc.info.socket }).ouvrir({ runId: "run-lcjs-declarer" });
      const mw = middlewareNoortrace(session, { classes: { lire_sinistre: "lecture" }, modele: "declarer" });
      const { r } = await lancer(session, [["outil__double", {}]], trace, { mw, config: { callbacks: mw.rappels } });
      await mw.rappels[0].file.vide();
      await session.fermer();
      expect(trace).to.deep.equal([]);
      expect(recu(r, "call_0").content).to.equal(TEXTE_ENTREE_INVALIDE);
      const echanges = outilsDe((await banc.evenements()).slice(avant), "noortrace.modele.echange");
      expect(echanges.length).to.equal(2);
      expect(echanges.every((e) => e.context.length >= 1)).to.equal(true);
      expect(mw.rappels[0].file.echangesPerdus).to.equal(0);
    });
  });

  // ------------------------------------------------------------ SDK Agents d'OpenAI TypeScript

  describe("SDK Agents d'OpenAI 0.21.0 (TypeScript) : envelopperExecution", function () {
    let A;
    before(async function () {
      A = await import("@openai/agents");
      A.setTracingDisabled(true);
    });

    /** Modèle de test : un appel d'outil par tour, puis un message ; note ses entrées. */
    function modele(appels) {
      const vus = [];
      return {
        vus,
        recu(tour) {
          for (const entree of vus) {
            const sorties = (Array.isArray(entree) ? entree : []).filter((x) => x.type === "function_call_result");
            if (sorties.length > tour) {
              const o = sorties[tour].output;
              return typeof o === "string" ? o : (o?.text ?? JSON.stringify(o));
            }
          }
          throw new Error("résultat non reçu par le modèle");
        },
        async getResponse(req) {
          vus.push(Array.isArray(req.input) ? [...req.input] : req.input);
          const tour = (Array.isArray(req.input) ? req.input : []).filter((x) => x.type === "function_call_result").length;
          const output =
            tour < appels.length
              ? [{ type: "function_call", callId: `call_${tour}`, name: appels[tour][0], arguments: JSON.stringify(appels[tour][1]), status: "completed", id: `fc_${tour}` }]
              : [{ type: "message", role: "assistant", status: "completed", id: "msg_f", content: [{ type: "output_text", text: "fini" }] }];
          return { usage: new A.Usage(), output, responseId: undefined };
        },
        // eslint-disable-next-line require-yield
        async *getStreamedResponse() {
          throw new Error("non employé");
        },
      };
    }

    function outils(a, trace) {
      const { tool } = A;
      const z = { type: "object", properties: { sinistre: { type: "string" }, montant: { type: "string" }, devise: { type: "string" } }, required: ["sinistre", "montant", "devise"], additionalProperties: false };
      return [
        tool({ name: "preparer_paiement", description: "Prépare un ordre de paiement.", parameters: z, strict: true, execute: a.envelopperExecution("preparer_paiement", async ({ sinistre }) => (trace.push(["preparer_paiement", performance.now()]), `ORD-${sinistre}`)) }),
        tool({ name: "approuver_paiement", description: "Paiement soumis à approbation.", parameters: { type: "object", properties: { montant: { type: "string" } }, required: ["montant"], additionalProperties: false }, strict: true, execute: a.envelopperExecution("approuver_paiement", async () => (trace.push(["approuver_paiement", performance.now()]), "paye")) }),
        tool({ name: "lire_sinistre", description: "Lit un sinistre.", parameters: { type: "object", properties: { sinistre: { type: "string" } }, required: ["sinistre"], additionalProperties: false }, strict: true, execute: a.envelopperExecution("lire_sinistre", async ({ sinistre }) => (trace.push(["lire_sinistre", performance.now()]), `sinistre ${sinistre} ouvert`)) }),
      ];
    }

    const adaptateur = (session, o = {}) => adaptateurAgentsOpenAI(session, { classes: { preparer_paiement: "ecriture", lire_sinistre: "lecture" }, ...o });

    async function lancer(a, m, trace, o = {}) {
      const agent = new A.Agent({ name: "agent-sinistres", instructions: "Essai.", tools: outils(a, trace), mcpServers: o.mcpServers ?? [], model: m });
      return A.run(agent, "Traite le sinistre 2026-77812.");
    }

    it("(i) démon arrêté : outil d'écriture non exécuté, « noortrace: enregistreur injoignable »", async function () {
      const trace = [];
      const session = await new ClientNoortrace({ socket: banc.info.socket, delaiMs: 2000, reprises: 0 }).ouvrir({ runId: "run-oajs-i" });
      const m = modele([["preparer_paiement", ARGS]]);
      await banc.commande({ cmd: "arreter" });
      try {
        await lancer(adaptateur(session), m, trace);
      } finally {
        await banc.commande({ cmd: "demarrer" });
      }
      expect(trace).to.deep.equal([]);
      expect(m.recu(0)).to.equal(TEXTE_INJOIGNABLE);
    });

    it("(ii) a_approuver : outil non exécuté, signal d'approbation exact", async function () {
      const trace = [];
      const session = await new ClientNoortrace({ socket: banc.info.socket }).ouvrir({ runId: "run-oajs-ii" });
      const e = espionner(session);
      // Arguments distincts de ceux de l'essai LangChain : le service rattache une demande identique au même ticket.
      const m = modele([["approuver_paiement", { montant: "9200.00" }]]);
      await lancer(adaptateur(session), m, trace);
      await session.fermer();
      expect(trace).to.deep.equal([]);
      const d = e.debuts[0];
      expect(d.decision).to.equal("a_approuver");
      expect(m.recu(0)).to.equal(`noortrace: appel soumis a approbation ; ticket=${d.ticket} ; state=nouveau`);
    });

    it("(iii) debutAppel a répondu avant le premier effet de l'outil", async function () {
      const trace = [];
      const session = await new ClientNoortrace({ socket: banc.info.socket }).ouvrir({ runId: "run-oajs-iii" });
      const e = espionner(session);
      await lancer(adaptateur(session), modele([["preparer_paiement", ARGS]]), trace);
      await session.fermer();
      expect(trace.length).to.equal(1);
      expect(e.reponses[0]).to.be.at.most(trace[0][1]);
    });

    function chat(n, nom, args) {
      return { id: `chatcmpl-js-${n}`, object: "chat.completion", created: 1794306000, model: "modele-chat", choices: [{ index: 0, message: { role: "assistant", content: null, tool_calls: [{ id: `call_${n}`, type: "function", function: { name: nom, arguments: JSON.stringify(args) } }] }, finish_reason: "tool_calls" }], usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 } };
    }
    const FIN = { id: "chatcmpl-js-fin", object: "chat.completion", created: 1794306000, model: "modele-chat", choices: [{ index: 0, message: { role: "assistant", content: "fini" }, finish_reason: "stop" }], usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 } };

    it("(iv) agent réel par la passerelle : outil local et outil MCP par le frontal, un événement par appel ; journal et dossier vérifiés", async function () {
      const { default: OpenAI } = await import("openai");
      const trace = [];
      // Le SDK Agents remplace « . » par « _ » dans le nom d'un outil MCP vu par le modèle (getAllTools).
      await banc.commande({ cmd: "scenario", reponses: [chat(0, "preparer_paiement", ARGS), chat(1, "demo__claims_get", { claim_id: "2026-77812" }), chat(2, "lire_sinistre", { sinistre: "2026-77812" }), FIN] });
      const avant = (await banc.evenements()).length;
      const session = await new ClientNoortrace({ socket: banc.info.socket }).ouvrir({ runId: "run-oajs-iv" });
      const serveur = new A.MCPServerStreamableHttp({ url: banc.info.mcp_url, name: "noortrace", requestInit: { headers: { Authorization: `Bearer ${banc.info.mcp_jeton}` } }, cacheToolsList: true });
      await serveur.connect();
      let r;
      try {
        const m = new A.OpenAIChatCompletionsModel(new OpenAI({ baseURL: `${banc.info.passerelle_url}/v1`, apiKey: banc.info.passerelle_jeton, maxRetries: 0 }), "modele-chat");
        r = await lancer(adaptateur(session), m, trace, { mcpServers: [serveur] });
      } finally {
        await serveur.close();
        await session.fermer();
      }
      expect(r.finalOutput).to.equal("fini");
      expect(trace.map((t) => t[0])).to.deep.equal(["preparer_paiement", "lire_sinistre"]);
      const nouveaux = await attendreEchanges(banc, avant, 4);
      const outilsEvt = nouveaux.map((e) => e.execution.tool).filter((t) => !t.startsWith("noortrace."));
      expect(outilsEvt.sort()).to.deep.equal([`${ALIAS}__lire_sinistre`, `${ALIAS}__preparer_paiement`, "demo__claims.get"].sort());
      const echanges = outilsDe(nouveaux, "noortrace.modele.echange");
      expect(echanges.length).to.equal(4);
      expect(echanges.every((e) => e.context.length === 0)).to.equal(true);
      const local = outilsDe(nouveaux, `${ALIAS}__preparer_paiement`)[0];
      await verifierParcours(banc, local.seq, "openai-agents-ts");
    });

    it("(v) exception injectée dans le code de l'adaptateur : outil non exécuté", async function () {
      const trace = [];
      const session = await new ClientNoortrace({ socket: banc.info.socket }).ouvrir({ runId: "run-oajs-v" });
      const a = adaptateur(session);
      a.preparer = () => {
        throw new Error("exception injectee dans l'adaptateur");
      };
      const m = modele([["preparer_paiement", ARGS]]);
      await lancer(a, m, trace);
      await session.fermer();
      expect(trace).to.deep.equal([]);
      expect(m.recu(0)).to.equal(TEXTE_INJOIGNABLE);
    });

    it("arguments analysés en JSON strict ; échanges déclarés par le processeur de traces (modele: declarer)", async function () {
      const { default: OpenAI } = await import("openai");
      expect(argumentsDeclares('{"a":1}')).to.deep.equal({ a: 1 });
      expect(argumentsDeclares("pas du json")).to.equal("pas du json");
      const trace = [];
      await banc.commande({ cmd: "scenario", reponses: [chat(0, "lire_sinistre", { sinistre: "8" }), FIN] });
      const avant = (await banc.evenements()).length;
      const session = await new ClientNoortrace({ socket: banc.info.socket }).ouvrir({ runId: "run-oajs-declarer" });
      const a = adaptateur(session, { modele: "declarer" });
      A.setTraceProcessors([a.processeur]);
      A.setTracingDisabled(false);
      try {
        const m = new A.OpenAIChatCompletionsModel(new OpenAI({ baseURL: `${banc.info.passerelle_url}/v1`, apiKey: banc.info.passerelle_jeton, maxRetries: 0 }), "modele-chat");
        await lancer(a, m, trace);
      } finally {
        A.setTracingDisabled(true);
        A.setTraceProcessors([]);
      }
      await a.processeur.file.vide();
      await session.fermer();
      const echanges = outilsDe(await attendreEchanges(banc, avant, 4), "noortrace.modele.echange");
      const declares = echanges.filter((e) => e.context.length >= 1);
      expect(declares.length).to.equal(2);
      expect(declares.every((e) => e.code.model === "openai/modele-chat")).to.equal(true);
      expect(a.processeur.file.echangesPerdus).to.equal(0);
    });
  });
});
