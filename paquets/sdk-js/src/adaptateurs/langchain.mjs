// Adaptateur LangChain JavaScript (CT-2 6.6, ligne « LangChain 1.5.19 (JavaScript) »).
//
// Point d'interception : l'intergiciel `wrapToolCall` (`langchain` 1.5.19,
// `dist/agents/middleware/types.d.ts` L352), créé par `createMiddleware` et
// passé **en dernier** à `createAgent({ model, tools, middleware: [...] })` :
// `chainToolCallHandlers` fait du premier de la liste la couche la plus
// externe (`dist/agents/utils.js`), le dernier voit les arguments après toute
// réécriture par un autre intergiciel.
//
// - Déclaré à `debutAppel` : `request.toolCall.name`, `request.toolCall.args`,
//   la classe de `classes` ou `null`.
// - Outil non exécuté : `new ToolMessage({ content: <texte>, tool_call_id,
//   status: "error" })`, sans appeler `handler` : la forme du résultat
//   d'erreur que le `ToolNode` du cadre construit lui-même
//   (`dist/agents/nodes/ToolNode.js` L32-L45) (LISEZMOI du paquet, lecture 163).
// - Déclaré à `finAppel` : `content` du `ToolMessage` rendu par `handler`,
//   `isError` = `status === "error"` ; un `Command` : `{"noortrace_sdk_non_json": "Command"}`.
// - Outil MCP (EX-6.17) : `@langchain/mcp-adapters` 2.0.1 ne pose aucune marque
//   d'origine MCP (`dist/tools.js` L207-L212 : `metadata: { annotations }`) :
//   seule la liste `ignorer` les écarte.
// - Échanges de modèle (`modele: "declarer"`) : gestionnaire de rappels
//   `middleware.rappels` (`handleChatModelStart`, `handleLLMStart`,
//   `handleLLMEnd`), exécuté en tâche de fond sans `awaitHandlers`, point
//   d'observation, file d'EX-6.11 (3), format `autre` ; à passer dans
//   `{ callbacks: middleware.rappels }`.

import { createMiddleware, ToolMessage } from "langchain";
import { BaseCallbackHandler } from "@langchain/core/callbacks/base";
import { FileEchanges, TEXTE_INJOIGNABLE, intercepter, reglagesAdaptateur, valeurDeclaree, etiquette } from "../adaptateurs.mjs";

/**
 * Gestionnaire de rappels de modèle (R12-F13) : requête vue au départ, réponse par
 * `handleLLMEnd` ; une erreur n'atteint jamais l'agent.
 */
export class GestionnaireEchangesNoortrace extends BaseCallbackHandler {
  name = "GestionnaireEchangesNoortrace";

  /** @param {object} session @param {{fileMax?: number}} [o] */
  constructor(session, o = {}) {
    super({ raiseError: false });
    this.file = new FileEchanges(session, { fileMax: o.fileMax ?? 1000 });
    this.debuts = new Map();
  }

  _modele(llm, extra) {
    const p = extra?.invocation_params ?? {};
    const m = p.model ?? p.model_name ?? p.modelName ?? llm?.kwargs?.model ?? llm?.kwargs?.model_name;
    return { modele: typeof m === "string" ? m : null, label: etiquette(p._type ?? llm?.id?.at?.(-1)) };
  }

  handleChatModelStart(llm, messages, runId, parentRunId, extra) {
    try {
      const { modele, label } = this._modele(llm, extra);
      const requete = { ...(modele ? { model: modele } : {}), messages: messages.map((liste) => liste.map((m) => valeurDeclaree(JSON.parse(JSON.stringify(m.toDict ? m.toDict() : m))))) };
      this.debuts.set(runId, { t0: performance.now(), label, requete: valeurDeclaree(requete) });
    } catch {
      /* jamais propagé */
    }
  }

  handleLLMStart(llm, prompts, runId, parentRunId, extra) {
    try {
      const { modele, label } = this._modele(llm, extra);
      this.debuts.set(runId, { t0: performance.now(), label, requete: { ...(modele ? { model: modele } : {}), prompts: [...prompts] } });
    } catch {
      /* jamais propagé */
    }
  }

  handleLLMEnd(output, runId) {
    try {
      const d = this.debuts.get(runId) ?? { t0: performance.now(), label: "local", requete: {} };
      this.debuts.delete(runId);
      let reponse;
      try {
        reponse = JSON.parse(JSON.stringify(output));
      } catch {
        reponse = { noortrace_sdk_non_json: "LLMResult" };
      }
      this.file.ajouter({ format: "autre", providerLabel: d.label, request: d.requete, response: valeurDeclaree(reponse), status: null, durationMs: Math.max(0, Math.floor(performance.now() - d.t0)), isError: false });
    } catch {
      /* jamais propagé */
    }
  }
}

/**
 * Intergiciel NOORTRACE : `middlewareNoortrace(session, { classes, modele = "passerelle", ignorer })`.
 * @param {object} session session de `noortrace-sdk`
 * @param {{classes?: Record<string, "lecture"|"ecriture">, modele?: "passerelle"|"declarer", ignorer?: string[]}} [o]
 */
export function middlewareNoortrace(session, o = {}) {
  const r = reglagesAdaptateur(o);
  const interne = {
    preparer(request) {
      const nom = request.toolCall.name;
      return { nom, args: request.toolCall.args ?? {}, classe: r.classes[nom] ?? null };
    },
    declarer(v) {
      if (v instanceof ToolMessage || (v && typeof v === "object" && v.getType?.() === "tool")) return { resultat: valeurDeclaree(v.content), isError: v.status === "error" };
      return { resultat: { noortrace_sdk_non_json: v?.constructor?.name ?? typeof v }, isError: false };
    },
    erreur(request, texte) {
      return new ToolMessage({ content: texte, tool_call_id: request.toolCall.id, name: request.toolCall.name, status: "error" });
    },
  };
  const mw = createMiddleware({
    name: "MiddlewareNoortrace",
    wrapToolCall: async (request, handler) => {
      let passer;
      try {
        passer = r.ignorer.has(request.toolCall.name);
      } catch {
        return interne.erreur(request, TEXTE_INJOIGNABLE);
      }
      if (passer) return handler(request);
      const issue = await intercepter(session, () => interne.preparer(request), () => handler(request), (v) => interne.declarer(v));
      return issue.texte !== null ? interne.erreur(request, issue.texte) : issue.valeur;
    },
  });
  // Accès des essais et des intégrations : rappels d'observation, fonctions internes.
  Object.defineProperty(mw, "rappels", { value: r.modele === "declarer" ? [new GestionnaireEchangesNoortrace(session)] : [], enumerable: false });
  Object.defineProperty(mw, "interne", { value: interne, enumerable: false });
  return mw;
}
