// Adaptateur du SDK Agents d'OpenAI, TypeScript (CT-2 6.6, ligne « SDK Agents
// d'OpenAI 0.21.0 (TypeScript) »).
//
// Point d'interception : l'intégration enveloppe la fonction `execute` qu'elle
// passe à `tool({…})` par `envelopperExecution(nom, execute)`, sans toucher au
// cadre ; `needsApproval` (`@openai/agents-core` 0.21.0, `dist/tool.d.ts`
// L247) n'est pas employé. `execute(input, context, details)` reçoit les
// arguments déjà analysés par le cadre (`dist/tool.d.ts` L649, L656) ; une
// chaîne (outil sans schéma) est analysée en JSON strict, à défaut déclarée
// telle quelle.
//
// - Outil non exécuté : la chaîne du texte d'EX-6.19, valeur rendue par `execute`.
// - Déclaré à `finAppel` : les arguments ; la valeur rendue par `execute` d'origine.
// - Outils MCP (EX-6.17) : les outils de `mcpServers` ne passent pas par
//   `envelopperExecution` ; un nom de `ignorer` non plus.
// - Échanges de modèle (`modele: "declarer"`) : `processeur`, à enregistrer
//   par `addTraceProcessor` (R12-F35), `onSpanEnd` des spans `generation` et
//   `response` (`dist/tracing/spans.d.ts` L46-L72) ; point d'observation, file
//   d'EX-6.11 (3), format `autre`.

import { FileEchanges, intercepter, reglagesAdaptateur, valeurDeclaree } from "../adaptateurs.mjs";

/** Arguments déclarés : objet tel quel ; chaîne analysée en JSON strict, sinon déclarée telle quelle. */
export function argumentsDeclares(input) {
  if (typeof input !== "string") return valeurDeclaree(input === undefined ? null : input);
  try {
    return JSON.parse(input);
  } catch {
    return input;
  }
}

/** Processeur de traces : échanges observés (`generation`, `response`) mis dans la file d'EX-6.11 (3). */
export class ProcesseurEchangesNoortrace {
  /** @param {object} session @param {{fileMax?: number}} [o] */
  constructor(session, o = {}) {
    this.file = new FileEchanges(session, { fileMax: o.fileMax ?? 1000 });
  }

  async onTraceStart() {}

  async onTraceEnd() {}

  async onSpanStart() {}

  async onSpanEnd(span) {
    try {
      const d = span.spanData;
      let requete;
      let reponse;
      if (d?.type === "generation") {
        if (d.input === undefined && d.output === undefined) return;
        requete = { ...(typeof d.model === "string" ? { model: d.model } : {}), input: valeurDeclaree(d.input ?? null), model_config: valeurDeclaree(d.model_config ?? null) };
        reponse = { output: valeurDeclaree(d.output ?? null), usage: valeurDeclaree(d.usage ?? null) };
      } else if (d?.type === "response") {
        if (d._input === undefined && d._response === undefined) return;
        const modele = d._response?.model;
        requete = { ...(typeof modele === "string" ? { model: modele } : {}), input: valeurDeclaree(d._input ?? null) };
        reponse = valeurDeclaree(d._response ?? null);
      } else {
        return;
      }
      const debut = Date.parse(span.startedAt ?? "");
      const fin = Date.parse(span.endedAt ?? "");
      const durationMs = Number.isFinite(debut) && Number.isFinite(fin) ? Math.max(0, fin - debut) : 0;
      this.file.ajouter({ format: "autre", providerLabel: "openai", request: requete, response: reponse, status: null, durationMs, isError: span.error != null });
    } catch {
      /* jamais propagé */
    }
  }

  async shutdown() {}

  async forceFlush() {}
}

/**
 * `adaptateurAgentsOpenAI(session, { classes, modele = "passerelle", ignorer })` :
 * `{ envelopperExecution(nom, execute), processeur }`.
 * @param {object} session session de `noortrace-sdk`
 * @param {{classes?: Record<string, "lecture"|"ecriture">, modele?: "passerelle"|"declarer", ignorer?: string[]}} [o]
 */
export function adaptateurAgentsOpenAI(session, o = {}) {
  const r = reglagesAdaptateur(o);
  const a = {
    processeur: r.modele === "declarer" ? new ProcesseurEchangesNoortrace(session) : null,
    preparer(nom, input) {
      return { nom, args: argumentsDeclares(input), classe: r.classes[nom] ?? null };
    },
    /**
     * Enveloppe la fonction `execute` d'un outil local (point d'interception, EX-6.16).
     * @template T
     * @param {string} nom nom de l'outil passé à `tool({ name })`
     * @param {(input: any, context?: any, details?: any) => T|Promise<T>} execute
     */
    envelopperExecution(nom, execute) {
      if (r.ignorer.has(nom)) return execute;
      return async (input, context, details) => {
        // Nom que le modèle voit : celui de l'appel (`details.toolCall.name`) ; `tool({ name })`
        // le normalise (`toFunctionToolName`, `dist/utils/tools.mjs` L23-L33), à défaut `nom`.
        const vu = typeof details?.toolCall?.name === "string" ? details.toolCall.name : nom;
        const issue = await intercepter(session, () => a.preparer(vu, input), async () => execute(input, context, details), (v) => ({ resultat: valeurDeclaree(v === undefined ? null : v), isError: false }));
        return issue.texte !== null ? issue.texte : issue.valeur;
      };
    },
  };
  return a;
}
