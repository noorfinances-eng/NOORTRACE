// Types de l'adaptateur du SDK Agents d'OpenAI, TypeScript (CT-2 6.6).
import type { Session } from "../index.js";
import type { FileEchanges } from "../adaptateurs.js";
import type { ReglagesAdaptateur } from "./langchain.js";

export declare class ProcesseurEchangesNoortrace {
  constructor(session: Session, o?: { fileMax?: number });
  readonly file: FileEchanges;
  onTraceStart(trace: unknown): Promise<void>;
  onTraceEnd(trace: unknown): Promise<void>;
  onSpanStart(span: unknown): Promise<void>;
  onSpanEnd(span: unknown): Promise<void>;
  shutdown(): Promise<void>;
  forceFlush(): Promise<void>;
}

export declare function argumentsDeclares(input: unknown): unknown;

export declare function adaptateurAgentsOpenAI(
  session: Session,
  o?: ReglagesAdaptateur,
): {
  readonly processeur: ProcesseurEchangesNoortrace | null;
  envelopperExecution<T>(nom: string, execute: (input: any, context?: any, details?: any) => T | Promise<T>): (input: any, context?: any, details?: any) => Promise<T | string>;
};
