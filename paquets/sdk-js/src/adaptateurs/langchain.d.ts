// Types de l'adaptateur LangChain JavaScript (CT-2 6.6).
import type { Session } from "../index.js";
import type { FileEchanges } from "../adaptateurs.js";

export interface ReglagesAdaptateur {
  classes?: Record<string, "lecture" | "ecriture">;
  modele?: "passerelle" | "declarer";
  ignorer?: string[];
}

export declare class GestionnaireEchangesNoortrace {
  constructor(session: Session, o?: { fileMax?: number });
  readonly file: FileEchanges;
}

/** Intergiciel de `createMiddleware` (`wrapToolCall`), à passer en dernier à `createAgent`. */
export declare function middlewareNoortrace(session: Session, o?: ReglagesAdaptateur): any & { readonly rappels: GestionnaireEchangesNoortrace[] };
