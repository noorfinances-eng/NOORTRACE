// Types du SDK TypeScript de NOORTRACE (CT-2 6.5, EX-6.9 : « types inclus »).

export type Classe = "lecture" | "ecriture";
export type Decision = "autorise" | "a_approuver" | "refuse";
export type EtatTicket = "nouveau" | "en_attente" | "approuve" | "refuse" | "expire";
export type SorteContexte = "document" | "donnees" | "memoire" | "autre";
export type FormatEchange = "anthropic-messages" | "openai-chat" | "openai-responses" | "gemini" | "autre";

/** Effet de CT-1 §5.3. */
export interface Effet {
  system: string;
  action: "lecture" | "ecriture" | "suppression" | "envoi" | "execution";
  object: string;
  amount: string | null;
  currency: string | null;
}

/** Résultat de `debutAppel` : exactement ses quatre membres (EX-6.9). */
export interface Debut {
  call: string | null;
  decision: Decision;
  ticket: string | null;
  ticket_state: EtatTicket | null;
}

/** Événement durable : `seq` et `hash` (null pour un événement en attente du mode dégradé, 14.5). */
export interface Scelle {
  seq: number | null;
  hash: string | null;
}

/** Référence de la pièce stockée. */
export interface Reference {
  sha256: string;
  length: number;
  redacted: boolean;
}

export interface OptionsClient {
  socket?: string | null;
  tcp?: string | null;
  jeton?: string | null;
  delaiMs?: number;
  reprises?: number;
  surIndisponibiliteLecture?: "bloquer" | "executer";
}

export interface ParametresAppel {
  tool: string;
  arguments: unknown;
  classe?: Classe | null;
  contexte?: string[];
  intent?: string | null;
  effects?: Effet[] | null;
}

export declare class ClientNoortrace {
  constructor(o?: OptionsClient);
  static depuisEnvironnement(): ClientNoortrace;
  readonly delaiMs: number;
  readonly reprises: number;
  readonly surIndisponibiliteLecture: "bloquer" | "executer";
  ouvrir(o?: { runId?: string | null; onBehalfOf?: string | null }): Promise<Session>;
}

export declare class Session {
  declarerContexte(p: { kind: SorteContexte; octets: Uint8Array | string; mediaType?: string | null }): Promise<Reference>;
  debutAppel(p: ParametresAppel): Promise<Debut>;
  finAppel(debut: Debut, p: { resultat?: unknown; isError: boolean; durationMs: number }): Promise<Scelle>;
  appelOutil<T>(p: ParametresAppel, fonction: (args: any) => T | Promise<T>): Promise<T>;
  echangeModele(p: {
    format: FormatEchange;
    providerLabel: string;
    request: unknown;
    response: unknown;
    status?: number | null;
    durationMs: number;
    isError: boolean;
  }): Promise<Scelle>;
  fermer(): Promise<object>;
}

export declare class ErreurNoortrace extends Error {
  code: number | null;
  data: unknown;
}
export declare class ErreurNoortraceIndisponible extends ErreurNoortrace {
  envoyee: boolean;
}
export declare class ErreurNoortraceDegrade extends ErreurNoortrace {
  raison: string | null;
}
export declare class ErreurNoortraceLimite extends ErreurNoortrace {
  direction: string | null;
  limite: number | null;
}
export declare class ErreurNoortraceNonDurable extends ErreurNoortrace {
  intent_id: string | null;
}
export declare class ErreurNoortraceEntreeInvalide extends ErreurNoortrace {
  raison: string | null;
}
export declare class ErreurNoortraceConfiguration extends ErreurNoortrace {}
export declare class AppelNonAutorise extends ErreurNoortrace {
  decision: Decision;
  ticket: string | null;
  ticket_state: EtatTicket | null;
  texte: string;
}

export declare const PRISE_DEFAUT: string;
export declare const CHEMIN_PRISE_MAX: number;
export declare const FERMER_A_LA_SORTIE_MS: number;
export declare function delaiReprise(n: number, u?: number): number;
export declare function estValeurJson(v: unknown): boolean;
export declare function nomDuType(v: unknown): string;
export declare function nomDeClasse(e: unknown): string;
export declare function texteNonAutorise(ticket: string | null, etat: string | null): string;
