// Types de la file des échanges observés (CT-2 EX-6.11 (3)), offerte aux adaptateurs de cadres (6.6).

import type { Session } from "./index.js";

export declare class FileEchanges {
  constructor(session: Session, o?: { fileMax?: number; sortie?: { write(s: string): void } });
  readonly fileMax: number;
  readonly echangesPerdus: number;
  ajouter(p: Parameters<Session["echangeModele"]>[0]): boolean;
  vide(): Promise<void>;
}

/** Textes fixes d'EX-6.19. */
export declare const TEXTE_DEGRADE: string;
export declare const TEXTE_INJOIGNABLE: string;
export declare const TEXTE_LIMITE: string;
export declare const TEXTE_ENTREE_INVALIDE: string;
export declare const TEXTE_NON_DURABLE: string;

export declare function nomDeclarable(nom: unknown): boolean;
export declare function texteAvantExecution(e: unknown): string;
export declare function valeurDeclaree(v: unknown): unknown;
export declare function etiquette(texte: unknown, defaut?: string): string;
export declare function reglagesAdaptateur(o?: { classes?: Record<string, "lecture" | "ecriture">; modele?: "passerelle" | "declarer"; ignorer?: string[] }): {
  classes: Record<string, "lecture" | "ecriture">;
  modele: "passerelle" | "declarer";
  ignorer: Set<string>;
};
/** Point d'interception commun (EX-6.16 à EX-6.19). */
export declare function intercepter(
  session: Session,
  preparer: () => { nom: string; args: unknown; classe: "lecture" | "ecriture" | null },
  executer: () => Promise<unknown>,
  declarer: (v: unknown) => { resultat: unknown; isError: boolean },
): Promise<{ executee: boolean; texte: string | null; valeur?: unknown }>;
