// Types de la file des échanges observés (CT-2 EX-6.11 (3)), offerte aux adaptateurs de cadres (6.6).

import type { Session } from "./index.js";

export declare class FileEchanges {
  constructor(session: Session, o?: { fileMax?: number; sortie?: { write(s: string): void } });
  readonly fileMax: number;
  readonly echangesPerdus: number;
  ajouter(p: Parameters<Session["echangeModele"]>[0]): boolean;
  vide(): Promise<void>;
}
