// Dossier d'inscription `inscription-client-v0` tenu par l'agent (CT-4
// EX-7.16, EX-7.24) : lu en JSON strict et contrôlé contre son schéma,
// réécrit (fichier temporaire, `fsync`, renommage) à chaque passage d'une
// étape, `updated_at` à l'instant du passage. Quand chaque étape est
// `capturee` ou `faite`, `result` est rempli (7.10) à l'instant du dernier
// passage.

import fs from "node:fs";
import { lireJsonStrict } from "@noortrace/approbation";
import { ecrireHorodatage } from "@noortrace/noyau";
import { IDS, valider } from "../commun/schemas.mjs";
import { ecrireAtomique, serialiser } from "./donnees.mjs";

/** Lit un dossier ; rend `{ dossier }` ou `{ erreur }` (illisible ou hors schéma). */
export function lireDossier(chemin) {
  let octets;
  try {
    octets = fs.readFileSync(chemin);
  } catch {
    return { erreur: "dossier illisible" };
  }
  let d;
  try {
    d = lireJsonStrict(octets);
  } catch (e) {
    return { erreur: `dossier : JSON illisible (${e.message})` };
  }
  const v = valider(IDS.inscription, d);
  if (!v.valide) return { erreur: `dossier hors du schéma inscription-client-v0 (${v.erreurs[0]})` };
  return { dossier: d };
}

/** Réécrit le dossier (EX-7.16). */
export function ecrireDossier(chemin, dossier) {
  const v = valider(IDS.inscription, dossier);
  if (!v.valide) throw new Error(`dossier hors schéma : ${v.erreurs.join(" ; ")}`);
  ecrireAtomique(chemin, serialiser(dossier));
}

/** L'étape `step` d'objet `subject` (ou la première de ce `step` si `subject` est omis). */
export function etape(dossier, step, subject = undefined) {
  return dossier.steps.find((e) => e.step === step && (subject === undefined || e.subject === subject)) ?? null;
}

/**
 * Tenue d'un dossier sur disque : `passer(etape, changements)` applique les
 * changements, pose `updated_at`, remplit `result` si l'inscription est finie
 * (`completer`), puis réécrit.
 */
export class TenueDossier {
  constructor(chemin, dossier, { horloge, completer = null }) {
    this.chemin = chemin;
    this.dossier = dossier;
    this.horloge = horloge;
    this.completer = completer;
  }

  async passer(e, changements) {
    const instant = ecrireHorodatage(this.horloge.murale());
    Object.assign(e, changements, { updated_at: instant });
    if (this.dossier.result === null && this.dossier.steps.every((x) => x.state === "capturee" || x.state === "faite") && this.completer) {
      const result = await this.completer(this.dossier, instant);
      if (result) this.dossier.result = result;
    }
    ecrireDossier(this.chemin, this.dossier);
    return e;
  }
}

/** Référence d'une étape transactionnelle (`reference_transaction`), ou null si l'étape n'en a pas. */
export function referenceTransaction(e) {
  if (!e || e.transaction_hash === null || e.block_number === null || e.block_hash === null || e.capture === null) return null;
  return { transaction_hash: e.transaction_hash, block_number: e.block_number, block_hash: e.block_hash, capture: e.capture };
}
