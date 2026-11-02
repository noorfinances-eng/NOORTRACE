// Annuaire des approbateurs, en lecture (CT-3 13.4) : forme canonique d'une
// identité de session (EX-13.7), entrée active d'une identité et son adresse
// active, alias de demandeur, administrateurs ; contrôle de l'identité de
// session sur le canal de la console (EX-12.13, EX-12.14, EX-12.16,
// EX-12.19), dans l'ordre de la fonction `controleCanal` d'EX-13.32.
//
// Les méthodes qui modifient l'annuaire (inscription, validation,
// révocation…) et les méthodes `tickets`, `consulter` et `annuaire` du canal
// relèvent de l'étape 6 (console) ; à l'étape 4, le service lit l'annuaire
// d'un fichier `annuaire-approbateurs-v0` de la configuration, s'en sert pour
// contrôler `voter`, `recuser` et `retirer`, et en tire les adresses connues
// de la lecture du jeu (EX-8.1, pas 5).

import fs from "node:fs";
import { IDS, registreSchemas } from "./schema.mjs";
import { lireJsonStrict } from "./json.mjs";

const MOTIF_IDENTITE = /^(oidc https:\/\/[!-"$->@-~]+ [!-~]{1,255}|utilisateur [!-~]{1,128} [!-~]{1,255})$/;

/**
 * Identité de session canonique (EX-13.7) ?
 * @param {unknown} s
 */
export function identiteCanonique(s) {
  return typeof s === "string" && s.length >= 1 && s.length <= 256 && MOTIF_IDENTITE.test(s);
}

/** Annuaire en lecture. */
export class Annuaire {
  /** @param {object} document `annuaire-approbateurs-v0` */
  constructor(document) {
    const r = registreSchemas().valider(IDS.annuaire, document);
    if (!r.valide) throw new Error(`annuaire non conforme : ${r.erreurs[0].pointeur} ${r.erreurs[0].regle}`);
    this.document = document;
  }

  /** Lit un fichier d'annuaire. */
  static lire(chemin) {
    return new Annuaire(lireJsonStrict(fs.readFileSync(chemin)));
  }

  /** Annuaire vide d'une organisation (aucune entrée). */
  static vide(org_id, administrators = []) {
    return new Annuaire({
      version: 0, org: "organisation", org_id, console_origin: "https://console.invalid", registration_ttl_ms: 600000,
      administrators, revision: 0, updated_at: "1970-01-01T00:00:00.000Z", entries: [], operations: [],
    });
  }

  get administrators() {
    return this.document.administrators;
  }

  /** Entrée dont l'identité de session est `identite`, ou null. */
  entree(identite) {
    return this.document.entries.find((e) => e.session_identity === identite) ?? null;
  }

  /** Entrée active de l'identité, ou null. */
  entreeActive(identite) {
    const e = this.entree(identite);
    return e && e.active ? e : null;
  }

  /** Adresse active d'une entrée, ou null (une seule par entrée, EX-13.10). */
  static adresseActive(e) {
    return e?.addresses.find((a) => a.state === "active")?.address ?? null;
  }

  /** Session de l'organisation : administrateur, ou identité dont l'entrée est active (EX-12.14). */
  sessionDeLOrganisation(identite) {
    return this.administrators.includes(identite) || this.entreeActive(identite) !== null;
  }

  /** Toutes les adresses de l'annuaire, quel que soit leur état (EX-8.1, pas 5). */
  adresses() {
    return this.document.entries.flatMap((e) => e.addresses.map((a) => a.address));
  }
}

/**
 * Contrôle de l'identité de session d'une méthode du canal de la console,
 * avant que l'entrée de 7.4 soit formée (EX-12.14, EX-12.16, EX-12.19).
 * @param {Annuaire} annuaire
 * @param {"tickets"|"consulter"|"voter"|"recuser"|"retirer"} methode
 * @param {object} requete corps de la méthode
 * @param {{launched_by: string, eligible: string[]}|null} ticket ticket connu de l'organisation, ou null
 * @returns {string|null} `identite_invalide`, `session_non_autorisee`, `ticket_inconnu`, ou null
 */
export function controleCanal(annuaire, methode, requete, ticket) {
  const id = requete.session_identity;
  if (!identiteCanonique(id)) return "identite_invalide";
  const admin = annuaire.administrators.includes(id);
  const entree = annuaire.entreeActive(id);
  switch (methode) {
    case "tickets":
      return annuaire.sessionDeLOrganisation(id) ? null : "session_non_autorisee";
    case "consulter": {
      if (!annuaire.sessionDeLOrganisation(id)) return "session_non_autorisee";
      if (ticket === null) return "ticket_inconnu";
      if (admin) return null;
      const adresse = Annuaire.adresseActive(entree);
      return adresse !== null && ticket.eligible.includes(adresse) ? null : "session_non_autorisee";
    }
    case "voter":
    case "recuser": {
      const adresse = Annuaire.adresseActive(entree);
      if (adresse === null || adresse !== String(requete.approver).toLowerCase()) return "session_non_autorisee";
      return ticket === null ? "ticket_inconnu" : null;
    }
    case "retirer": {
      if (ticket === null) return "ticket_inconnu";
      const demandeur = entree !== null && requete.by === ticket.launched_by && entree.requester_identities.includes(ticket.launched_by);
      const administrateur = requete.by === id && admin;
      return demandeur || administrateur ? null : "session_non_autorisee";
    }
    default:
      return "requete_invalide";
  }
}
