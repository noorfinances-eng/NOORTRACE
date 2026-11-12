// Annuaire des approbateurs tenu par le service (CT-3 13.4 à 13.6,
// EX-13.37, EX-13.38) : état seulement (document courant, défis
// d'inscription non expirés) et préséance au démarrage. Aucune règle de
// l'annuaire n'est écrite ici : elles ont une seule implémentation, le module
// d'annuaire de la bibliothèque de la console (`@noortrace/console/annuaire`,
// rubrique 1.3 de ses interfaces), que ce module importe et réexporte.
//
// La persistance (enregistrements chiffrés `annuaire` et `defis`, EX-7.30,
// EX-13.38) est celle du magasin d'état ; le service décide quand écrire.

import {
  estIdentiteCanonique, annuaireVide, entreeActive, adresseActive, sessionDeLOrganisation, adressesConnues,
  annuaireDeSession, appliquerOperation, verifierInscription, defisNonExpires, recopierAdministrateurs, controleCanal,
  verifierAnnuaireExporte,
} from "@noortrace/console/annuaire";
import { IDS, registreSchemas } from "./schema.mjs";
import { cloner, egaliteJson } from "./json.mjs";

export {
  estIdentiteCanonique, annuaireVide, entreeActive, adresseActive, sessionDeLOrganisation, adressesConnues,
  annuaireDeSession, appliquerOperation, verifierInscription, defisNonExpires, recopierAdministrateurs, controleCanal,
  verifierAnnuaireExporte,
};

/** Méthodes du canal de la console qui passent par `appliquerOperation` (EX-13.13, EX-13.15, EX-13.17). */
export const METHODES_ANNUAIRE = Object.freeze([
  "preparer_inscription", "inscrire", "valider", "revoquer", "desactiver", "reactiver", "lier_demandeur", "delier_demandeur",
]);

/** Erreur qui interdit le démarrage (EX-13.38, EX-13.37). */
export class ErreurAnnuaire extends Error {
  constructor(message) {
    super(message);
    this.name = "ErreurAnnuaire";
  }
}

/** Le document est-il conforme à `annuaire-approbateurs-v0` ? */
export function annuaireConforme(document) {
  return registreSchemas().estValide(IDS.annuaire, document);
}

/** Réglages de la configuration recopiés dans l'annuaire (EX-13.38). */
function reglages(config) {
  return {
    org: config.org,
    org_id: config.org_id,
    console_origin: config.console_origin,
    registration_ttl_ms: config.registration_ttl_ms,
    administrators: [...config.administrators],
  };
}

/**
 * Annuaire retenu au démarrage, dans l'ordre d'EX-13.38 (points 1 à 6).
 * @param {{persiste: {annuaire: object|null, defis: object[]|null}, config: object,
 *   lireAmorce: () => unknown, at: string, journal: (type: string, detail: object) => void}} p
 *   `persiste` : membres `annuaire` et `defis` relus de l'état (EX-7.23), null s'ils n'y sont pas ;
 *   `lireAmorce` : lit le document de `console.annuaire` (appelée seulement s'il faut l'amorce)
 * @returns {{document: object, defis: object[], persiste: boolean, aEcrire: boolean, changeAdministrateurs: boolean}}
 *   `aEcrire` : l'annuaire retenu diffère de l'état persisté et doit l'être avant toute méthode
 * @throws {ErreurAnnuaire}
 */
export function annuaireDeDemarrage(p) {
  const c = p.config;
  const amorceDeclaree = typeof c.console?.annuaire === "string";
  let document;
  let persiste;
  if (p.persiste.annuaire) {
    // point 2 : dès qu'un annuaire est persisté, seul l'état fait foi
    document = cloner(p.persiste.annuaire);
    persiste = true;
    if (amorceDeclaree) p.journal("annuaire_amorce_ignoree", { amorce: c.console.annuaire });
  } else if (amorceDeclaree) {
    // point 1 et point 3 : amorce conforme et sans écart aux points 1 à 6 d'EX-13.19
    let doc;
    try {
      doc = p.lireAmorce();
    } catch (e) {
      throw new ErreurAnnuaire(`amorce de l'annuaire illisible : ${e.message}`);
    }
    const ecarts = verifierAnnuaireExporte(doc, { conforme: annuaireConforme });
    if (ecarts.length) {
      throw new ErreurAnnuaire(`amorce de l'annuaire refusée (EX-13.38, point 3) : ${ecarts.map((x) => `${x.code} ${x.pointer}`).join(", ")}`);
    }
    document = cloner(doc);
    persiste = false;
  } else {
    // point 1 : annuaire vide de la configuration
    document = annuaireVide(reglages(c));
    persiste = false;
  }
  if (!annuaireConforme(document)) throw new ErreurAnnuaire("annuaire persisté non conforme à annuaire-approbateurs-v0");
  // point 4 : org, org_id et console_origin de la configuration
  for (const k of ["org", "org_id", "console_origin"]) {
    if (document[k] !== c[k]) throw new ErreurAnnuaire(`annuaire d'un autre ${k} que la configuration (EX-13.38, point 4)`);
  }
  let aEcrire = false;
  // point 5 : registration_ttl_ms recopié, sans opération ni changement de revision
  if (document.registration_ttl_ms !== c.registration_ttl_ms) {
    p.journal("annuaire_ttl_recopie", { avant: document.registration_ttl_ms, apres: c.registration_ttl_ms });
    document = { ...document, registration_ttl_ms: c.registration_ttl_ms };
    if (persiste) aEcrire = true;
  }
  // point 6 : recopie d'administrators (EX-13.37), qui persiste l'annuaire s'il change
  let r;
  try {
    r = recopierAdministrateurs(document, [...c.administrators], p.at);
  } catch (e) {
    throw new ErreurAnnuaire(`réglage administrators refusé (EX-13.37) : ${e.code ?? e.message}`);
  }
  if (r.changed) {
    document = r.annuaire;
    aEcrire = true;
    persiste = true;
  }
  const defis = defisNonExpires(p.persiste.defis ?? [], p.at);
  return { document, defis, persiste, aEcrire, changeAdministrateurs: r.changed };
}

/**
 * État de l'annuaire du service : document courant, défis non expirés, et
 * s'il est déjà persisté (EX-13.38, point 1 : l'amorce et l'annuaire vide ne
 * le sont qu'avec la première opération acceptée).
 */
export class EtatAnnuaire {
  /** @param {{document: object, defis: object[], persiste: boolean}} p */
  constructor(p) {
    this.document = p.document;
    this.defis = p.defis;
    this.persiste = p.persiste;
  }

  /** Adresses connues pour la lecture du jeu (EX-8.1, pas 5). */
  adresses() {
    return adressesConnues(this.document);
  }

  /**
   * Applique une méthode qui modifie l'annuaire ou ses défis, sans rien
   * changer à l'état : rend ce que `appliquerOperation` rend, et ce qui a
   * changé. Le service persiste, puis adopte (`adopter`).
   * @param {string} methode
   * @param {object} corps
   * @param {string} at
   * @param {{nonce?: string}} [o]
   */
  calculer(methode, corps, at, o = {}) {
    const defis = defisNonExpires(this.defis, at);
    const options = { defis, identifiant: "aleatoire" };
    if (o.nonce !== undefined) options.nonce = o.nonce;
    const r = appliquerOperation(this.document, methode, corps, at, options);
    const nouveauxDefis = defisNonExpires(r.defis, at);
    return {
      ...r,
      defis: nouveauxDefis,
      annuaireChange: r.annuaire !== this.document && !egaliteJson(r.annuaire, this.document),
      defisChanges: !egaliteJson(nouveauxDefis, this.defis),
    };
  }

  /** Adopte un état calculé, une fois persisté. */
  adopter({ annuaire, defis, persiste }) {
    if (annuaire !== undefined) this.document = annuaire;
    if (defis !== undefined) this.defis = defis;
    if (persiste) this.persiste = true;
  }

  /** Membres de l'état complet à persister (EX-13.38) : `annuaire` seulement s'il est persisté. */
  exporter() {
    return this.persiste ? { annuaire: this.document, defis: this.defis } : { defis: this.defis };
  }
}
