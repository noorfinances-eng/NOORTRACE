// Module d'annuaire de la console (« @noortrace/console/annuaire ») : la seule
// implémentation des règles de l'annuaire des approbateurs, partagée par le
// service d'approbation, la page de la console et les essais. Règles de CT-3
// tenues : identité de session (EX-13.7, EX-12.13) ; annuaire, entrées et
// invariants « une personne, une clé » (EX-13.9, EX-13.10) ; annuaire vide et
// défis persistés (EX-13.38) ; message d'inscription (EX-13.12) ; défi et
// contrôle du texte par la console (EX-13.13) ; vérification d'une inscription
// (EX-13.15, normalisation d'EX-9.3) ; opérations de l'annuaire et bornes du
// schéma (EX-13.17, `limite_annuaire`) ;
// recopie du réglage `administrators` (EX-13.37) ; contrôles de la console
// avant un vote, une récusation ou un retrait (EX-13.18, EX-7.15) ; contrôle
// de session du canal (EX-12.13, EX-12.14, EX-12.16, EX-12.19) ; document
// réduit (EX-12.17) ; vérification d'un annuaire exporté (EX-13.19).
//
// L'annuaire est le document `annuaire-approbateurs-v0` lui-même : aucune
// fonction ne modifie ses paramètres ; chaque rendu est un objet neuf.

import { ErreurConsole } from "./erreurs.mjs";
import { formeRequete } from "./formes.mjs";
import { analyserIdentite, estIdentiteCanonique, identiteCanonique } from "./identite.mjs";
import { decoderInstant, encoderInstant, instantParametre } from "./instants.mjs";
import { cloner, egaliteJson } from "./json.mjs";
import { analyserMessageInscription, champsInscriptionValides, messageInscription } from "./message.mjs";
import { utf8Strict, versHex } from "./octets.mjs";
import { N_SECP256K1, verifierSignature } from "./signatures.mjs";

export { ErreurConsole, analyserIdentite, estIdentiteCanonique, identiteCanonique, messageInscription, analyserMessageInscription };

// Bornes d'`annuaire-approbateurs-v0` (EX-13.17, révision 0.6 : `limite_annuaire`).
const MAX_ENTREES = 10000;
const MAX_ADRESSES = 64;
const MAX_DEMANDEURS = 64;

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const aCle = (o, c) => Object.prototype.hasOwnProperty.call(o, c);

function exigerAnnuaire(annuaire, nom) {
  if (!estObjet(annuaire) || !Array.isArray(annuaire.entries) || !Array.isArray(annuaire.operations) || !Array.isArray(annuaire.administrators)) {
    throw new TypeError(`${nom} : annuaire attendu`);
  }
}

function exigerChaine(v, nom) {
  if (typeof v !== "string") throw new TypeError(`${nom} : chaine attendue`);
}

// ---------------------------------------------------------------------------
// Lectures (EX-13.10, EX-12.14, EX-12.17)

/**
 * L'entrée dont `session_identity` égale l'identité, ou `null`.
 * @param {object} annuaire
 * @param {string} identite
 * @returns {object|null}
 */
export function entreeDeSession(annuaire, identite) {
  exigerAnnuaire(annuaire, "entreeDeSession");
  exigerChaine(identite, "entreeDeSession");
  const e = annuaire.entries.find((x) => x.session_identity === identite);
  return e === undefined ? null : cloner(e);
}

/**
 * L'entrée de l'identité si elle est active, sinon `null`.
 * @param {object} annuaire
 * @param {string} identite
 * @returns {object|null}
 */
export function entreeActive(annuaire, identite) {
  const e = entreeDeSession(annuaire, identite);
  return e !== null && e.active === true ? e : null;
}

/**
 * L'adresse `active` de l'entrée, ou `null`.
 * @param {object|null} entree
 * @returns {string|null}
 */
export function adresseActive(entree) {
  if (entree === null) return null;
  if (!estObjet(entree) || !Array.isArray(entree.addresses)) throw new TypeError("adresseActive : entree ou null attendu");
  const a = entree.addresses.find((x) => x.state === "active");
  return a === undefined ? null : a.address;
}

/**
 * Vrai pour une identité de `administrators` ou d'une entrée active
 * (« session de l'organisation », EX-12.14).
 * @param {object} annuaire
 * @param {string} identite
 */
export function sessionDeLOrganisation(annuaire, identite) {
  exigerAnnuaire(annuaire, "sessionDeLOrganisation");
  exigerChaine(identite, "sessionDeLOrganisation");
  return annuaire.administrators.includes(identite) || entreeActive(annuaire, identite) !== null;
}

/**
 * Toutes les adresses de l'annuaire, tous états, triées, sans doublon.
 * @param {object} annuaire
 * @returns {string[]}
 */
export function adressesConnues(annuaire) {
  exigerAnnuaire(annuaire, "adressesConnues");
  const s = new Set();
  for (const e of annuaire.entries) for (const a of e.addresses) s.add(a.address);
  return [...s].sort();
}

/**
 * L'annuaire que la méthode `annuaire` rend à une identité (EX-12.17) : complet
 * pour une identité de `administrators` ; sinon réduit à l'entrée de
 * l'identité (0 ou 1) et aux opérations qui la visent, les autres membres
 * gardés tels quels.
 * @param {object} annuaire
 * @param {string} identite
 * @returns {object}
 */
export function annuaireDeSession(annuaire, identite) {
  exigerAnnuaire(annuaire, "annuaireDeSession");
  exigerChaine(identite, "annuaireDeSession");
  const copie = cloner(annuaire);
  if (annuaire.administrators.includes(identite)) return copie;
  const e = copie.entries.find((x) => x.session_identity === identite);
  copie.entries = e === undefined ? [] : [e];
  copie.operations = e === undefined ? [] : copie.operations.filter((o) => o.entry === e.id);
  return copie;
}

// ---------------------------------------------------------------------------
// Annuaire vide et recopie du réglage `administrators` (EX-13.38, EX-13.37)

function listeAdministrateursValide(liste) {
  return (
    Array.isArray(liste) &&
    liste.length >= 1 &&
    liste.length <= 64 &&
    liste.every((x) => estIdentiteCanonique(x)) &&
    new Set(liste).size === liste.length
  );
}

/**
 * L'annuaire vide d'EX-13.38, point 1.
 * @param {{org: string, org_id: string, console_origin: string, registration_ttl_ms: number, administrators: string[]}} reglages
 * @returns {object}
 * @throws {ErreurConsole} `identite_invalide` si `administrators` n'est pas de 1 à 64 identités canoniques distinctes
 */
export function annuaireVide(reglages) {
  if (!estObjet(reglages)) throw new TypeError("annuaireVide : reglages attendus");
  exigerChaine(reglages.org, "annuaireVide (org)");
  exigerChaine(reglages.org_id, "annuaireVide (org_id)");
  exigerChaine(reglages.console_origin, "annuaireVide (console_origin)");
  if (!Number.isSafeInteger(reglages.registration_ttl_ms)) throw new TypeError("annuaireVide : registration_ttl_ms entier attendu");
  if (!listeAdministrateursValide(reglages.administrators)) {
    throw new ErreurConsole("identite_invalide", "administrators : de 1 a 64 identites canoniques distinctes attendues (EX-13.9)");
  }
  return {
    version: 0,
    org: reglages.org,
    org_id: reglages.org_id,
    console_origin: reglages.console_origin,
    registration_ttl_ms: reglages.registration_ttl_ms,
    administrators: [...reglages.administrators],
    revision: 0,
    updated_at: null,
    entries: [],
    operations: [],
  };
}

function operation(doc, at, op, by, champs) {
  return {
    seq: doc.revision + 1,
    at,
    op,
    by,
    entry: champs.entry ?? null,
    address: champs.address ?? null,
    launched_by: champs.launched_by ?? null,
    reason: champs.reason ?? null,
    administrators: champs.administrators ?? null,
  };
}

function inscrireOperation(doc, op) {
  doc.operations.push(op);
  doc.revision = op.seq;
  doc.updated_at = op.at;
}

/**
 * Recopie du réglage `administrators` dans l'annuaire (EX-13.37) : opération
 * `changer_administrateurs` si la liste diffère, comme liste, de la copie.
 * @param {object} annuaire
 * @param {string[]} administrateurs
 * @param {string} at
 * @returns {{annuaire: object, changed: boolean}} l'annuaire inchangé (même objet) si la liste est la même
 * @throws {ErreurConsole} `identite_invalide` pour une liste hors de la forme d'EX-13.9
 */
export function recopierAdministrateurs(annuaire, administrateurs, at) {
  exigerAnnuaire(annuaire, "recopierAdministrateurs");
  instantParametre(at, "recopierAdministrateurs (at)");
  if (!listeAdministrateursValide(administrateurs)) {
    throw new ErreurConsole("identite_invalide", "administrators : de 1 a 64 identites canoniques distinctes attendues (EX-13.9)");
  }
  if (egaliteJson(annuaire.administrators, administrateurs)) return { annuaire, changed: false };
  const doc = cloner(annuaire);
  const avant = [...annuaire.administrators];
  const apres = [...administrateurs];
  inscrireOperation(doc, operation(doc, at, "changer_administrateurs", "configuration", { administrators: { before: avant, after: apres } }));
  doc.administrators = [...administrateurs];
  return { annuaire: doc, changed: true };
}

// ---------------------------------------------------------------------------
// Défis (EX-13.13, EX-13.38)

/**
 * Les défis dont `expires_at` est postérieur à `at`.
 * @param {object[]} defis
 * @param {string} at
 * @returns {object[]}
 */
export function defisNonExpires(defis, at) {
  if (!Array.isArray(defis)) throw new TypeError("defisNonExpires : tableau attendu");
  const t = instantParametre(at, "defisNonExpires (at)");
  return defis.filter((d) => decoderInstant(d.fields.expires_at) > t).map((d) => cloner(d));
}

/**
 * Contrôle, par la console, du texte d'inscription servi par le service
 * (EX-13.13) : le premier écart, dans l'ordre `message_invalide` (texte
 * différent de celui que la console reconstruit des champs reçus),
 * `origine_differente`, `identite_differente`, `adresse_differente` ; ou `null`.
 * @param {unknown} reponse `$defs/reponse_preparer_inscription`
 * @param {{origine: string, identite: string, adresse: string}} attendu
 * @returns {null|"message_invalide"|"origine_differente"|"identite_differente"|"adresse_differente"}
 */
export function controleDefi(reponse, attendu) {
  if (!estObjet(attendu)) throw new TypeError("controleDefi : attendu requis");
  exigerChaine(attendu.origine, "controleDefi (origine)");
  exigerChaine(attendu.identite, "controleDefi (identite)");
  exigerChaine(attendu.adresse, "controleDefi (adresse)");
  if (
    !estObjet(reponse) ||
    Object.keys(reponse).length !== 2 ||
    !aCle(reponse, "fields") ||
    !aCle(reponse, "message") ||
    typeof reponse.message !== "string" ||
    !champsInscriptionValides(reponse.fields) ||
    messageInscription(reponse.fields) !== reponse.message
  ) {
    return "message_invalide";
  }
  if (reponse.fields.origin !== attendu.origine) return "origine_differente";
  if (reponse.fields.identity !== attendu.identite) return "identite_differente";
  if (reponse.fields.address !== attendu.adresse) return "adresse_differente";
  return null;
}

// ---------------------------------------------------------------------------
// Identifiants d'entrée (EX-13.9, EX-13.38, A.10)

function modeIdentifiant(options, nom) {
  const v = options.identifiant === undefined ? "aleatoire" : options.identifiant;
  if (v !== "aleatoire" && v !== "compteur") throw new TypeError(`${nom} : identifiant vaut "aleatoire" ou "compteur"`);
  return v;
}

function aleaOctets(n) {
  const o = new Uint8Array(n);
  globalThis.crypto.getRandomValues(o);
  return o;
}

function nouvelIdentifiant(annuaire, mode) {
  const pris = new Set(annuaire.entries.map((e) => e.id));
  if (mode === "compteur") {
    const id = `apb-${String(annuaire.entries.length + 1).padStart(4, "0")}`;
    if (pris.has(id)) throw new TypeError(`identifiant compteur deja attribue : ${id}`);
    return id;
  }
  while (true) {
    const id = `apb-${versHex(aleaOctets(8)).slice(2)}`;
    if (!pris.has(id)) return id;
  }
}

// ---------------------------------------------------------------------------
// Inscription (EX-13.15)

function lireOptions(options, nom) {
  if (options === undefined) return {};
  if (!estObjet(options)) throw new TypeError(`${nom} : options attendues`);
  return options;
}

function exigerDefis(defis, nom) {
  if (!Array.isArray(defis) || !defis.every((d) => estObjet(d) && estObjet(d.fields))) {
    throw new TypeError(`${nom} : tableau de defis attendu`);
  }
}

/**
 * Vérification d'une requête `inscrire` (EX-13.15, pas 1 à 13).
 * @param {object} annuaire
 * @param {object[]} defis `$defs/defi`
 * @param {unknown} requete corps d'`inscrire`
 * @param {string} recuA instant de réception
 * @param {{identifiant?: "aleatoire"|"compteur"}} [options]
 * @returns {{accepted: boolean, reason: string|null, entry: string|null, signature: string|null, defis: object[]}}
 */
export function verifierInscription(annuaire, defis, requete, recuA, options) {
  exigerAnnuaire(annuaire, "verifierInscription");
  exigerDefis(defis, "verifierInscription");
  const r = instantParametre(recuA, "verifierInscription (recuA)");
  const mode = modeIdentifiant(lireOptions(options, "verifierInscription"), "verifierInscription");
  const apres = defis.map((d) => cloner(d));
  const refus = (reason) => ({ accepted: false, reason, entry: null, signature: null, defis: apres });
  // 1 à 3 : forme, identité, message.
  if (!formeRequete("inscrire", requete)) return refus("requete_invalide");
  if (!estIdentiteCanonique(requete.session_identity)) return refus("identite_invalide");
  let champs;
  try {
    champs = analyserMessageInscription(requete.message);
  } catch (e) {
    if (e instanceof ErreurConsole) return refus("message_invalide");
    throw e;
  }
  // 4 : défi connu et non présenté ; il est marqué présenté dès ce pas.
  const k = apres.findIndex((d) => d.fields.nonce === champs.nonce);
  if (k < 0) return refus("nonce_inconnu");
  const defi = apres[k];
  const dejaPresente = defi.used === true;
  apres[k] = { fields: defi.fields, used: true };
  if (dejaPresente) return refus("nonce_deja_utilise");
  // 5 : Emis le ≤ r < Expire le.
  if (!(decoderInstant(champs.issued_at) <= r && r < decoderInstant(champs.expires_at))) return refus("inscription_expiree");
  // 6 à 9 : origine, organisation, identité, adresse.
  if (champs.origin !== annuaire.console_origin) return refus("origine_differente");
  if (champs.org !== annuaire.org || champs.org_id !== annuaire.org_id) return refus("organisation_differente");
  if (champs.identity !== requete.session_identity || champs.identity !== defi.fields.identity) return refus("identite_differente");
  if (champs.address !== requete.address || champs.address !== defi.fields.address) return refus("adresse_differente");
  // 10 : le message est le texte du défi.
  let texteDefi = null;
  try {
    texteDefi = messageInscription(defi.fields);
  } catch (e) {
    if (!(e instanceof ErreurConsole)) throw e;
  }
  if (texteDefi === null || requete.message !== texteDefi) return refus("message_invalide");
  // 11 : signature normalisée qui recouvre l'adresse sur le condensé EIP-191.
  const v = verifierSignature(utf8Strict(requete.message), requete.signature, requete.address);
  if (!v.valide) return refus("signature_invalide");
  // 12 et 13 : entrée active, adresse libre.
  const entree = annuaire.entries.find((e) => e.session_identity === requete.session_identity);
  if (entree !== undefined && entree.active !== true) return refus("identite_desactivee");
  if (annuaire.entries.some((e) => e.addresses.some((a) => a.address === requete.address))) return refus("adresse_deja_attribuee");
  // En dernier (EX-13.17, révision 0.6) : bornes du schéma de l'annuaire ;
  // le défi reste marqué présenté, comme pour tout refus après le pas 4.
  if (entree !== undefined ? entree.addresses.length >= MAX_ADRESSES : annuaire.entries.length >= MAX_ENTREES) return refus("limite_annuaire");
  const id = entree !== undefined ? entree.id : nouvelIdentifiant(annuaire, mode);
  return { accepted: true, reason: null, entry: id, signature: v.signature, defis: apres };
}

// Effet d'une inscription acceptée sur un document de travail.
function effetInscription(doc, identite, adresse, message, signature, at, id) {
  const champs = analyserMessageInscription(message);
  let entree = doc.entries.find((e) => e.session_identity === identite);
  if (entree === undefined) {
    entree = {
      id,
      session_identity: identite,
      external_id: null,
      display_name: null,
      active: true,
      requester_identities: [],
      created_at: at,
      addresses: [],
    };
    doc.entries.push(entree);
  }
  entree.addresses.push({
    address: adresse,
    state: "en_attente",
    proof: {
      message,
      signature,
      nonce: champs.nonce,
      issued_at: champs.issued_at,
      expires_at: champs.expires_at,
      received_at: at,
    },
    validated_at: null,
    validated_by: null,
    revoked_at: null,
    revoked_by: null,
    revocation_cause: null,
    revocation_reason: null,
    replaced_by: null,
  });
  inscrireOperation(doc, operation(doc, at, "inscrire", identite, { entry: entree.id, address: adresse }));
  return { entry: entree.id, address: adresse, state: "en_attente", revision: doc.revision };
}

// ---------------------------------------------------------------------------
// Opérations d'EX-13.17, sur un document de travail, avec la liste
// d'administrateurs en vigueur (celle du document, ou celle du rejeu
// d'EX-13.19). Rend `{ reason }` ou `{ reason: null, response, effacer }`.

function reponseEntree(doc, e) {
  return { entry: e.id, active: e.active, requester_identities: [...e.requester_identities], revision: doc.revision };
}

function executer(doc, methode, req, at, admins) {
  const session = req.session_identity;
  const admin = admins.includes(session);
  const entree = () => doc.entries.find((e) => e.id === req.entry);
  switch (methode) {
    case "valider": {
      if (!admin) return { reason: "non_administrateur" };
      const e = entree();
      if (e === undefined) return { reason: "entree_inconnue" };
      const a = e.addresses.find((x) => x.address === req.address);
      if (a === undefined) return { reason: "adresse_inconnue" };
      if (e.session_identity === session) return { reason: "auto_validation" };
      if (e.active !== true) return { reason: "identite_desactivee" };
      if (a.state !== "en_attente") return { reason: "etat_incompatible" };
      const precedente = e.addresses.find((x) => x.state === "active");
      if (precedente !== undefined) {
        precedente.state = "revoquee";
        precedente.revoked_at = at;
        precedente.revoked_by = session;
        precedente.revocation_cause = "remplacee";
        precedente.revocation_reason = null;
        precedente.replaced_by = a.address;
      }
      a.state = "active";
      a.validated_at = at;
      a.validated_by = session;
      inscrireOperation(doc, operation(doc, at, "valider", session, { entry: e.id, address: a.address }));
      return { reason: null, response: { entry: e.id, address: a.address, state: "active", revision: doc.revision } };
    }
    case "revoquer": {
      const e = entree();
      if (e === undefined) return { reason: "entree_inconnue" };
      const a = e.addresses.find((x) => x.address === req.address);
      if (a === undefined) return { reason: "adresse_inconnue" };
      const personne = e.session_identity === session;
      if (!admin && !personne) return { reason: "revocation_non_autorisee" };
      if (a.state !== "en_attente" && a.state !== "active") return { reason: "etat_incompatible" };
      a.state = "revoquee";
      a.revoked_at = at;
      a.revoked_by = session;
      a.revocation_cause = personne ? "personne" : "administrateur";
      a.revocation_reason = req.reason;
      a.replaced_by = null;
      inscrireOperation(doc, operation(doc, at, "revoquer", session, { entry: e.id, address: a.address, reason: req.reason }));
      return { reason: null, response: { entry: e.id, address: a.address, state: "revoquee", revision: doc.revision } };
    }
    case "desactiver": {
      if (!admin) return { reason: "non_administrateur" };
      const e = entree();
      if (e === undefined) return { reason: "entree_inconnue" };
      if (e.active !== true) return { reason: "etat_incompatible" };
      e.active = false;
      for (const a of e.addresses) {
        if (a.state === "en_attente" || a.state === "active") {
          a.state = "revoquee";
          a.revoked_at = at;
          a.revoked_by = session;
          a.revocation_cause = "desactivation";
          a.revocation_reason = null;
          a.replaced_by = null;
        }
      }
      inscrireOperation(doc, operation(doc, at, "desactiver", session, { entry: e.id, reason: req.reason }));
      return { reason: null, response: reponseEntree(doc, e), effacer: e.session_identity };
    }
    case "reactiver": {
      if (!admin) return { reason: "non_administrateur" };
      const e = entree();
      if (e === undefined) return { reason: "entree_inconnue" };
      if (e.active === true) return { reason: "etat_incompatible" };
      e.active = true;
      inscrireOperation(doc, operation(doc, at, "reactiver", session, { entry: e.id, reason: req.reason }));
      return { reason: null, response: reponseEntree(doc, e) };
    }
    case "lier_demandeur": {
      if (!admin) return { reason: "non_administrateur" };
      const e = entree();
      if (e === undefined) return { reason: "entree_inconnue" };
      if (doc.entries.some((x) => x.requester_identities.includes(req.launched_by))) return { reason: "demandeur_deja_lie" };
      if (e.requester_identities.length >= MAX_DEMANDEURS) return { reason: "limite_annuaire" };
      e.requester_identities.push(req.launched_by);
      inscrireOperation(doc, operation(doc, at, "lier_demandeur", session, { entry: e.id, launched_by: req.launched_by }));
      return { reason: null, response: reponseEntree(doc, e) };
    }
    case "delier_demandeur": {
      if (!admin) return { reason: "non_administrateur" };
      const e = entree();
      if (e === undefined) return { reason: "entree_inconnue" };
      const k = e.requester_identities.indexOf(req.launched_by);
      if (k < 0) return { reason: "demandeur_inconnu" };
      e.requester_identities.splice(k, 1);
      inscrireOperation(doc, operation(doc, at, "delier_demandeur", session, { entry: e.id, launched_by: req.launched_by }));
      return { reason: null, response: reponseEntree(doc, e) };
    }
    default:
      throw new TypeError(`methode inconnue : ${methode}`);
  }
}

const METHODES_OPERATION = Object.freeze([
  "preparer_inscription",
  "inscrire",
  "valider",
  "revoquer",
  "desactiver",
  "reactiver",
  "lier_demandeur",
  "delier_demandeur",
]);

/**
 * Applique une méthode de l'annuaire (EX-13.13, EX-13.15, EX-13.17), dans
 * l'ordre de ses vérifications, forme et identité d'abord.
 * @param {object} annuaire
 * @param {string} methode
 * @param {unknown} requete corps de la méthode
 * @param {string} at instant de l'horloge du service
 * @param {{defis?: object[], nonce?: string, identifiant?: "aleatoire"|"compteur"}} [options]
 * @returns {{annuaire: object, defis: object[], accepted: boolean, reason: string|null, response: object|null}}
 */
export function appliquerOperation(annuaire, methode, requete, at, options) {
  exigerAnnuaire(annuaire, "appliquerOperation");
  if (!METHODES_OPERATION.includes(methode)) throw new TypeError("appliquerOperation : methode de l'annuaire attendue");
  const t = instantParametre(at, "appliquerOperation (at)");
  const opts = lireOptions(options, "appliquerOperation");
  const defis = opts.defis === undefined ? [] : opts.defis;
  exigerDefis(defis, "appliquerOperation");
  const mode = modeIdentifiant(opts, "appliquerOperation");
  if (opts.nonce !== undefined && (typeof opts.nonce !== "string" || !/^[0-9a-f]{32}$/.test(opts.nonce))) {
    throw new TypeError("appliquerOperation : nonce de 32 chiffres hexadecimaux minuscules attendu");
  }
  const copieDefis = () => defis.map((d) => cloner(d));
  const refus = (reason, d = copieDefis()) => ({ annuaire, defis: d, accepted: false, reason, response: null });

  if (methode === "inscrire") {
    const v = verifierInscription(annuaire, defis, requete, at, { identifiant: mode });
    if (!v.accepted) return refus(v.reason, v.defis);
    const doc = cloner(annuaire);
    const response = effetInscription(doc, requete.session_identity, requete.address, requete.message, v.signature, at, v.entry);
    return { annuaire: doc, defis: v.defis, accepted: true, reason: null, response };
  }

  if (!formeRequete(methode, requete)) return refus("requete_invalide");
  if (!estIdentiteCanonique(requete.session_identity)) return refus("identite_invalide");

  if (methode === "preparer_inscription") {
    const e = annuaire.entries.find((x) => x.session_identity === requete.session_identity);
    if (e !== undefined && e.active !== true) return refus("identite_desactivee");
    if (annuaire.entries.some((x) => x.addresses.some((a) => a.address === requete.address))) return refus("adresse_deja_attribuee");
    const nonce = opts.nonce !== undefined ? opts.nonce : versHex(aleaOctets(16)).slice(2);
    const fields = {
      origin: annuaire.console_origin,
      org: annuaire.org,
      org_id: annuaire.org_id,
      identity: requete.session_identity,
      address: requete.address,
      issued_at: at,
      expires_at: encoderInstant(t + annuaire.registration_ttl_ms),
      nonce,
    };
    const message = messageInscription(fields);
    const apres = copieDefis().filter((d) => !(d.fields.identity === fields.identity && d.fields.address === fields.address));
    apres.push({ fields: cloner(fields), used: false });
    return { annuaire, defis: apres, accepted: true, reason: null, response: { fields, message } };
  }

  const doc = cloner(annuaire);
  const r = executer(doc, methode, requete, at, annuaire.administrators);
  if (r.reason !== null) return refus(r.reason);
  let apres = copieDefis();
  if (r.effacer !== undefined) apres = apres.filter((d) => d.fields.identity !== r.effacer);
  return { annuaire: doc, defis: apres, accepted: true, reason: null, response: r.response };
}

// ---------------------------------------------------------------------------
// Contrôles de la console (EX-13.18, EX-7.15)

/**
 * Contrôle de la console avant de demander la signature d'un vote ou
 * d'envoyer une récusation (EX-13.18, conditions 1 à 6, 1 à 5 pour
 * `recuser`), avec l'avertissement `separation_incomplete`.
 * @param {object} annuaire
 * @param {string} session identité de session
 * @param {"voter"|"recuser"} action
 * @param {string} adresse adresse choisie (comparée en minuscules)
 * @param {{launched_by: string|null, self_approval: string, policy_requester_addresses: string[], directory_requester_addresses: string[], members: string[]|null}} ticket
 * @returns {{allowed: boolean, reason: string|null, warnings: {code: "separation_incomplete", addresses: string[]}[]}}
 */
export function controleVote(annuaire, session, action, adresse, ticket) {
  exigerAnnuaire(annuaire, "controleVote");
  exigerChaine(session, "controleVote (session)");
  exigerChaine(adresse, "controleVote (adresse)");
  if (action !== "voter" && action !== "recuser") throw new TypeError("controleVote : action voter ou recuser attendue");
  if (
    !estObjet(ticket) ||
    !Array.isArray(ticket.policy_requester_addresses) ||
    !Array.isArray(ticket.directory_requester_addresses) ||
    !(ticket.members === null || Array.isArray(ticket.members))
  ) {
    throw new TypeError("controleVote : ticket attendu");
  }
  const declarees = new Set(ticket.policy_requester_addresses);
  const incompletes = [...new Set(ticket.directory_requester_addresses.filter((a) => !declarees.has(a)))].sort();
  const warnings = incompletes.length > 0 ? [{ code: "separation_incomplete", addresses: incompletes }] : [];
  const choisie = adresse.toLowerCase();
  const raison = (() => {
    if (ticket.members === null) return "jeu_non_fige";
    const e = annuaire.entries.find((x) => x.session_identity === session);
    if (e === undefined) return "identite_inconnue";
    if (e.active !== true) return "identite_desactivee";
    const active = e.addresses.find((x) => x.state === "active");
    if (active === undefined || active.address !== choisie) return "adresse_non_attribuee";
    if (!ticket.members.includes(choisie)) return "hors_jeu";
    if (action === "voter" && ticket.self_approval === "interdite" && e.requester_identities.includes(ticket.launched_by)) {
      return "session_du_demandeur";
    }
    return null;
  })();
  return { allowed: raison === null, reason: raison, warnings };
}

/**
 * L'objet `ticket` de `controleVote`, tiré de la vue du ticket
 * (`request.delegation.launched_by`, `separation`, `approver_set`).
 * @param {object} vue `$defs/vue_ticket`
 * @returns {{launched_by: string|null, self_approval: string, policy_requester_addresses: string[], directory_requester_addresses: string[], members: string[]|null}}
 */
export function ticketDeControleVote(vue) {
  if (!estObjet(vue) || !estObjet(vue.request) || !estObjet(vue.request.delegation) || !estObjet(vue.separation)) {
    throw new TypeError("ticketDeControleVote : vue du ticket attendue");
  }
  return {
    launched_by: vue.request.delegation.launched_by,
    self_approval: vue.separation.self_approval,
    policy_requester_addresses: [...vue.separation.requester_addresses],
    directory_requester_addresses: [...vue.separation.requester_directory_addresses],
    members: vue.approver_set === null ? null : [...vue.approver_set.members],
  };
}

/**
 * Le `by` d'un retrait que la console peut envoyer (EX-13.18, EX-7.15) : le
 * `launched_by` du ticket quand il figure dans `requester_identities` de
 * l'entrée active de la session, sinon l'identité de session quand elle est
 * dans `administrators`, sinon `null`.
 * @param {object} annuaire
 * @param {string} session
 * @param {{launched_by: string|null}} ticket
 * @returns {string|null}
 */
export function actionRetrait(annuaire, session, ticket) {
  exigerAnnuaire(annuaire, "actionRetrait");
  exigerChaine(session, "actionRetrait (session)");
  if (!estObjet(ticket)) throw new TypeError("actionRetrait : ticket attendu");
  const e = annuaire.entries.find((x) => x.session_identity === session && x.active === true);
  if (e !== undefined && typeof ticket.launched_by === "string" && e.requester_identities.includes(ticket.launched_by)) {
    return ticket.launched_by;
  }
  if (annuaire.administrators.includes(session)) return session;
  return null;
}

const METHODES_CONTROLE_CANAL = Object.freeze(["tickets", "consulter", "voter", "recuser", "retirer"]);

/**
 * Contrôle de l'identité de session par le service sur le canal de la console
 * (EX-12.13, EX-12.14, EX-12.16, EX-12.19), fait avant que l'entrée de 7.4 ne
 * soit formée. Rend `null`, ou la première raison : `requete_invalide` (forme
 * du corps, EX-12.13), `identite_invalide`, puis `session_non_autorisee` ou
 * `ticket_inconnu` dans l'ordre de la règle de la méthode.
 * @param {object} annuaire
 * @param {"tickets"|"consulter"|"voter"|"recuser"|"retirer"} methode
 * @param {unknown} requete
 * @param {{launched_by: string|null, eligible: string[]}|null} ticket nul pour un ticket inconnu dans l'organisation, et toujours pour `tickets`
 * @returns {null|"requete_invalide"|"identite_invalide"|"session_non_autorisee"|"ticket_inconnu"}
 */
export function controleCanal(annuaire, methode, requete, ticket) {
  exigerAnnuaire(annuaire, "controleCanal");
  if (!METHODES_CONTROLE_CANAL.includes(methode)) throw new TypeError("controleCanal : methode tickets, consulter, voter, recuser ou retirer attendue");
  if (ticket !== null && (!estObjet(ticket) || !Array.isArray(ticket.eligible))) throw new TypeError("controleCanal : ticket ou null attendu");
  if (!formeRequete(methode, requete)) return "requete_invalide";
  const session = requete.session_identity;
  if (!estIdentiteCanonique(session)) return "identite_invalide";
  const admin = annuaire.administrators.includes(session);
  const e = annuaire.entries.find((x) => x.session_identity === session && x.active === true);
  const active = e === undefined ? null : adresseActive(e);
  switch (methode) {
    case "tickets":
      return admin || e !== undefined ? null : "session_non_autorisee";
    case "consulter":
      if (!admin && e === undefined) return "session_non_autorisee";
      if (ticket === null) return "ticket_inconnu";
      if (admin || (active !== null && ticket.eligible.includes(active))) return null;
      return "session_non_autorisee";
    case "voter":
    case "recuser":
      if (active === null || active !== requete.approver) return "session_non_autorisee";
      if (ticket === null) return "ticket_inconnu";
      return null;
    case "retirer": {
      if (ticket === null) return "ticket_inconnu";
      const demandeur = e !== undefined && requete.by === ticket.launched_by && e.requester_identities.includes(ticket.launched_by);
      const administrateur = requete.by === session && admin;
      return demandeur || administrateur ? null : "session_non_autorisee";
    }
    default:
      throw new TypeError("methode inconnue");
  }
}

// ---------------------------------------------------------------------------
// Annuaire exporté (EX-13.19, EX-13.37)

// Forme minimale qu'il faut pour parcourir le document sans erreur ; le
// contrôle du schéma lui-même est celui de l'appelant (`conforme`).
function parcourable(d) {
  const ch = (v) => typeof v === "string";
  const chOuNul = (v) => v === null || typeof v === "string";
  const listeCh = (v) => Array.isArray(v) && v.every(ch);
  if (!estObjet(d)) return false;
  if (!ch(d.org) || !ch(d.org_id) || !ch(d.console_origin) || !Number.isSafeInteger(d.revision) || !chOuNul(d.updated_at)) return false;
  if (!listeCh(d.administrators) || !Array.isArray(d.entries) || !Array.isArray(d.operations)) return false;
  for (const e of d.entries) {
    if (!estObjet(e) || !ch(e.id) || !ch(e.session_identity) || typeof e.active !== "boolean" || !listeCh(e.requester_identities) || !ch(e.created_at)) return false;
    if (!Array.isArray(e.addresses)) return false;
    for (const a of e.addresses) {
      if (!estObjet(a) || !ch(a.address) || !ch(a.state) || !estObjet(a.proof)) return false;
      const p = a.proof;
      if (![p.message, p.signature, p.nonce, p.issued_at, p.expires_at, p.received_at].every(ch)) return false;
      if (![a.validated_at, a.validated_by, a.revoked_at, a.revoked_by, a.revocation_cause, a.revocation_reason, a.replaced_by].every(chOuNul)) return false;
    }
  }
  for (const o of d.operations) {
    if (!estObjet(o) || !Number.isSafeInteger(o.seq) || !ch(o.at) || !ch(o.op) || !ch(o.by)) return false;
    if (![o.entry, o.address, o.launched_by, o.reason].every(chOuNul)) return false;
    if (o.administrators !== null && !(estObjet(o.administrators) && listeCh(o.administrators.before) && listeCh(o.administrators.after))) return false;
  }
  return true;
}

// Point 4 : preuve canonique qui recouvre l'adresse (`preuve_invalide`) ;
// lignes concordantes (`preuve_discordante`).
function ecartsPreuve(d, e, a) {
  const p = a.proof;
  let champs = null;
  try {
    champs = analyserMessageInscription(p.message);
  } catch (x) {
    if (!(x instanceof ErreurConsole)) throw x;
  }
  if (champs === null) return ["preuve_invalide"];
  const codes = [];
  let canonique = /^0x[0-9a-f]{130}$/.test(p.signature);
  if (canonique) {
    const s = BigInt(`0x${p.signature.slice(66, 130)}`);
    const v = parseInt(p.signature.slice(130, 132), 16);
    canonique = (v === 27 || v === 28) && s <= N_SECP256K1 >> 1n;
  }
  if (!canonique || !verifierSignature(utf8Strict(p.message), p.signature, a.address).valide) codes.push("preuve_invalide");
  const recu = decoderInstant(p.received_at);
  const emis = decoderInstant(champs.issued_at);
  const expire = decoderInstant(champs.expires_at);
  const concorde =
    champs.origin === d.console_origin &&
    champs.org === d.org &&
    champs.org_id === d.org_id &&
    champs.identity === e.session_identity &&
    champs.address === a.address &&
    champs.nonce === p.nonce &&
    champs.issued_at === p.issued_at &&
    champs.expires_at === p.expires_at &&
    recu !== null &&
    emis <= recu &&
    recu < expire;
  if (!concorde) codes.push("preuve_discordante");
  return codes;
}

// Rejeu d'une opération `inscrire` (EX-13.19, point 6 : pas 3, 6 à 9 et 11 à
// 13 d'EX-13.15, identité et adresse du message comparées à `by` et à
// `address` de l'opération, preuve tirée du document exporté).
function rejouerInscription(d, travail, o) {
  if (o.address === null || o.entry === null || o.launched_by !== null || o.reason !== null || !estIdentiteCanonique(o.by)) return false;
  const source = d.entries.find((e) => e.id === o.entry);
  const adresse = source === undefined ? undefined : source.addresses.find((a) => a.address === o.address);
  if (adresse === undefined) return false;
  const message = adresse.proof.message;
  let champs;
  try {
    champs = analyserMessageInscription(message);
  } catch (x) {
    if (x instanceof ErreurConsole) return false;
    throw x;
  }
  if (champs.origin !== d.console_origin || champs.org !== d.org || champs.org_id !== d.org_id) return false;
  if (champs.identity !== o.by || champs.address !== o.address) return false;
  const v = verifierSignature(utf8Strict(message), adresse.proof.signature, o.address);
  if (!v.valide) return false;
  const existante = travail.entries.find((e) => e.session_identity === o.by);
  if (existante !== undefined && existante.active !== true) return false;
  if (travail.entries.some((e) => e.addresses.some((a) => a.address === o.address))) return false;
  if (existante !== undefined ? existante.id !== o.entry : travail.entries.some((e) => e.id === o.entry)) return false;
  effetInscription(travail, o.by, o.address, message, v.signature, o.at, o.entry);
  return true;
}

function rejouerOperation(d, travail, o, admins) {
  if (o.op === "changer_administrateurs") {
    if (o.by !== "configuration" || o.administrators === null || o.entry !== null || o.address !== null || o.launched_by !== null || o.reason !== null) return null;
    const { before, after } = o.administrators;
    if (!egaliteJson(before, admins) || egaliteJson(before, after) || !listeAdministrateursValide(after)) return null;
    return [...after];
  }
  if (o.administrators !== null) return null;
  if (o.op === "inscrire") return rejouerInscription(d, travail, o) ? admins : null;
  const formes = {
    valider: { session_identity: o.by, entry: o.entry, address: o.address },
    revoquer: { session_identity: o.by, entry: o.entry, address: o.address, reason: o.reason },
    desactiver: { session_identity: o.by, entry: o.entry, reason: o.reason },
    reactiver: { session_identity: o.by, entry: o.entry, reason: o.reason },
    lier_demandeur: { session_identity: o.by, entry: o.entry, launched_by: o.launched_by },
    delier_demandeur: { session_identity: o.by, entry: o.entry, launched_by: o.launched_by },
  };
  if (!aCle(formes, o.op)) return null;
  const req = formes[o.op];
  // Les membres que la méthode ne porte pas sont nuls dans l'opération.
  if ((o.op === "valider" && o.reason !== null) || (o.op !== "lier_demandeur" && o.op !== "delier_demandeur" && o.launched_by !== null)) return null;
  if ((o.op === "desactiver" || o.op === "reactiver") && o.address !== null) return null;
  if ((o.op === "lier_demandeur" || o.op === "delier_demandeur") && (o.address !== null || o.reason !== null)) return null;
  if (!formeRequete(o.op, req) || !estIdentiteCanonique(o.by)) return null;
  const r = executer(travail, o.op, req, o.at, admins);
  return r.reason === null ? admins : null;
}

const sansDonneesSansEffet = (entries) =>
  entries.map((e) => {
    const { external_id: _x, display_name: _d, ...reste } = e;
    return reste;
  });

/**
 * Vérifie hors ligne un annuaire exporté (EX-13.19, points 1 à 6 ;
 * EX-13.37) : la liste complète des écarts `{ code, pointer }`, triée par
 * pointeur puis par code (unités UTF-16) ; `[{ code: "schema", pointer: null }]`
 * pour un document non conforme.
 * @param {unknown} doc document exporté
 * @param {{conforme?: (doc: unknown) => boolean}} [options] contrôle du schéma `annuaire-approbateurs-v0` par l'appelant
 * @returns {{code: string, pointer: string|null}[]}
 */
export function verifierAnnuaireExporte(doc, options) {
  const opts = lireOptions(options, "verifierAnnuaireExporte");
  if (opts.conforme !== undefined && typeof opts.conforme !== "function") throw new TypeError("verifierAnnuaireExporte : conforme doit etre une fonction");
  if ((opts.conforme !== undefined && opts.conforme(doc) !== true) || !parcourable(doc)) return [{ code: "schema", pointer: null }];
  const d = doc;
  const ecarts = [];
  const ecart = (code, pointer) => ecarts.push({ code, pointer });

  // 2 : revision, seq, instants, updated_at.
  if (d.revision !== d.operations.length) ecart("revision_incoherente", "/revision");
  let precedent = null;
  d.operations.forEach((o, j) => {
    if (o.seq !== j + 1) ecart("revision_incoherente", `/operations/${j}/seq`);
    const t = decoderInstant(o.at);
    if (t === null || (precedent !== null && t < precedent)) ecart("revision_incoherente", `/operations/${j}/at`);
    if (t !== null) precedent = t;
  });
  const derniere = d.operations.length === 0 ? null : d.operations[d.operations.length - 1].at;
  if (d.updated_at !== derniere) ecart("revision_incoherente", "/updated_at");

  // 3 : identifiants, identités, adresses uniques ; une adresse active par entrée.
  const ids = new Set();
  const identites = new Set();
  const adresses = new Set();
  d.entries.forEach((e, i) => {
    if (ids.has(e.id)) ecart("identifiant_double", `/entries/${i}/id`);
    ids.add(e.id);
    if (identites.has(e.session_identity)) ecart("identite_double", `/entries/${i}/session_identity`);
    identites.add(e.session_identity);
    e.addresses.forEach((a, k) => {
      if (adresses.has(a.address)) ecart("adresse_double", `/entries/${i}/addresses/${k}/address`);
      adresses.add(a.address);
    });
    if (e.addresses.filter((a) => a.state === "active").length > 1) ecart("deux_adresses_actives", `/entries/${i}/addresses`);
  });

  // 4 et 5 : preuves ; validation par la personne de l'entrée.
  d.entries.forEach((e, i) => {
    e.addresses.forEach((a, k) => {
      for (const code of ecartsPreuve(d, e, a)) ecart(code, `/entries/${i}/addresses/${k}/proof`);
      if (a.validated_by !== null && a.validated_by === e.session_identity) ecart("auto_validation", `/entries/${i}/addresses/${k}/validated_by`);
    });
  });

  // 6 : rejeu des opérations depuis un annuaire vide.
  const premierChangement = d.operations.find((o) => o.op === "changer_administrateurs");
  let admins = premierChangement !== undefined && premierChangement.administrators !== null ? [...premierChangement.administrators.before] : [...d.administrators];
  const travail = { ...cloner({ ...d, entries: [], operations: [] }), revision: 0, updated_at: null };
  let echec = null;
  for (let j = 0; j < d.operations.length; j++) {
    const suivants = rejouerOperation(d, travail, d.operations[j], admins);
    if (suivants === null) {
      echec = j;
      break;
    }
    admins = suivants;
  }
  if (echec !== null) ecart("operations_incoherentes", `/operations/${echec}`);
  else if (!egaliteJson(admins, d.administrators)) ecart("operations_incoherentes", "/administrators");
  else if (!egaliteJson(sansDonneesSansEffet(travail.entries), sansDonneesSansEffet(d.entries))) ecart("operations_incoherentes", "/entries");

  const compare = (x, y) => (x < y ? -1 : x > y ? 1 : 0);
  return ecarts.sort((x, y) => compare(x.pointer, y.pointer) || compare(x.code, y.code));
}
