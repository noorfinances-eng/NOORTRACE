// Travaux typés et confirmations hors bande (CT-4 EX-7.23, EX-7.26 ;
// INTERFACES.md 3.3, 3.5) : forme de chaque travail que l'interface remet à
// l'agent, et de chaque confirmation, contrôlée champ par champ par
// `champs.mjs`. L'interface s'en sert avant de remettre ; l'agent la refait
// à la réception et ne croit pas l'interface (EX-7.23).
//
// `lireTravail` et `lireConfirmation` rendent une forme normalisée (adresses
// en minuscules, montants en `bigint` sérialisés en décimal) ou lèvent
// `ErreurChamp` (`requete_invalide` ou `reference_refusee`), dont le
// message ne recopie jamais une valeur refusée.

import * as C from "./champs.mjs";
import { lireReference } from "./references.mjs";
import { registreSchemas, IDS } from "./schemas.mjs";

const { ErreurChamp } = C;

/** Commandes offertes à l'étape 6 (INTERFACES.md 0.1, 3.3). */
export const COMMANDES = Object.freeze([
  "inscrire-client-preparer", "inscrire-client", "approvisionner", "condense-inscription", "inscrire-cle", "capturer", "exporter", "verifier", "paquet",
  "condense-administration", "administrer-jeu",
]);

/** `command` de la sortie de l'outil correspondant à chaque commande (EX-7.24 ; `paquet` : EX-7.30, révision 0.7). */
export const COMMANDE_OUTIL = Object.freeze({
  "inscrire-client-preparer": "inscrire-client",
  "inscrire-client": "inscrire-client",
  approvisionner: "approvisionner",
  "condense-inscription": "condense",
  "inscrire-cle": "inscrire-cle",
  capturer: "capturer",
  exporter: "exporter",
  verifier: "verifier",
  paquet: "paquet-client",
  "condense-administration": "condense",
  "administrer-jeu": "administrer-jeu",
});

/** Opérations du jeu d'un client (CT-4 §6.6.2, RG-11) et la forme de leur argument. */
export const OPERATIONS_JEU = Object.freeze({
  "CuratorSet.addCurator": "adresse",
  "CuratorSet.removeCurator": "adresse",
  "CuratorSet.setThreshold": "entier",
  "CuratorSet.proposeAdmin": "adresse",
  "CuratorSet.acceptAdmin": "aucun",
});

/** Opérations d'une confirmation hors bande (EX-7.26, INTERFACES.md 3.5). */
export const OPERATIONS_CONFIRMATION = Object.freeze(["approvisionnement", "approvisionner", "administrer-jeu"]);

/** Identité d'un exploitant (INTERFACES.md 1) : `exploitant <name>`, nom du fichier des comptes. */
export const MOTIF_IDENTITE = /^exploitant [!-~]{1,255}$/;

const MOTIF_HORODATAGE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;

function clesExactes(champ, o, admises, requises = []) {
  C.objet(champ, o);
  for (const k of Object.keys(o)) if (!admises.includes(k)) throw new ErreurChamp("requete_invalide", champ, `membre inconnu ${JSON.stringify(k).slice(0, 40)}`);
  for (const k of requises) if (!(k in o)) throw new ErreurChamp("requete_invalide", champ, `membre ${k} absent`);
}

function documentCleEnregistreur(champ, v) {
  C.objet(champ, v);
  const r = registreSchemas().valider(`${IDS.inscription}#/$defs/cle_enregistreur`, v);
  if (!r.valide) throw new ErreurChamp("requete_invalide", champ, `document cle_enregistreur hors de son schéma (${r.erreurs[0]?.pointeur || "/"} : ${r.erreurs[0]?.regle})`);
  return v;
}

/** Document JSON contrôlé contre son schéma (EX-7.25, révision 0.7 : type « document »). */
function documentControle(champ, v, ref) {
  C.objet(champ, v);
  const r = registreSchemas().valider(ref, v);
  if (!r.valide) throw new ErreurChamp("requete_invalide", champ, `document hors de son schéma (${r.erreurs[0]?.pointeur || "/"} : ${r.erreurs[0]?.regle})`);
  return v;
}

function origineOuNull(champ, v) {
  if (v === null) return null;
  const r = registreSchemas().valider(`${IDS.annuaire}#/$defs/origine`, v);
  if (!r.valide) throw new ErreurChamp("requete_invalide", champ, "origine HTTPS attendue (annuaire-approbateurs-v0#/$defs/origine), ou null");
  return v;
}

function administrateursOuNull(champ, v) {
  if (v === null) return null;
  const r = registreSchemas().valider(`${IDS.annuaire}#/$defs/liste_administrateurs`, v);
  if (!r.valide) throw new ErreurChamp("requete_invalide", champ, "liste d'identités de session attendue (annuaire-approbateurs-v0#/$defs/liste_administrateurs), ou null");
  return v;
}

/** Paramètres de chaque commande : `lire(parametres, contexte)` rend les paramètres normalisés. */
const PARAMETRES = {
  "inscrire-client-preparer"(p, { slug, production }) {
    clesExactes("parametres", p, ["org", "journaux", "approbateurs", "seuil", "admin_jeu", "cles_enregistreur", "budget_jour", "tresorerie", "cles_essai"], ["org", "journaux", "seuil"]);
    const org = C.slug("parametres.org", p.org, { production });
    if (org !== slug) throw new ErreurChamp("requete_invalide", "slug", "le slug du travail doit égaler parametres.org");
    const sortie = {
      org,
      journaux: C.liste("parametres.journaux", p.journaux, C.nomJournal, { min: 1, max: 16 }),
      seuil: C.seuil("parametres.seuil", p.seuil),
    };
    if ("cles_essai" in p) {
      if (production) throw new ErreurChamp("reference_refusee", "parametres.cles_essai", "clés d'essai refusées hors du réseau de développement (EX-7.3)");
      for (const k of ["approbateurs", "admin_jeu", "cles_enregistreur"]) {
        if (k in p) throw new ErreurChamp("requete_invalide", `parametres.${k}`, "les clés d'essai donnent déjà ce membre");
      }
      // Chemin relatif sous le répertoire du client, sans composant . ni .. (EX-7.25, révision 0.7).
      sortie.cles_essai = C.cheminRelatif("parametres.cles_essai", p.cles_essai);
    } else {
      for (const k of ["approbateurs", "admin_jeu", "cles_enregistreur"]) {
        if (!(k in p)) throw new ErreurChamp("requete_invalide", `parametres.${k}`, "membre absent (sans clés d'essai)");
      }
      // Forme seulement : l'adresse nulle, un double ou un ordre quelconque sont jugés par OP-4 (EX-7.24 : même refus que l'outil).
      const adresseLibre = (champ, v) => C.adresse(champ, v, { nonNulle: false });
      sortie.approbateurs = C.liste("parametres.approbateurs", p.approbateurs, adresseLibre, { min: 1, max: 64 });
      sortie.admin_jeu = adresseLibre("parametres.admin_jeu", p.admin_jeu);
      sortie.cles_enregistreur = C.liste("parametres.cles_enregistreur", p.cles_enregistreur, documentCleEnregistreur, { min: 0, max: 16 });
    }
    if ("budget_jour" in p) sortie.budget_jour = C.montant("parametres.budget_jour", p.budget_jour, { min: 1n }).toString();
    if ("tresorerie" in p) sortie.tresorerie = lireReferenceTexte("parametres.tresorerie", p.tresorerie);
    return sortie;
  },
  "inscrire-client"(p) {
    clesExactes("parametres", p, []);
    return {};
  },
  approvisionner(p) {
    clesExactes("parametres", p, ["cle_chaine", "budget_jour"], ["cle_chaine"]);
    const s = { cle_chaine: C.adresse("parametres.cle_chaine", p.cle_chaine) };
    if ("budget_jour" in p) s.budget_jour = C.montant("parametres.budget_jour", p.budget_jour, { min: 1n }).toString();
    return s;
  },
  "condense-inscription"(p) {
    clesExactes("parametres", p, ["key_id"], ["key_id"]);
    return { key_id: C.keyId("parametres.key_id", p.key_id) };
  },
  "inscrire-cle"(p) {
    clesExactes("parametres", p, ["demande", "cle_chaine", "relayeur"], ["demande"]);
    const s = { demande: C.objet("parametres.demande", p.demande) };
    const avecRelayeur = "relayeur" in p ? C.booleen("parametres.relayeur", p.relayeur) : false;
    if (avecRelayeur && "cle_chaine" in p) throw new ErreurChamp("requete_invalide", "parametres", "cle_chaine ou relayeur, pas les deux");
    if (!avecRelayeur && !("cle_chaine" in p)) throw new ErreurChamp("requete_invalide", "parametres.cle_chaine", "référence de la clé de chaîne attendue (ou relayeur)");
    if (avecRelayeur) s.relayeur = true;
    else s.cle_chaine = lireReferenceTexte("parametres.cle_chaine", p.cle_chaine);
    return s;
  },
  capturer(p) {
    clesExactes("parametres", p, ["transaction", "envoi"]);
    const n = ("transaction" in p ? 1 : 0) + ("envoi" in p ? 1 : 0);
    if (n !== 1) throw new ErreurChamp("requete_invalide", "parametres", "transaction ou envoi attendu, un seul");
    return "transaction" in p ? { transaction: C.hachage("parametres.transaction", p.transaction) } : { envoi: C.hachage("parametres.envoi", p.envoi) };
  },
  exporter(p) {
    clesExactes("parametres", p, ["manifeste", "cles"], ["manifeste"]);
    const s = { manifeste: C.cheminRelatif("parametres.manifeste", p.manifeste) };
    if ("cles" in p) s.cles = C.cheminRelatif("parametres.cles", p.cles);
    return s;
  },
  verifier(p) {
    clesExactes("parametres", p, ["parties", "manifeste", "ancres"], ["parties", "manifeste"]);
    const s = { parties: C.cheminRelatif("parametres.parties", p.parties), manifeste: C.cheminRelatif("parametres.manifeste", p.manifeste) };
    if ("ancres" in p) s.ancres = C.cheminRelatif("parametres.ancres", p.ancres);
    return s;
  },
  "condense-administration"(p) {
    clesExactes("parametres", p, ["op", "arg"], ["op"]);
    if (typeof p.op !== "string" || !(p.op in OPERATIONS_JEU)) throw new ErreurChamp("requete_invalide", "parametres.op", `opération du jeu attendue : ${Object.keys(OPERATIONS_JEU).join(", ")}`);
    const forme = OPERATIONS_JEU[p.op];
    if (forme === "aucun") {
      if ("arg" in p) throw new ErreurChamp("requete_invalide", "parametres.arg", "CuratorSet.acceptAdmin n'a pas d'argument");
      return { op: p.op };
    }
    if (!("arg" in p)) throw new ErreurChamp("requete_invalide", "parametres.arg", "argument de l'opération attendu");
    return { op: p.op, arg: forme === "adresse" ? C.adresse("parametres.arg", p.arg) : C.entier("parametres.arg", p.arg, { min: 1, max: 64 }) };
  },
  "administrer-jeu"(p) {
    clesExactes("parametres", p, ["demande", "relayeur", "expediteur"], ["demande"]);
    const s = { demande: documentControle("parametres.demande", p.demande, `${IDS.operations}#/$defs/demande_signature`) };
    const avecRelayeur = "relayeur" in p ? C.booleen("parametres.relayeur", p.relayeur) : false;
    if (avecRelayeur && "expediteur" in p) throw new ErreurChamp("requete_invalide", "parametres", "expediteur ou relayeur, pas les deux");
    if (!avecRelayeur && !("expediteur" in p)) throw new ErreurChamp("requete_invalide", "parametres.expediteur", "référence de la clé expéditrice attendue (ou relayeur)");
    if (avecRelayeur) s.relayeur = true;
    else s.expediteur = lireReferenceTexte("parametres.expediteur", p.expediteur);
    return s;
  },
  paquet(p) {
    clesExactes("parametres", p, ["prepared_by", "console_origin", "administrators"], ["prepared_by", "console_origin", "administrators"]);
    return {
      prepared_by: C.texte("parametres.prepared_by", p.prepared_by, { max: 256 }),
      console_origin: origineOuNull("parametres.console_origin", p.console_origin),
      administrators: administrateursOuNull("parametres.administrators", p.administrators),
    };
  },
};

/** Lit une référence de clé et la rend sous sa forme texte (aucune valeur résolue). */
function lireReferenceTexte(champ, v) {
  lireReference(champ, v);
  return v;
}

/**
 * Lit un travail typé `{ commande, slug, parametres }` (sans identité).
 * `contexte.production` : vrai si l'instance est de nature production
 * (slug `o-…`, clés d'essai refusées). Rend le travail normalisé.
 */
export function lireTravail(travail, { production = false } = {}) {
  clesExactes("travail", travail, ["commande", "slug", "parametres"], ["commande", "slug", "parametres"]);
  if (typeof travail.commande !== "string" || !COMMANDES.includes(travail.commande)) throw new ErreurChamp("requete_invalide", "travail.commande", `commande inconnue ; admises : ${COMMANDES.join(", ")}`);
  // Le slug d'un client existant suit la grammaire de RG-1 ; la forme de production n'est exigée qu'à la préparation.
  const slug = C.slug("travail.slug", travail.slug, { production: production && travail.commande === "inscrire-client-preparer" });
  const parametres = PARAMETRES[travail.commande](travail.parametres, { slug, production });
  return { commande: travail.commande, slug, parametres };
}

/** Lit un horodatage RFC 3339 à trois décimales en UTC (CT-1 §3). */
export function horodatage(champ, v) {
  if (typeof v !== "string" || !MOTIF_HORODATAGE.test(v) || Number.isNaN(Date.parse(v))) throw new ErreurChamp("requete_invalide", champ, "horodatage AAAA-MM-JJThh:mm:ss.sssZ attendu");
  return v;
}

/**
 * Lit une confirmation hors bande (EX-7.26, INTERFACES.md 3.5) :
 * `{ operation, objet: { org_id, cle_chaine }, personne_client, canal,
 * instant, piece_sha256 }`.
 */
export function lireConfirmation(c) {
  clesExactes("confirmation", c, ["operation", "objet", "personne_client", "canal", "instant", "piece_sha256"], ["operation", "objet", "personne_client", "canal", "instant", "piece_sha256"]);
  if (!OPERATIONS_CONFIRMATION.includes(c.operation)) throw new ErreurChamp("requete_invalide", "confirmation.operation", "approvisionnement, approvisionner ou administrer-jeu attendu");
  // Objet (EX-7.26) : la clé de chaîne d'un approvisionnement, ou le condensé de la demande d'administration du jeu.
  const membre = c.operation === "administrer-jeu" ? "digest" : "cle_chaine";
  clesExactes("confirmation.objet", c.objet, ["org_id", membre], ["org_id", membre]);
  const objet = { org_id: C.hachage("confirmation.objet.org_id", c.objet.org_id) };
  if (membre === "digest") objet.digest = C.hachage("confirmation.objet.digest", c.objet.digest);
  else objet.cle_chaine = C.adresse("confirmation.objet.cle_chaine", c.objet.cle_chaine);
  return {
    operation: c.operation,
    objet,
    personne_client: C.texte("confirmation.personne_client", c.personne_client, { max: 256 }),
    canal: C.texte("confirmation.canal", c.canal, { max: 256 }),
    instant: horodatage("confirmation.instant", c.instant),
    piece_sha256: C.hachage("confirmation.piece_sha256", c.piece_sha256),
  };
}

/** Lit l'identité d'un exploitant (`exploitant <name>`). */
export function lireIdentite(v) {
  if (typeof v !== "string" || !MOTIF_IDENTITE.test(v)) throw new ErreurChamp("requete_invalide", "exploitant", "identité « exploitant <nom> » attendue");
  return v;
}
