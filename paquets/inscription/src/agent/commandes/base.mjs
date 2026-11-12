// Vérifications et ressources communes aux commandes de l'agent : OP-2 puis
// OP-1 (CT-4 §7.3 : « OP-2 avant OP-1 »), clés des comptes de l'exploitant
// par rôle (EX-3.1, EX-7.3), dossier du client, lectures d'état du registre
// des jeux (`isRegistered`, `curatorSetOf`, `admin`), confirmations hors
// bande (EX-7.26).

import fs from "node:fs";
import { keccak256, octetsVersHex, utf8 } from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";
import { op1, op2, lecture } from "../reseau.mjs";
import { signataire, ErreurReference } from "../cles.mjs";
import { lireDossier } from "../dossier.mjs";
import * as J from "../jeu.mjs";
import { ajouterLigne, lireLignes } from "../donnees.mjs";
import { ecrireHorodatage } from "@noortrace/noyau";

/** Rôle d'un compte de l'exploitant dans la configuration → rôle de `accounts` du manifeste (EX-3.1). */
export const ROLES_MANIFESTE = Object.freeze({ deployeur: "deployeur", administrateur: "administrateur_registre", tresorerie: "tresorerie", relayeur: "relayeur" });

const ZERO20 = "0x" + "00".repeat(20);

/** `keccak256(utf8(s))` en hexadécimal. */
export const keccakTexte = (s) => octetsVersHex(keccak256(utf8(s)));

/** OP-2 puis OP-1 (EX-4.9) ; consignés dans la sortie, ou arrêt de la commande. */
export async function prealables(ctx, sortie) {
  const r2 = await op2(ctx.rpc, { nature: ctx.instance.nature });
  // Un point injoignable arrête tout ; un index de suiveur est consigné, OP-1 s'exécute encore, puis la commande
  // s'arrête sur la première vérification en échec (même conduite que l'outil de référence).
  if (!r2.ok && r2.code !== "noeud_suiveur") sortie.echec("OP-2", "inutilisable", r2.code, r2.detail);
  if (r2.ok) sortie.reussie("OP-2");
  else sortie.noter("OP-2", "echoue", r2.detail);
  if (ctx.instance.manifeste === null) {
    // EX-7.2 : sans manifeste, seul le réseau de développement (0x84c) est admis.
    const c = await ctx.rpc.appelerPremier("eth_chainId", []).catch(() => null);
    if (!c || c.erreur || c.resultat !== "0x84c") sortie.arreter("refuse", "reseau_non_developpement", "OP-1", `eth_chainId ${c?.resultat ?? "illisible"} : sans manifeste, seul le réseau de développement 0x84c est admis (EX-7.2)`);
  }
  const r1 = await op1(ctx.rpc, ctx.instance, { attendre: ctx.attendre });
  if (!r1.ok) {
    const resultat = r1.code === "noeud_injoignable" || r1.code === "inutilisable" ? "inutilisable" : /^certificat_/.test(r1.code) ? "incertain" : "refuse";
    if (!r2.ok) sortie.noter("OP-1", "echoue", r1.detail);
    else sortie.echec("OP-1", resultat, r1.code === "inutilisable" ? "certificat_indisponible" : r1.code, r1.detail);
  } else sortie.reussie("OP-1");
  if (!r2.ok) sortie.arreter("refuse", r2.code, "OP-2", r2.detail);
}

/**
 * Référence de la clé d'un rôle : celle du travail, sinon celle de la
 * configuration (`comptes.<rôle>`, ou `comptes.exploitant` qui tient les
 * quatre rôles sur les réseaux 2124 et 31337, EX-7.3). Rend `{ reference,
 * role }` ou null.
 */
export function referenceRole(ctx, role, reference = null) {
  if (reference) return { reference, role };
  const c = ctx.config.comptes ?? {};
  if (c[role]) return { reference: c[role], role };
  if (c.exploitant) return { reference: c.exploitant, role: "exploitant" };
  return null;
}

/**
 * Résout la clé d'un rôle ; arrêt `usage` si aucune n'est désignée ou si la
 * référence ne se résout pas. Une référence résolue est consignée
 * (`reference_employee` : travail, client, rôle, référence, jamais la clé) :
 * la recherche d'EX-7.21 du paquet porte sur les références qu'ont employées
 * les travaux du client.
 */
export function cleRole(ctx, sortie, role, reference = null, { option = role } = {}) {
  const r = referenceRole(ctx, role, reference);
  if (!r) sortie.arreter("inutilisable", "usage", null, `${option} (ou exploitant sur le réseau de développement) est obligatoire`);
  try {
    const s = signataire(r.reference, { role: r.role, nature: ctx.instance.nature, evmChainId: ctx.instance.evmChainId });
    ctx.consigner?.("reference_employee", { id: ctx.travailId ?? null, slug: ctx.slug ?? null, role: r.role, reference: r.reference });
    return s;
  } catch (e) {
    if (e instanceof ErreurReference) sortie.arreter(e.code === "reseau_non_developpement" ? "refuse" : "inutilisable", e.code === "reseau_non_developpement" ? "reseau_non_developpement" : "usage", null, e.message);
    throw e;
  }
}

/**
 * OP-5, première partie : l'adresse de la clé d'un rôle est celle de son rôle
 * dans `accounts` du manifeste à la tête (EX-3.1) ; hors du réseau de
 * développement, deux rôles n'ont pas la même adresse. Rend null ou le
 * message d'écart.
 */
export function ecartCompte(ctx, role, adresse) {
  const attendu = ctx.instance.comptes[ROLES_MANIFESTE[role]];
  const nom = { deployeur: "déployeur", administrateur: "administrateur du registre", tresorerie: "trésorerie", relayeur: "relayeur" }[role];
  if (!attendu) return `aucun compte de rôle ${ROLES_MANIFESTE[role]} dans le manifeste`;
  if (attendu !== adresse) return `${nom} ${adresse} ≠ compte de rôle ${ROLES_MANIFESTE[role]} ${attendu}`;
  return null;
}

/** Hors du réseau de développement, deux rôles employés n'ont pas la même adresse (EX-3.1). */
export function ecartRolesDistincts(ctx, adresses) {
  if (ctx.instance.nature === "developpement") return null;
  const vus = new Map();
  for (const [role, a] of Object.entries(adresses)) {
    if (vus.has(a)) return `${vus.get(a)} et ${role} sous la même adresse ${a} hors du réseau de développement (EX-3.1)`;
    vus.set(a, role);
  }
  return null;
}

/** Lit le dossier du client ; arrêt `entree_illisible` (OP-4) s'il est hors de son schéma, `usage` s'il manque. */
export function dossierClient(ctx, sortie) {
  if (!fs.existsSync(ctx.client.dossier)) sortie.arreter("inutilisable", "usage", null, `aucun dossier pour le client ${ctx.slug}`);
  const l = lireDossier(ctx.client.dossier);
  if (l.erreur) sortie.echec("OP-4", "inutilisable", "entree_illisible", l.erreur);
  return l.dossier;
}

/** Lectures d'état du registre des jeux et d'un jeu, à une hauteur (`latest` par défaut). */
export const etat = {
  async isRegistered(ctx, orgId, h = "latest") {
    return J.decoderMot(await lecture(ctx.rpc, ctx.instance.contrats.curator_set_registry, J.encoderIsRegistered(orgId), h)) === 1n;
  },
  async curatorSetOf(ctx, orgId, h = "latest") {
    const a = J.decoderAdresse(await lecture(ctx.rpc, ctx.instance.contrats.curator_set_registry, J.encoderCuratorSetOf(orgId), h));
    if (a === null) throw new R.ErreurLecture("retour_illisible", "curatorSetOf illisible");
    return a;
  },
  async adminRegistre(ctx, h = "latest") {
    const a = J.decoderAdresse(await lecture(ctx.rpc, ctx.instance.contrats.curator_set_registry, J.encoderAdmin(), h));
    if (a === null) throw new R.ErreurLecture("retour_illisible", "admin() illisible");
    return a;
  },
  async adminJeu(ctx, jeu, h = "latest") {
    return J.decoderAdresse(await lecture(ctx.rpc, jeu, J.encoderAdmin(), h));
  },
  async seuil(ctx, jeu, h = "latest") {
    return J.decoderMot(await lecture(ctx.rpc, jeu, J.encoderGetThreshold(), h));
  },
  async taille(ctx, jeu, h = "latest") {
    return J.decoderMot(await lecture(ctx.rpc, jeu, J.encoderGetCuratorCount(), h));
  },
  async estMembre(ctx, jeu, a, h = "latest") {
    return J.decoderMot(await lecture(ctx.rpc, jeu, J.encoderIsCurator(a), h)) === 1n;
  },
};

/**
 * Confirmations hors bande inscrites et non consommées pour une opération et
 * une clé de chaîne d'une organisation (EX-7.26). Une confirmation n'autorise
 * qu'un approvisionnement (relecture de l'étape 6, R4 : EX-7.26 et EX-8.21
 * demandent la confirmation avant *tout* approvisionnement) : le versement
 * qui s'en sert la consomme par une ligne `{ consommation, travail, org_id,
 * cle_chaine, instant }` du même registre, en ajout seul.
 */
export function confirmationsPour(ctx, { operations, orgId, cleChaine = null, digest = null }) {
  const lignes = lireLignes(ctx.donnees.confirmations);
  const consommees = new Set(lignes.filter((l) => typeof l.consommation === "string").map((l) => l.consommation));
  const objet = (o) => (digest !== null ? o?.digest === digest : o?.cle_chaine === cleChaine);
  return lignes.filter((c) => typeof c.id === "string" && !consommees.has(c.id) && operations.includes(c.operation) && c.objet?.org_id === orgId && objet(c.objet));
}

/** Aucune confirmation non consommée au moment d'un versement : le travail est refusé, sans sortie (EX-7.26). */
export class ConfirmationAbsente extends Error {
  constructor(message) {
    super(message);
    this.name = "ConfirmationAbsente";
  }
}

/**
 * Consomme, juste avant un versement, la plus ancienne confirmation non
 * consommée qui l'autorise ; lève `ConfirmationAbsente` s'il n'y en a pas
 * (l'agent ne croit pas l'admission faite à la remise). Rend son `id`.
 */
export function consommerConfirmation(ctx, { operations, orgId, cleChaine = null, digest = null }) {
  const c = confirmationsPour(ctx, { operations, orgId, cleChaine, digest })[0];
  if (!c) throw new ConfirmationAbsente(digest !== null ? `confirmation hors bande absente pour la demande d'administration du jeu ${digest} (EX-7.26)` : `confirmation hors bande absente pour l'approvisionnement de ${cleChaine} (EX-7.26)`);
  ajouterLigne(ctx.donnees.confirmations, { consommation: c.id, travail: ctx.travailId, org_id: orgId, ...(digest !== null ? { digest } : { cle_chaine: cleChaine }), instant: ecrireHorodatage(ctx.horloge.murale()) });
  return c.id;
}

export { ZERO20 };
