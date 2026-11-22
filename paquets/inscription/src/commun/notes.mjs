// Notes internes de l'application d'exploitant (CT-4 EX-7.23, complément du 2026-11-19, décision du porteur sur le
// suivi interne des clients ; INTERFACES.md 2.6 et 3.7) : le nom interne d'un client et la remise de son paquet.
//
// Une note n'est ni un travail ni une confirmation : aucun pas de CT-4 7.1 ni aucune commande ne la lit. Elle reste
// dans l'application : l'agent la garde, en ajout seul, dans `notes-internes.ndjson` de ses données, hors du
// répertoire des clients ; elle ne part jamais vers le registre public et n'entre dans aucun dossier, aucune sortie,
// aucune partie ni le paquet.
//
// Trois sortes :
// - `nom_interne` : `{ nom }`, un texte de 1 à 80 caractères (type texte d'EX-7.25), ou null pour retirer le nom ;
//   le dernier en date vaut ; les précédents restent dans le registre ;
// - `remise_paquet` : `{ manifest_sha256 }`, le SHA-256 du manifeste du paquet remis (EX-7.19) ; une déclaration de
//   l'exploitant, rien de plus ;
// - `correction_remise` : `{ remise, motif }`, l'identifiant de la remise corrigée et le motif (texte, 1 à 300
//   caractères) ; la remise reste lisible, marquée corrigée.
//
// Module pur : la route et l'agent lisent la forme par `lireCorpsNote` et `lireNote` ; l'interface et l'agent
// interprètent le registre par `etatNotes`.

import * as C from "./champs.mjs";
import { ErreurChamp } from "./champs.mjs";

/** Sortes de note (complément du 2026-11-19). */
export const SORTES_NOTE = Object.freeze(["nom_interne", "remise_paquet", "correction_remise"]);
/** Longueur d'un nom interne, en caractères. */
export const NOM_INTERNE_MAX = 80;
/** Longueur du motif d'une correction, en caractères. */
export const MOTIF_CORRECTION_MAX = 300;
/** Identifiant d'une note : `not-` et 32 chiffres hexadécimaux. */
export const MOTIF_ID_NOTE = /^not-[0-9a-f]{32}$/;
/** Nom du registre des notes dans les données de l'agent (INTERFACES.md 3.6). */
export const FICHIER_NOTES = "notes-internes.ndjson";

const MEMBRES = Object.freeze({
  nom_interne: ["nom"],
  remise_paquet: ["manifest_sha256"],
  correction_remise: ["remise", "motif"],
});

function exacts(champ, o, membres) {
  C.objet(champ, o);
  for (const k of Object.keys(o)) if (!membres.includes(k)) throw new ErreurChamp("requete_invalide", champ, `membre inconnu ${JSON.stringify(k).slice(0, 40)}`);
  for (const k of membres) if (!(k in o)) throw new ErreurChamp("requete_invalide", champ, `membre ${k} absent`);
}

/** Les membres propres à une sorte, contrôlés (la valeur refusée n'est jamais recopiée). */
function membresDeSorte(champ, n) {
  switch (n.sorte) {
    case "nom_interne": {
      if (n.nom === null) return { nom: null };
      const nom = C.texte(`${champ}.nom`, n.nom, { max: NOM_INTERNE_MAX });
      if (nom.trim() !== nom || nom.trim() === "") throw new ErreurChamp("requete_invalide", `${champ}.nom`, "nom sans espace au début ni à la fin attendu");
      return { nom };
    }
    case "remise_paquet":
      return { manifest_sha256: C.hachage(`${champ}.manifest_sha256`, n.manifest_sha256) };
    case "correction_remise": {
      if (typeof n.remise !== "string" || !MOTIF_ID_NOTE.test(n.remise)) throw new ErreurChamp("requete_invalide", `${champ}.remise`, "identifiant not- et 32 chiffres hexadécimaux attendu");
      const motif = C.texte(`${champ}.motif`, n.motif, { max: MOTIF_CORRECTION_MAX });
      if (motif.trim() === "") throw new ErreurChamp("requete_invalide", `${champ}.motif`, "motif non vide attendu");
      return { remise: n.remise, motif };
    }
    default:
      throw new ErreurChamp("requete_invalide", `${champ}.sorte`, `${SORTES_NOTE.join(", ")} attendu`);
  }
}

/**
 * Corps reçu par `POST /api/clients/<slug>/notes` (INTERFACES.md 2.3) : `{ sorte, …membres de la sorte }`, sans
 * l'organisation, que la route prend du dossier du client. Rend la note normalisée ou lève `ErreurChamp`.
 */
export function lireCorpsNote(n) {
  C.objet("note", n);
  if (!SORTES_NOTE.includes(n.sorte)) throw new ErreurChamp("requete_invalide", "note.sorte", `${SORTES_NOTE.join(", ")} attendu`);
  exacts("note", n, ["sorte", ...MEMBRES[n.sorte]]);
  return { sorte: n.sorte, ...membresDeSorte("note", n) };
}

/** Note remise à l'agent (INTERFACES.md 3.2) : `{ sorte, org_id, …membres de la sorte }`. Rend la note normalisée ou lève `ErreurChamp`. */
export function lireNote(n) {
  C.objet("note", n);
  if (!SORTES_NOTE.includes(n.sorte)) throw new ErreurChamp("requete_invalide", "note.sorte", `${SORTES_NOTE.join(", ")} attendu`);
  exacts("note", n, ["sorte", "org_id", ...MEMBRES[n.sorte]]);
  return { sorte: n.sorte, org_id: C.hachage("note.org_id", n.org_id), ...membresDeSorte("note", n) };
}

/**
 * Ce que les notes disent d'un client, d'après les lignes du registre (dans l'ordre de leur écriture) :
 * `{ nom, noms, remises }`.
 * - `nom` : le nom interne en vigueur, `{ id, valeur, exploitant, recu_a }`, ou null (aucun, ou retiré) ;
 * - `noms` : chaque note de nom, dans l'ordre (`valeur` null pour un retrait) ;
 * - `remises` : chaque remise, dans l'ordre, `{ id, manifest_sha256, exploitant, recu_a, correction }`, `correction`
 *   valant `{ id, motif, exploitant, recu_a }` ou null.
 * Une ligne illisible ou d'une autre organisation est ignorée ; une correction qui ne vise pas une remise de ce
 * client, non encore corrigée, aussi (l'agent ne l'écrit pas).
 */
export function etatNotes(lignes, orgId) {
  const noms = [];
  const remises = [];
  for (const l of Array.isArray(lignes) ? lignes : []) {
    if (!l || typeof l !== "object" || l.org_id !== orgId || typeof l.id !== "string") continue;
    const auteur = { id: l.id, exploitant: typeof l.exploitant === "string" ? l.exploitant : "", recu_a: typeof l.recu_a === "string" ? l.recu_a : "" };
    if (l.sorte === "nom_interne" && (l.nom === null || typeof l.nom === "string")) noms.push({ ...auteur, valeur: l.nom });
    else if (l.sorte === "remise_paquet" && typeof l.manifest_sha256 === "string") remises.push({ ...auteur, manifest_sha256: l.manifest_sha256, correction: null });
    else if (l.sorte === "correction_remise" && typeof l.motif === "string") {
      const r = remises.find((x) => x.id === l.remise && x.correction === null);
      if (r) r.correction = { ...auteur, motif: l.motif };
    }
  }
  const dernier = noms.length > 0 ? noms[noms.length - 1] : null;
  return { nom: dernier && dernier.valeur !== null ? dernier : null, noms, remises };
}

/** La remise en vigueur (non corrigée) d'un paquet, la dernière notée, ou null. */
export function remiseEnVigueur(etat, manifestSha256) {
  if (!manifestSha256) return null;
  const l = (etat?.remises ?? []).filter((r) => r.manifest_sha256 === manifestSha256 && r.correction === null);
  return l.length > 0 ? l[l.length - 1] : null;
}
