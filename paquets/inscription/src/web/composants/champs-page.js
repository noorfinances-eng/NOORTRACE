// Contrôle des champs dans la page, pour l'affichage seulement (INTERFACES.md 2.1) : les mêmes fonctions que le
// serveur (src/commun/champs.mjs, src/commun/references.mjs) ; le serveur et l'agent refont chaque contrôle.

import * as C from "../../commun/champs.mjs";
import { lireReference } from "../../commun/references.mjs";

/** Lit la valeur d'un champ de type déclaré ; rend `{ valeur }` ou `{ erreur }` (message sans la valeur). */
export function lireChamp(champ, brut) {
  const texte = typeof brut === "string" ? brut.trim() : brut;
  try {
    switch (champ.type) {
      case "adresse": return { valeur: C.adresse(champ.nom, texte, { nonNulle: false }) };
      case "liste_adresses": return { valeur: texte.split(/[\s,]+/).filter(Boolean).map((a, k) => C.adresse(`${champ.nom}[${k}]`, a, { nonNulle: false })) };
      case "hachage": return { valeur: C.hachage(champ.nom, texte) };
      case "cle_publique_ed25519": return { valeur: C.clePubliqueEd25519(champ.nom, texte) };
      case "slug": return { valeur: C.slug(champ.nom, texte) };
      case "nom_journal": return { valeur: C.nomJournal(champ.nom, texte) };
      case "liste_noms_journal": return { valeur: texte.split(/[\s,]+/).filter(Boolean).map((n, k) => C.nomJournal(`${champ.nom}[${k}]`, n)) };
      case "seuil": return { valeur: C.seuil(champ.nom, Number(texte)) };
      case "entier": return { valeur: C.entier(champ.nom, /^[0-9]{1,15}$/.test(texte) ? Number(texte) : NaN, { min: 0 }) };
      case "montant": return { valeur: C.montant(champ.nom, texte, { min: 1n }).toString() };
      case "reference_cle": lireReference(champ.nom, texte); return { valeur: texte };
      case "texte": return { valeur: C.texte(champ.nom, texte) };
      case "chemin": return { valeur: C.cheminRelatif(champ.nom, texte) };
      case "document": return { valeur: C.objet(champ.nom, JSON.parse(texte)) };
      case "liste_documents": { const l = JSON.parse(texte); if (!Array.isArray(l)) throw new C.ErreurChamp("requete_invalide", champ.nom, "tableau JSON attendu"); return { valeur: l }; }
      case "identite": return { valeur: texte };
      case "liste_identites": return { valeur: texte.split(/\n+/).map((x) => x.trim()).filter(Boolean) };
      // Une ligne par valeur, une ligne vide gardée vide (les noms des approbateurs suivent l'ordre des adresses).
      case "liste_textes": return { valeur: texte.split(/\r?\n/).map((x, k) => (x.trim() === "" ? "" : C.texte(`${champ.nom}[${k}]`, x.trim(), { max: 80 }))) };
      case "origine": return { valeur: texte };
      default: return { erreur: `${champ.nom} : type non déclaré (EX-7.25)` };
    }
  } catch (e) {
    return { erreur: e instanceof SyntaxError ? `${champ.nom} : JSON illisible` : e.message };
  }
}

/**
 * Membres qu'exige une fiche d'enregistreur (`inscription-client-v0#/$defs/cle_enregistreur`, `required` ; CT-2
 * EX-11.13). La page ne s'en sert que pour dire tôt qu'un texte collé n'est pas une fiche ; le serveur et l'agent
 * contrôlent la fiche entière contre son schéma.
 */
export const MEMBRES_FICHE = Object.freeze(["key_id", "journal_id", "algorithm", "public_key", "custody_class", "backend_type", "created_at", "chain_key", "chain_key_class", "origin_proof"]);

/**
 * Lit les fiches d'enregistreur d'un champ `liste_documents` saisi en une zone par fiche (complément du 2026-11-18,
 * troisième lecture des écrans) : chaque zone porte le contenu d'un fichier du client, tel quel ; la page assemble
 * la liste, dans l'ordre des zones. Rend `{ valeur }` (la liste, celle qu'aurait donnée la saisie à la main de
 * « [ fiche, fiche ] » dans une seule zone) ou `{ erreur, zone, regle, erreurs }` : la première zone fautive (0 pour
 * la première zone) et sa règle (`fiche_vide`, `fiche_liste`, `fiche_illisible`), et dans `erreurs` chaque zone
 * fautive, sans la valeur refusée.
 */
export function lireFiches(champ, textes) {
  const valeur = [];
  // Chaque zone est lue ; toutes les zones fautives sont rendues dans `erreurs` (cinquième lecture des écrans : la
  // page signale tout d'un coup), la première aussi dans `erreur`, `zone` et `regle`.
  const erreurs = [];
  for (const [zone, brut] of textes.entries()) {
    const texte = String(brut ?? "").trim();
    const refus = (regle) => erreurs.push({ erreur: `${champ.nom}[${zone}] : ${regle}`, zone, regle });
    if (texte === "") { refus("fiche_vide"); continue; }
    let v;
    try {
      v = JSON.parse(texte);
    } catch {
      refus("fiche_illisible");
      continue;
    }
    if (Array.isArray(v)) { refus("fiche_liste"); continue; }
    if (v === null || typeof v !== "object" || MEMBRES_FICHE.some((m) => !Object.hasOwn(v, m))) { refus("fiche_illisible"); continue; }
    valeur.push(v);
  }
  return erreurs.length > 0 ? { ...erreurs[0], erreurs } : { valeur };
}

/**
 * Empreinte SHA-256 d'un fichier choisi dans la page (CT-4 EX-7.25, complément du 2026-11-18) : le fichier est lu
 * dans le navigateur et son empreinte calculée par `crypto.subtle.digest`, sans rien envoyer ni garder. Un seul
 * calcul pour l'aide « Choisir la pièce » du formulaire de confirmation et pour « Calculer l'empreinte d'une pièce »,
 * hors du formulaire (quatrième lecture des écrans). Rend `0x` suivi de 64 chiffres hexadécimaux en minuscules.
 */
export async function empreinteFichier(fichier) {
  const condense = await window.crypto.subtle.digest("SHA-256", await fichier.arrayBuffer());
  return `0x${[...new Uint8Array(condense)].map((x) => x.toString(16).padStart(2, "0")).join("")}`;
}
