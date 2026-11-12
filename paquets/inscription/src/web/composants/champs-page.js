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
      case "origine": return { valeur: texte };
      default: return { erreur: `${champ.nom} : type non déclaré (EX-7.25)` };
    }
  } catch (e) {
    return { erreur: e instanceof SyntaxError ? `${champ.nom} : JSON illisible` : e.message };
  }
}
