"use client";
// Bouton qui copie un texte exact dans le presse-papiers (complément du 2026-11-18, décision du porteur sur le
// langage des écrans) : le document à remettre aux approbateurs du client se copie tel quel, sans le sélectionner
// à la main ; de même, à la troisième lecture des écrans, l'adresse du compte technique et chaque empreinte qui se
// compare ou se transmet (`CopierValeur`). Rien n'est envoyé : la copie se fait par `navigator.clipboard.writeText`,
// appelé dans le clic. Si le navigateur la refuse (ou n'a pas de presse-papiers), le texte exact est sélectionné
// dans la page (s'il est dans un bloc replié, le bloc s'ouvre) et la phrase dit comment le copier au clavier. Aucun
// script ni style en ligne : la politique de sécurité du contenu reste celle d'INTERFACES.md 2.3.

import { useId, useState } from "react";

const COPIE = "Copié.";
const REPLI = "La copie automatique n'a pas pu se faire : le texte est sélectionné, copiez-le au clavier (Ctrl+C, ou Cmd+C sur Mac).";

/** Sélectionne dans la page le texte de l'élément `id` (et ouvre le bloc replié qui le cache) ; rend vrai s'il l'a pu. */
function selectionner(id) {
  const e = id ? document.getElementById(id) : null;
  if (!e) return false;
  for (let d = e.closest("details"); d; d = d.parentElement?.closest("details") ?? null) d.open = true;
  const s = window.getSelection();
  if (!s) return false;
  s.removeAllRanges();
  const r = document.createRange();
  r.selectNodeContents(e);
  s.addRange(r);
  return true;
}

/**
 * Bouton « Copier » : `texte` est copié tel quel ; `cible` est l'identifiant de l'élément qui l'affiche, sélectionné
 * si la copie est refusée. `faite` : phrase dite après une copie réussie.
 */
export default function CopierTexte({ texte, libelle = "Copier", cible = null, faite = COPIE, repli = REPLI, ...attributs }) {
  const [etat, setEtat] = useState("");
  const copier = async () => {
    try {
      if (!navigator.clipboard?.writeText) throw new Error("presse-papiers indisponible");
      await navigator.clipboard.writeText(texte);
      setEtat(faite);
    } catch {
      setEtat(selectionner(cible) ? repli : "La copie n'a pas pu se faire : sélectionnez le texte à la main, puis copiez-le.");
    }
  };
  return (
    <span className="ins-copier">
      <button type="button" className="nt-bouton nt-bouton-petit nt-sans-impression" onClick={copier} data-copier="" {...attributs}>{libelle}</button>
      <span className={etat ? "nt-attenue nt-petit" : "nt-masque"} role="status" data-copie-etat="">{etat}</span>
    </span>
  );
}

/**
 * Valeur exacte venue des données (adresse ou empreinte), affichée telle quelle et marquée `data-valeur`, suivie de
 * la fin de sa phrase (`suite`, par exemple le point) et de son bouton « Copier ». `forme` (« adresse » ou
 * « empreinte ») règle le repli sur téléphone : la valeur se coupe en deux moitiés égales au lieu de laisser quelques
 * caractères seuls sur la ligne suivante.
 */
export function CopierValeur({ valeur, forme = "adresse", libelle = "Copier", suite = null, ...attributs }) {
  const id = useId();
  return (
    <span className="ins-a-copier" data-a-copier={forme}>
      <span><span className={`nt-fixe ins-${forme}`} id={id} data-valeur="" {...attributs}>{valeur}</span>{suite}</span>
      <CopierTexte texte={valeur} libelle={libelle} cible={id} />
    </span>
  );
}
