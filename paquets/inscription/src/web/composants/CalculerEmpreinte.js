"use client";
// « Calculer l'empreinte d'une pièce — rien n'est enregistré » (complément du 2026-11-18, quatrième lecture des
// écrans ; CT-4 EX-7.25, complément de même date) : sur l'écran des confirmations, hors du formulaire qui note une
// confirmation, la personne choisit un fichier ; la page le lit et calcule son empreinte SHA-256 dans le navigateur,
// par le même calcul que l'aide « Choisir la pièce » (`empreinteFichier`), puis l'affiche et dit si c'est celle de la
// pièce d'une confirmation de la liste. Le fichier ne part nulle part et n'est gardé nulle part ; aucune requête ne
// part ; aucun champ n'est rempli. L'élément de choix du fichier n'a pas de nom de champ et porte le type de la
// valeur qu'il fait calculer (`hachage`, EX-7.25).

import { useRef, useState } from "react";
import { empreinteFichier } from "./champs-page.js";
import { CopierValeur } from "./CopierTexte.js";

const taille = (n) => (n < 1024 ? "moins de 1 Ko" : n < 1024 * 1024 ? `${Math.round(n / 1024)} Ko` : `${(n / 1024 / 1024).toFixed(1).replace(".", ",")} Mo`);

/** `pieces` : `[{ empreinte, libelle }]`, la pièce de chaque confirmation de la liste et ce qui la désigne en mots. */
export default function CalculerEmpreinte({ pieces = [] }) {
  const fichier = useRef(null);
  const [resultat, setResultat] = useState(null);
  const calculer = async (ev) => {
    const f = ev.target.files?.[0];
    ev.target.value = "";
    if (!f) return;
    if (!window.crypto?.subtle) {
      setResultat({ erreur: "Ce navigateur ne sait pas calculer l'empreinte ici. Demandez à l'équipe technique de la calculer pour vous." });
      return;
    }
    try {
      setResultat({ nom: f.name, taille: f.size, empreinte: await empreinteFichier(f) });
    } catch {
      setResultat({ erreur: "Le fichier n'a pas pu être lu. Vérifiez qu'il est bien sur votre poste et réessayez." });
    }
  };
  const memes = resultat?.empreinte ? pieces.filter((p) => p.empreinte.toLowerCase() === resultat.empreinte) : [];
  return (
    <div className="nt-encart nt-pile ins-calculer" data-calculer-empreinte="">
      <div className="ins-aide-saisie">
        <input ref={fichier} type="file" hidden tabIndex={-1} data-type="hachage" onChange={calculer} data-calcul-piece="" aria-hidden="true" />
        <button type="button" className="nt-bouton" onClick={() => fichier.current?.click()} data-calculer="">Calculer l'empreinte d'une pièce — rien n'est enregistré</button>
      </div>
      <p className="nt-aide">Choisissez le fichier de la pièce sur votre poste : l'outil calcule son empreinte ici même et la compare à celles des pièces ci-dessous. Le fichier ne quitte pas votre poste, et rien n'est noté.</p>
      <div role="status" aria-live="polite" data-empreinte-calculee="">
        {resultat?.erreur ? <p className="nt-aide">{resultat.erreur}</p> : null}
        {resultat?.empreinte ? (
          <>
            <p>Empreinte de <span className="nt-fixe" data-valeur="">{resultat.nom}</span> ({taille(resultat.taille)}), calculée sur votre poste :</p>
            <CopierValeur valeur={resultat.empreinte} forme="empreinte" libelle="Copier l'empreinte" data-empreinte-fichier="" />
            <p data-comparaison={memes.length > 0 ? "identique" : "differente"}>
              {memes.length > 0
                ? `Identique à l'empreinte de la pièce ${memes.length > 1 ? "de ces confirmations" : "de cette confirmation"} : ${memes.map((p) => p.libelle).join(" ; ")}. C'est bien la même pièce.`
                : "Elle ne correspond à la pièce d'aucune confirmation de cette liste."}
            </p>
          </>
        ) : null}
      </div>
    </div>
  );
}
