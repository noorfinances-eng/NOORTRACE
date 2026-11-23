"use client";
// Recherche dans la liste des clients (sixième lecture des écrans ; CT-4 EX-7.25, complément du 2026-11-18) : un texte
// cherché dans le nom interne et le nom court de chaque client déjà affiché. La recherche se fait dans la page, sur
// la liste que le serveur a rendue : aucune requête ne part, rien n'est gardé. L'élément n'a pas de nom de champ,
// n'est envoyé à aucune route et ne remplit aucun champ ; il ne fait que masquer les cartes qui ne correspondent pas.
// `cles` : pour chaque carte, dans l'ordre, `{ slug, nom }` (nom interne, ou null) ; `children` : les cartes.

import { Children, useId, useState } from "react";

/** Texte comparé : en minuscules, sans accent, espaces réduits. */
export const normaliser = (t) => String(t ?? "").normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase().replace(/\s+/g, " ").trim();

export default function RechercheClients({ cles, children }) {
  const id = useId();
  const [cherche, setCherche] = useState("");
  const cartes = Children.toArray(children);
  const q = normaliser(cherche);
  const garde = cles.map((c) => q === "" || normaliser(c.nom).includes(q) || normaliser(c.slug).includes(q));
  const vues = garde.filter(Boolean).length;
  return (
    <>
      <div className="nt-champ ins-recherche" role="search">
        <label className="nt-libelle" htmlFor={`${id}-recherche`}>Chercher un client</label>
        <input id={`${id}-recherche`} type="search" className="nt-saisie" autoComplete="off" spellCheck={false} data-recherche-clients="" aria-describedby={`${id}-aide ${id}-compte`} value={cherche} onChange={(e) => setCherche(e.target.value)} />
        <p className="nt-aide" id={`${id}-aide`}>Écrivez une partie de son nom interne ou de son nom court. La liste se réduit à mesure, sur cet écran ; rien n'est envoyé.</p>
        <p className="nt-attenue nt-petit" id={`${id}-compte`} role="status" aria-live="polite" data-recherche-compte="">{q === "" ? `${cles.length} ${cles.length > 1 ? "clients" : "client"}.` : `${vues} ${vues > 1 ? "clients correspondent" : vues === 1 ? "client correspond" : "client ne correspond"} à « ${cherche.trim()} », sur ${cles.length}.`}</p>
      </div>
      {vues === 0 ? <p className="nt-encart" data-recherche-vide="">Aucun client ne correspond. Vérifiez l'orthographe, ou effacez la recherche pour revoir tous les clients.</p> : null}
      <div className="ins-clients">
        {cartes.map((carte, k) => (garde[k] ? carte : null))}
      </div>
    </>
  );
}
