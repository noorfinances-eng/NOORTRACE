"use client";
// Écran de connexion : nom et mot de passe du compte d'exploitant (INTERFACES.md 1). Le mot de passe est celui du
// compte, jamais celui d'une clé ; il n'est envoyé qu'à POST /api/connexion.

import { useState } from "react";
import Icone from "./Icone.js";

export default function Connexion() {
  const [etat, setEtat] = useState({ attente: false, refus: "" });
  const envoyer = async (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.currentTarget);
    setEtat({ attente: true, refus: "" });
    const r = await fetch("/api/connexion", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: String(f.get("name") ?? ""), password: String(f.get("password") ?? "") }) });
    if (r.status === 204) {
      window.location.assign("/clients");
      return;
    }
    const corps = await r.json().catch(() => null);
    if (r.status === 429) setEtat({ attente: false, refus: `Trop d'essais : réessayez dans ${corps?.error?.data?.retry_after_s ?? "quelques"} s.` });
    else setEtat({ attente: false, refus: "Nom ou mot de passe refusé." });
  };
  return (
    <form className="nt-formulaire" onSubmit={envoyer}>
      {etat.refus ? (
        <div className="nt-bandeau nt-bandeau-erreur" role="alert">
          <Icone nom="alerte" />
          <div className="nt-bandeau-texte"><p className="nt-bandeau-titre">{etat.refus}</p></div>
        </div>
      ) : null}
      <div className="nt-champ">
        <label className="nt-libelle" htmlFor="connexion-nom">Nom du compte</label>
        <input className="nt-saisie" id="connexion-nom" name="name" data-type="texte" autoComplete="username" required maxLength={255} />
      </div>
      <div className="nt-champ">
        <label className="nt-libelle" htmlFor="connexion-mot-de-passe">Mot de passe du compte</label>
        <input className="nt-saisie" id="connexion-mot-de-passe" name="password" type="password" data-type="mot_de_passe_compte" autoComplete="current-password" required maxLength={1024} aria-describedby="connexion-aide" />
        <p className="nt-aide" id="connexion-aide">Le mot de passe de votre compte d'exploitant. Jamais celui d'une clé : aucune clé ne se saisit dans cet outil.</p>
      </div>
      <div className="nt-actions">
        <button type="submit" className="nt-bouton nt-bouton-principal" disabled={etat.attente}>Se connecter</button>
      </div>
      <p className={etat.attente ? "nt-attenue nt-petit" : "nt-masque"} role="status">{etat.attente ? "Vérification…" : ""}</p>
    </form>
  );
}
