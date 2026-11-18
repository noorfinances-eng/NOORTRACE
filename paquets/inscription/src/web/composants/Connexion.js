"use client";
// Écran de connexion : nom et mot de passe du compte (INTERFACES.md 1). Le mot de passe est celui du compte,
// jamais celui d'une clé ; il n'est envoyé qu'à POST /api/connexion. Langage (complément du 2026-11-18) : chaque
// refus dit ce qui s'est passé et quoi faire.

import { useState } from "react";
import Icone from "./Icone.js";

const REFUS = {
  identifiants: { titre: "Nom ou mot de passe refusé.", texte: "Vérifiez le nom du compte et les majuscules du mot de passe, puis réessayez. Après cinq erreurs de suite, l'outil fait attendre avant chaque nouvel essai. Mot de passe oublié : demandez à l'équipe technique, elle seule peut le changer." },
  injoignable: { titre: "L'outil ne répond pas.", texte: "Vérifiez que votre poste est bien relié au réseau, puis réessayez. Si cela dure, prévenez l'équipe technique." },
  autre: { titre: "La connexion n'a pas pu se faire.", texte: "Rechargez la page, puis réessayez. Si cela dure, prévenez l'équipe technique en lui donnant le détail ci-dessous." },
};

export default function Connexion() {
  const [etat, setEtat] = useState({ attente: false, refus: null });
  const envoyer = async (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.currentTarget);
    setEtat({ attente: true, refus: null });
    let r;
    try {
      r = await fetch("/api/connexion", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: String(f.get("name") ?? ""), password: String(f.get("password") ?? "") }) });
    } catch {
      setEtat({ attente: false, refus: REFUS.injoignable });
      return;
    }
    if (r.status === 204) {
      window.location.assign("/clients");
      return;
    }
    const corps = await r.json().catch(() => null);
    if (r.status === 429) {
      const n = corps?.error?.data?.retry_after_s;
      const delai = Number.isSafeInteger(n) ? `${n} ${n > 1 ? "secondes" : "seconde"}` : "quelques secondes";
      setEtat({ attente: false, refus: { titre: `Trop d'essais : attendez ${delai} avant de réessayer.`, texte: "L'outil ralentit les essais après plusieurs erreurs, pour protéger votre compte. Votre compte n'est pas fermé." } });
    } else if (r.status === 401) setEtat({ attente: false, refus: REFUS.identifiants });
    else setEtat({ attente: false, refus: { ...REFUS.autre, code: corps?.error?.code ?? `http_${r.status}`, message: corps?.error?.message ?? `réponse ${r.status}` } });
  };
  return (
    <form className="nt-formulaire" onSubmit={envoyer}>
      {etat.refus ? (
        <div className="nt-bandeau nt-bandeau-erreur" role="alert">
          <Icone nom="alerte" />
          <div className="nt-bandeau-texte">
            <p className="nt-bandeau-titre">{etat.refus.titre}</p>
            <p>{etat.refus.texte}</p>
            {etat.refus.code ? (
              <details className="ins-detail">
                <summary>Détail à transmettre</summary>
                <dl className="nt-definitions ins-detail-corps">
                  <dt>Code</dt><dd><span className="nt-fixe">{etat.refus.code}</span></dd>
                  <dt>Message exact</dt><dd><span className="nt-fixe">{etat.refus.message}</span></dd>
                </dl>
              </details>
            ) : null}
          </div>
        </div>
      ) : null}
      <div className="nt-champ">
        <label className="nt-libelle" htmlFor="connexion-nom">Nom de votre compte</label>
        <input className="nt-saisie" id="connexion-nom" name="name" data-type="texte" autoComplete="username" required maxLength={255} aria-describedby="connexion-nom-aide" />
        <p className="nt-aide" id="connexion-nom-aide">Le nom que l'équipe technique vous a donné pour cet outil.</p>
      </div>
      <div className="nt-champ">
        <label className="nt-libelle" htmlFor="connexion-mot-de-passe">Mot de passe de votre compte</label>
        <input className="nt-saisie" id="connexion-mot-de-passe" name="password" type="password" data-type="mot_de_passe_compte" autoComplete="current-password" required maxLength={1024} aria-describedby="connexion-aide" />
        <p className="nt-aide" id="connexion-aide">C'est le seul secret que cet outil vous demande. Il ne vous demandera jamais une clé secrète de signature.</p>
      </div>
      <div className="nt-actions">
        <button type="submit" className="nt-bouton nt-bouton-principal" disabled={etat.attente}>Se connecter</button>
      </div>
      <p className={etat.attente ? "nt-attenue nt-petit" : "nt-masque"} role="status">{etat.attente ? "Vérification en cours…" : ""}</p>
    </form>
  );
}
