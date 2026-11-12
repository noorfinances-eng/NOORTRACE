"use client";
// Écran de connexion : nom et mot de passe du compte d'exploitant (INTERFACES.md 1). Le mot de passe est celui du
// compte, jamais celui d'une clé ; il n'est envoyé qu'à POST /api/connexion.

import { useState } from "react";

export default function Connexion() {
  const [message, setMessage] = useState("");
  const envoyer = async (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.currentTarget);
    setMessage("vérification…");
    const r = await fetch("/api/connexion", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: String(f.get("name") ?? ""), password: String(f.get("password") ?? "") }) });
    if (r.status === 204) {
      window.location.assign("/clients");
      return;
    }
    const corps = await r.json().catch(() => null);
    if (r.status === 429) setMessage(`trop d'échecs récents : réessayer dans ${corps?.error?.data?.retry_after_s ?? "quelques"} s`);
    else setMessage("nom ou mot de passe refusé");
  };
  return (
    <form onSubmit={envoyer}>
      <label>
        <span>Nom du compte</span>
        <input name="name" data-type="texte" autoComplete="username" required maxLength={255} />
      </label>
      <label>
        <span>Mot de passe du compte d'exploitant</span>
        <input name="password" type="password" data-type="mot_de_passe_compte" autoComplete="current-password" required maxLength={1024} />
      </label>
      <button type="submit">Se connecter</button>
      <p className="refus" role="status">{message}</p>
    </form>
  );
}
