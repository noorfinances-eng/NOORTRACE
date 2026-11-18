"use client";
// Bouton de déconnexion (POST /api/deconnexion).

export default function Deconnexion() {
  const sortir = async () => {
    await fetch("/api/deconnexion", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }).catch(() => null);
    window.location.assign("/connexion");
  };
  return <button type="button" className="nt-bouton nt-bouton-petit nt-sans-impression" onClick={sortir}>Se déconnecter</button>;
}
