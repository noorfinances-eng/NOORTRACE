"use client";
// Bouton de déconnexion (POST /api/deconnexion).

export default function Deconnexion() {
  const sortir = async () => {
    await fetch("/api/deconnexion", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    window.location.assign("/connexion");
  };
  return <button type="button" onClick={sortir}>Se déconnecter</button>;
}
