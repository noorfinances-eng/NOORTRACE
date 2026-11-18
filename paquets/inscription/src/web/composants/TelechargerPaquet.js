"use client";
// Téléchargement du paquet du client (GET /api/clients/<slug>/paquet, INTERFACES.md 4.2). Le lien reste un lien :
// sans script, il télécharge l'archive comme avant. Avec script (complément du 2026-11-18, décision du porteur sur
// le langage des écrans), la page demande l'archive elle-même, pour qu'un refus du contrôle refait à chaque
// téléchargement se lise en clair sur cet écran, et non comme une réponse brute : ce qui s'est passé, quoi faire,
// le code et le message exacts au détail. La route et sa réponse ne changent pas.

import { useState } from "react";
import { Refus } from "./FormulaireTravail.js";

export default function TelechargerPaquet({ slug }) {
  const [etat, setEtat] = useState({ attente: false, refus: null, fait: false });
  const adresse = `/api/clients/${slug}/paquet`;
  const telecharger = async (ev) => {
    ev.preventDefault();
    setEtat({ attente: true, refus: null, fait: false });
    let r;
    try {
      r = await fetch(adresse);
    } catch {
      setEtat({ attente: false, refus: { code: "outil_injoignable", message: "aucune réponse de l'outil au téléchargement du paquet" }, fait: false });
      return;
    }
    if (!r.ok) {
      const corps = await r.json().catch(() => null);
      setEtat({ attente: false, refus: { code: corps?.error?.code ?? `http_${r.status}`, message: corps?.error?.message ?? `refus (${r.status})` }, fait: false });
      return;
    }
    const url = URL.createObjectURL(await r.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = `paquet-client-${slug}.tar`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    setEtat({ attente: false, refus: null, fait: true });
  };
  return (
    <div className="nt-pile">
      <div className="nt-actions">
        <a className="nt-bouton nt-bouton-principal" href={adresse} onClick={telecharger} aria-disabled={etat.attente ? "true" : undefined}>Télécharger le paquet</a>
      </div>
      <p className={etat.attente || etat.fait ? "nt-attenue nt-petit" : "nt-masque"} role="status">{etat.attente ? "Contrôle du paquet, puis téléchargement…" : etat.fait ? "Paquet contrôlé et téléchargé : il est dans les téléchargements de votre navigateur." : ""}</p>
      {etat.refus ? <Refus code={etat.refus.code} message={etat.refus.message} titre="Le paquet n'a pas été téléchargé." /> : null}
    </div>
  );
}
