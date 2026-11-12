"use client";
// Formulaire d'ajout d'une confirmation hors bande (EX-7.26) : opération, objet (clé de chaîne visée par un
// approvisionnement, ou condensé de la demande d'administration du jeu), personne du client qui a confirmé, canal (hors
// de l'application), instant, SHA-256 de la pièce qui la porte. L'agent y ajoute l'exploitant de la session et
// l'instant de réception. Chaque champ porte un type de la liste close d'EX-7.25.

import { useState } from "react";
import { lireChamp } from "./champs-page.js";

export default function FormulaireConfirmation({ slug, orgId, clesChaine }) {
  const [message, setMessage] = useState("");
  const envoyer = async (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.currentTarget);
    const champs = [
      { nom: "cle_chaine", type: "adresse" }, { nom: "personne_client", type: "texte" }, { nom: "canal", type: "texte" }, { nom: "piece_sha256", type: "hachage" },
    ];
    const v = {};
    for (const c of champs) {
      const r = lireChamp(c, String(f.get(c.nom) ?? ""));
      if (r.erreur) return setMessage(r.erreur);
      v[c.nom] = r.valeur;
    }
    const instant = String(f.get("instant") ?? "").trim();
    const operation = String(f.get("operation"));
    let objet = { org_id: orgId, cle_chaine: v.cle_chaine };
    if (operation === "administrer-jeu") {
      const d = lireChamp({ nom: "digest", type: "hachage" }, String(f.get("digest") ?? ""));
      if (d.erreur) return setMessage(d.erreur);
      objet = { org_id: orgId, digest: d.valeur };
    }
    const confirmation = { operation, objet, personne_client: v.personne_client, canal: v.canal, instant, piece_sha256: v.piece_sha256 };
    const r = await fetch(`/api/clients/${slug}/confirmations`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(confirmation) });
    const corps = await r.json().catch(() => null);
    if (!r.ok) return setMessage(corps?.error?.message ?? `refus (${r.status})`);
    setMessage(`confirmation ${corps.id} inscrite`);
    window.location.reload();
  };
  return (
    <form onSubmit={envoyer}>
      <label><span>Opération</span>
        <select name="operation" data-type="texte"><option value="approvisionnement">approvisionnement (pas 5)</option><option value="approvisionner">approvisionner (8.7)</option><option value="administrer-jeu">administrer-jeu (8.5)</option></select>
      </label>
      <label><span>Clé de chaîne visée (approvisionnement)</span>
        <select name="cle_chaine" data-type="adresse">{clesChaine.map((c) => <option key={c} value={c}>{c}</option>)}</select>
      </label>
      <label><span>Condensé de la demande d'administration du jeu (administrer-jeu)</span><input name="digest" data-type="hachage" /></label>
      <label><span>Personne du client qui a confirmé</span><input name="personne_client" data-type="texte" required maxLength={256} /></label>
      <label><span>Canal, hors de l'application</span><input name="canal" data-type="texte" required maxLength={256} /></label>
      <label><span>Instant de la confirmation (AAAA-MM-JJThh:mm:ss.sssZ)</span><input name="instant" data-type="texte" required /></label>
      <label><span>SHA-256 de la pièce qui porte la confirmation</span><input name="piece_sha256" data-type="hachage" required /></label>
      <button type="submit">Inscrire la confirmation</button>
      <p role="status">{message}</p>
    </form>
  );
}
