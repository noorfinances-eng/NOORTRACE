"use client";
// Formulaire d'un travail typé (INTERFACES.md 3.3) : chaque champ a un type déclaré de la liste close d'EX-7.25
// (attribut data-type), contrôlé dans la page pour l'affichage puis par le serveur et l'agent. Un champ à `options`
// est une liste de choix de ce type ; `parametre` nomme le paramètre du travail quand il diffère du champ ; `oui`
// fait d'un choix de texte un paramètre booléen (vrai si la valeur choisie est `oui`, absent sinon). Le travail est remis par POST /api/travaux ; la page
// suit son état par GET /api/travaux/<id> et affiche la sortie de la commande. Aucun champ ne reçoit une clé, une
// graine, une mnémonique, un jeton ni un mot de passe de clé : une clé se désigne par une référence (EX-7.3).

import { useState } from "react";
import { lireChamp } from "./champs-page.js";

const ATTENTE_MS = 1000;

function Champ({ champ }) {
  const commun = { name: champ.nom, "data-type": champ.type, required: !champ.facultatif, defaultValue: champ.defaut ?? undefined, autoComplete: "off", spellCheck: false };
  let entree;
  if (champ.options) entree = <select {...commun}>{champ.options.map((o) => <option key={o.valeur} value={o.valeur}>{o.libelle}</option>)}</select>;
  else if (["liste_adresses", "liste_noms_journal", "document", "liste_documents", "liste_identites"].includes(champ.type)) entree = <textarea {...commun} />;
  else entree = <input {...commun} type={champ.type === "seuil" ? "number" : "text"} placeholder={champ.exemple ?? ""} />;
  return (
    <label>
      <span>{champ.libelle}{champ.facultatif ? " (facultatif)" : ""}</span>
      {entree}
    </label>
  );
}

export default function FormulaireTravail({ titre, commande, slug, champs = [], fixe = {}, bouton = "Remettre le travail à l'agent" }) {
  const [etat, setEtat] = useState({ message: "", travail: null });
  const suivre = async (id) => {
    for (;;) {
      const r = await fetch(`/api/travaux/${id}`);
      const t = await r.json();
      setEtat({ message: `travail ${id} : ${t.etat}`, travail: t });
      if (["fini", "refuse", "abandonne"].includes(t.etat)) return;
      await new Promise((ok) => setTimeout(ok, ATTENTE_MS));
    }
  };
  const envoyer = async (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.currentTarget);
    const parametres = { ...fixe };
    for (const c of champs) {
      const brut = String(f.get(c.nom) ?? "");
      const cle = c.parametre ?? c.nom;
      if (c.oui) {
        if (brut === "oui") parametres[cle] = true;
        continue;
      }
      if (c.nullSiVide && brut.trim() === "") {
        parametres[cle] = null;
        continue;
      }
      if (c.facultatif && brut.trim() === "") continue;
      const v = lireChamp(c, brut);
      if (v.erreur) {
        setEtat({ message: v.erreur, travail: null });
        return;
      }
      if (c.nullSiVide && (v.valeur === "" || (Array.isArray(v.valeur) && v.valeur.length === 0))) parametres[cle] = null;
      else parametres[cle] = v.valeur;
    }
    const slugTravail = commande === "inscrire-client-preparer" ? parametres.org : slug;
    const r = await fetch("/api/travaux", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ commande, slug: slugTravail, parametres }) });
    const corps = await r.json().catch(() => null);
    if (!r.ok) {
      setEtat({ message: corps?.error?.message ?? `refus (${r.status})`, travail: null });
      return;
    }
    await suivre(corps.id);
  };
  const t = etat.travail;
  return (
    <section>
      {titre ? <h2>{titre}</h2> : null}
      <form onSubmit={envoyer} data-commande={commande}>
        {champs.map((c) => <Champ key={c.nom} champ={c} />)}
        <button type="submit">{bouton}</button>
      </form>
      <p className={t?.etat === "refuse" ? "refus" : "discret"} role="status">{etat.message}</p>
      {t?.motif ? <p className="refus">{t.motif.code === "confirmation_absente" ? "confirmation hors bande absente" : t.motif.message}</p> : null}
      {t?.sortie ? <pre>{JSON.stringify(t.sortie, null, 2)}</pre> : null}
    </section>
  );
}
