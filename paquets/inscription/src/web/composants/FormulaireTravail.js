"use client";
// Formulaire d'un travail typé (INTERFACES.md 3.3) : chaque champ a un type déclaré de la liste close d'EX-7.25
// (attribut data-type), contrôlé dans la page pour l'affichage puis par le serveur et l'agent. Un champ à `options`
// est une liste de choix de ce type ; `parametre` nomme le paramètre du travail quand il diffère du champ ; `oui`
// fait d'un choix de texte un paramètre booléen (vrai si la valeur choisie est `oui`, absent sinon). Le travail est remis par POST /api/travaux ; la page
// suit son état par GET /api/travaux/<id> et affiche la sortie de la commande. Aucun champ ne reçoit une clé, une
// graine, une mnémonique, un jeton ni un mot de passe de clé : une clé se désigne par une référence (EX-7.3).
//
// Présentation (complément du 2026-11-17) : un libellé et une aide par champ, des sections courtes (`sections`),
// la saisie refusée dite en clair sous le champ fautif (jamais la valeur), l'état du travail en mots, un refus en
// bandeau avec la conduite à tenir ; le code, le message exact et la sortie de la commande restent lisibles, tels
// quels, dans un bloc replié. Quand le travail finit, la fiche du serveur est relue.

import { useId, useState } from "react";
import { useRouter } from "next/navigation";
import { lireChamp } from "./champs-page.js";
import Icone from "./Icone.js";
import Pastille from "./Pastille.js";
import { etatTravail, explicationErreur, explicationSaisie, libelleCommande } from "../lib/parcours.mjs";

const ATTENTE_MS = 1000;
/** Types saisis en chasse fixe : identifiants, adresses, empreintes, références, documents. */
const TYPES_FIXES = new Set(["adresse", "liste_adresses", "hachage", "cle_publique_ed25519", "slug", "nom_journal", "liste_noms_journal", "reference_cle", "chemin", "document", "liste_documents", "origine", "identite", "liste_identites", "montant"]);
const ZONES = ["liste_adresses", "liste_noms_journal", "document", "liste_documents", "liste_identites"];

function Champ({ champ, prefixe, erreur, regle }) {
  const id = `${prefixe}-${champ.nom}`;
  const decrit = [champ.aide ? `${id}-aide` : null, erreur ? `${id}-erreur` : null].filter(Boolean).join(" ") || undefined;
  const classes = ["nt-saisie", TYPES_FIXES.has(champ.type) ? "nt-saisie-fixe" : ""].filter(Boolean).join(" ");
  const commun = { id, name: champ.nom, className: classes, "data-type": champ.type, required: !champ.facultatif, defaultValue: champ.defaut ?? undefined, autoComplete: "off", spellCheck: false, "aria-describedby": decrit, "aria-invalid": erreur ? "true" : undefined };
  let entree;
  if (champ.options) entree = <select {...commun}>{champ.options.map((o) => <option key={o.valeur} value={o.valeur}>{o.libelle}</option>)}</select>;
  else if (ZONES.includes(champ.type)) entree = <textarea {...commun} placeholder={champ.exemple ?? undefined} />;
  else entree = <input {...commun} type={champ.type === "seuil" ? "number" : "text"} placeholder={champ.exemple ?? undefined} />;
  return (
    <div className="nt-champ">
      <label className="nt-libelle" htmlFor={id}>{champ.libelle}{champ.facultatif ? <span className="nt-facultatif">(facultatif)</span> : null}</label>
      {entree}
      {champ.aide ? <p className="nt-aide" id={`${id}-aide`}>{champ.aide}</p> : null}
      {erreur ? <p className="nt-erreur" id={`${id}-erreur`} role="alert" data-regle={regle}><Icone nom="alerte" /><span>{erreur}</span></p> : null}
    </div>
  );
}

/** Refus ou échec, en bandeau : ce qui s'est passé, quoi faire ; le code et le message exacts au détail. */
function Refus({ code, message, slug }) {
  const x = explicationErreur(code);
  return (
    <div className="nt-bandeau nt-bandeau-erreur" role="alert">
      <Icone nom="alerte" />
      <div className="nt-bandeau-texte">
        <p className="nt-bandeau-titre">{x.phrase}</p>
        <p>{x.quoiFaire}</p>
        {code === "confirmation_absente" && slug ? <p><a href={`/clients/${slug}/confirmations`}>Ouvrir les confirmations hors bande</a></p> : null}
        <details className="ins-detail">
          <summary>Détail technique</summary>
          <dl className="nt-definitions ins-detail-corps">
            <dt>Code</dt><dd><span className="nt-fixe">{code}</span></dd>
            <dt>Message exact</dt><dd><span className="nt-fixe">{message}</span></dd>
          </dl>
        </details>
      </div>
    </div>
  );
}

export default function FormulaireTravail({ commande, slug, champs = [], sections = null, fixe = {}, bouton = "Remettre le travail à l'agent", principal = true }) {
  const prefixe = useId();
  const router = useRouter();
  const [etat, setEtat] = useState({ saisie: null, refus: null, travail: null, envoi: false });
  const tous = sections ? sections.flatMap((s) => s.champs) : champs;
  const suivre = async (id) => {
    for (;;) {
      const r = await fetch(`/api/travaux/${id}`);
      const t = await r.json();
      setEtat({ saisie: null, refus: null, travail: t, envoi: false });
      if (["fini", "refuse", "abandonne"].includes(t.etat)) return;
      await new Promise((ok) => setTimeout(ok, ATTENTE_MS));
    }
  };
  const envoyer = async (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.currentTarget);
    const parametres = { ...fixe };
    for (const c of tous) {
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
        // La phrase dit la forme attendue et, dans une liste, la ligne fautive ; la valeur refusée n'est jamais recopiée.
        const rang = /^[^ ]*\[([0-9]+)\]/.exec(v.erreur);
        setEtat({ saisie: { champ: c.nom, message: `${explicationSaisie(c.type)}${rang ? ` Ligne ${Number(rang[1]) + 1}.` : ""}`, regle: v.erreur }, refus: null, travail: null, envoi: false });
        return;
      }
      if (c.nullSiVide && (v.valeur === "" || (Array.isArray(v.valeur) && v.valeur.length === 0))) parametres[cle] = null;
      else parametres[cle] = v.valeur;
    }
    setEtat({ saisie: null, refus: null, travail: null, envoi: true });
    const slugTravail = commande === "inscrire-client-preparer" ? parametres.org : slug;
    const r = await fetch("/api/travaux", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ commande, slug: slugTravail, parametres }) });
    const corps = await r.json().catch(() => null);
    if (!r.ok) {
      setEtat({ saisie: null, refus: { code: corps?.error?.code ?? `http_${r.status}`, message: corps?.error?.message ?? `refus (${r.status})` }, travail: null, envoi: false });
      return;
    }
    await suivre(corps.id);
    // Le dossier a pu changer : la fiche rendue par le serveur est relue.
    router.refresh();
  };
  const t = etat.travail;
  const e = t ? etatTravail(t) : null;
  const echec = t && e.termine && e.ton !== "succes";
  const codeEchec = t?.motif?.code ?? t?.sortie?.error?.code ?? null;
  const messageEchec = t?.motif?.message ?? t?.sortie?.error?.message ?? null;
  const enCours = etat.envoi || (t !== null && !e.termine);
  const rendreChamp = (c) => <Champ key={c.nom} champ={c} prefixe={prefixe} erreur={etat.saisie?.champ === c.nom ? etat.saisie.message : null} regle={etat.saisie?.champ === c.nom ? etat.saisie.regle : undefined} />;
  return (
    <div className="nt-pile">
      <form className="nt-formulaire" onSubmit={envoyer} data-commande={commande}>
        {sections
          ? sections.map((s) => (
            <fieldset className="nt-groupe-champs ins-section" key={s.titre}>
              <legend>{s.titre}</legend>
              {s.texte ? <p className="nt-aide">{s.texte}</p> : null}
              {s.champs.map(rendreChamp)}
            </fieldset>
          ))
          : champs.map(rendreChamp)}
        <div className="nt-actions">
          <button type="submit" className={principal ? "nt-bouton nt-bouton-principal" : "nt-bouton"} disabled={enCours}>{bouton}</button>
        </div>
      </form>
      <div className="nt-pile" role="status" aria-live="polite">
        {etat.envoi ? <p className="nt-attenue nt-petit">Remise du travail à l'agent…</p> : null}
        {t && !(e.termine && e.ton === "succes") ? (
          <p className="ins-etat-travail">
            <Pastille ton={e.ton} icone={e.icone}>{e.libelle}</Pastille>
            <span className="nt-attenue nt-petit">{libelleCommande(t.commande)}. {e.explication}</span>
          </p>
        ) : null}
        {t && e.termine && e.ton === "succes" ? (
          <div className="nt-bandeau nt-bandeau-succes">
            <Icone nom="coche" />
            <div className="nt-bandeau-texte"><p className="nt-bandeau-titre">{libelleCommande(t.commande)} : {e.libelle.toLowerCase()}.</p><p>{e.explication} La fiche est à jour.</p></div>
          </div>
        ) : null}
      </div>
      {etat.refus ? <Refus code={etat.refus.code} message={etat.refus.message} slug={slug} /> : null}
      {echec && codeEchec ? <Refus code={codeEchec} message={messageEchec ?? ""} slug={slug} /> : null}
      {t?.sortie ? (
        <details className="nt-detail">
          <summary>Sortie de la commande<span className="nt-detail-note">telle que l'agent l'a rendue</span></summary>
          <div className="nt-detail-corps"><pre className="nt-pre">{JSON.stringify(t.sortie, null, 2)}</pre></div>
        </details>
      ) : null}
    </div>
  );
}
