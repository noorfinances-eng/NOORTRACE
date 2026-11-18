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
//
// Langage (complément du 2026-11-18, décision du porteur sur le langage des écrans) : l'aide de chaque champ dit ce
// qu'on attend et d'où vient l'information ; l'exemple s'écrit sous le champ (« Exemple : … »), jamais dans le
// champ, pour ne pas passer pour une saisie ; une section `replie` (réglages dont la valeur par défaut est sûre)
// se range dans un bloc replié ; un champ `tirage` offre un bouton qui tire un nom court au hasard dans la page ;
// un refus dit ce qui s'est passé, si quelque chose a été envoyé ou dépensé, et quoi faire.
//
// Un champ `choix` (même complément) montre tous ses choix, chacun avec sa phrase, sans en présélectionner aucun :
// un envoi sur le registre ne part pas d'un choix fait à la place de la personne. Tant qu'aucun choix n'est fait,
// la page refuse l'envoi et le dit. Ce que la route reçoit pour chaque choix ne change pas : `oui` donne le
// paramètre booléen vrai, l'autre choix ne donne aucun paramètre. Un champ `visibleSi` ne s'affiche qu'avec le
// choix qui le demande ; `requisSi` dit, dans la page, qu'il est alors nécessaire. Un choix `habituel` est mis en
// avant (premier, plus large, sa `marque` écrite dans le bouton) sans être coché : `avant` dit, au-dessus des
// choix, que rien n'est choisi d'avance.

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
const CHOIX_MANQUANT = "Faites un choix : l'outil n'en fait aucun à votre place. Rien n'a été envoyé.";

/** Nom court tiré au hasard dans la page, de la forme des clients de production (CT-4 EX-6.2) : « o- » et 32 chiffres hexadécimaux. */
function tirerNomCourt() {
  const o = new Uint8Array(16);
  window.crypto.getRandomValues(o);
  return `o-${[...o].map((x) => x.toString(16).padStart(2, "0")).join("")}`;
}

/** Champ à choix visibles, sans présélection : un bouton par choix, sa phrase dessous ; la valeur choisie est portée par un champ caché du type déclaré. */
function ChampChoix({ champ, id, erreur, regle, choisi, setChoisi }) {
  return (
    <div className="nt-champ" role="group" aria-labelledby={`${id}-libelle`} data-choix={champ.nom}>
      <p className="nt-libelle" id={`${id}-libelle`}>{champ.libelle}</p>
      {champ.avant ? <p className="nt-aide" id={`${id}-avant`} data-choix-avant="">{champ.avant}</p> : null}
      <input type="hidden" id={id} name={champ.nom} data-type={champ.type} value={choisi} readOnly />
      <div className="ins-choix">
        {champ.choix.map((o, k) => (
          <div className={o.habituel ? "ins-choix-un ins-choix-habituel" : "ins-choix-un"} key={o.valeur} data-choix-habituel={o.habituel ? "" : undefined}>
            <button type="button" className="nt-bouton nt-bouton-choix" aria-pressed={choisi === o.valeur} aria-describedby={`${id}-phrase-${k}`} onClick={() => setChoisi(o.valeur)} data-choix-valeur={o.valeur}><span>{o.libelle}{o.marque ? <span className="ins-choix-marque"> — {o.marque}</span> : null}</span></button>
            <p className="nt-aide" id={`${id}-phrase-${k}`}>{o.phrase}</p>
          </div>
        ))}
      </div>
      {erreur ? <p className="nt-erreur" id={`${id}-erreur`} role="alert" data-regle={regle}><Icone nom="alerte" /><span>{erreur}</span></p> : null}
      {champ.aide ? <p className="nt-aide" id={`${id}-aide`}>{champ.aide}</p> : null}
    </div>
  );
}

function Champ({ champ, prefixe, erreur, regle, choisi, setChoisi }) {
  const id = `${prefixe}-${champ.nom}`;
  if (champ.choix) return <ChampChoix champ={champ} id={id} erreur={erreur} regle={regle} choisi={choisi} setChoisi={setChoisi} />;
  const decrit = [champ.aide ? `${id}-aide` : null, champ.exemple ? `${id}-exemple` : null, erreur ? `${id}-erreur` : null].filter(Boolean).join(" ") || undefined;
  const classes = ["nt-saisie", TYPES_FIXES.has(champ.type) ? "nt-saisie-fixe" : ""].filter(Boolean).join(" ");
  const commun = { id, name: champ.nom, className: classes, "data-type": champ.type, required: !champ.facultatif, defaultValue: champ.defaut ?? undefined, autoComplete: "off", spellCheck: false, "aria-describedby": decrit, "aria-invalid": erreur ? "true" : undefined };
  let entree;
  // Une liste dont les choix viennent des données (noms, adresses) est marquée comme une valeur.
  if (champ.options) entree = <select {...commun} data-valeur={champ.donnees ? "" : undefined}>{champ.options.map((o) => <option key={o.valeur} value={o.valeur}>{o.libelle}</option>)}</select>;
  else if (ZONES.includes(champ.type)) entree = <textarea {...commun} />;
  else entree = <input {...commun} type={champ.type === "seuil" ? "number" : "text"} />;
  const tirer = () => {
    const e = document.getElementById(id);
    if (e) e.value = tirerNomCourt();
  };
  return (
    <div className="nt-champ">
      <label className="nt-libelle" htmlFor={id}>{champ.libelle}{champ.facultatif && !champ.requisSi ? <span className="nt-facultatif">(facultatif)</span> : null}</label>
      {entree}
      {erreur ? <p className="nt-erreur" id={`${id}-erreur`} role="alert" data-regle={regle}><Icone nom="alerte" /><span>{erreur}</span></p> : null}
      {champ.tirage ? (
        <div className="nt-actions">
          <button type="button" className="nt-bouton nt-bouton-petit" onClick={tirer} data-tirage={champ.nom}>{champ.tirage}</button>
        </div>
      ) : null}
      {champ.aide ? <p className="nt-aide" id={`${id}-aide`}>{champ.aide}</p> : null}
      {champ.apres ? <p className="nt-aide ins-a-retenir" data-a-retenir={champ.nom}><Icone nom="info" /><span>{champ.apres}</span></p> : null}
      {champ.exemple ? <p className="nt-aide ins-exemple" id={`${id}-exemple`} data-exemple="">Exemple : <span className="nt-fixe" data-valeur="">{champ.exemple}</span></p> : null}
    </div>
  );
}

/**
 * Refus ou échec, en bandeau : ce qui s'est passé, ce qui a été envoyé ou dépensé, quoi faire ; le code et le
 * message exacts au détail. Une phrase que CT-4 fixe mot pour mot (EX-7.26) s'affiche telle quelle sous la phrase
 * courante.
 */
export function Refus({ code, message, slug = null, titre = null }) {
  const x = explicationErreur(code);
  return (
    <div className="nt-bandeau nt-bandeau-erreur" role="alert" data-refus={code}>
      <Icone nom="alerte" />
      <div className="nt-bandeau-texte">
        <p className="nt-bandeau-titre">{titre ? `${titre} ` : ""}{x.phrase}</p>
        {x.fixe ? <p className="nt-attenue nt-petit" data-phrase-fixee="">Mention exacte de l'outil : « {x.fixe} ».</p> : null}
        <p>{x.effet}</p>
        <p><strong>Que faire :</strong> {x.quoiFaire}</p>
        {code === "confirmation_absente" && slug ? <p><a href={`/clients/${slug}/confirmations`}>Ouvrir les confirmations du client</a></p> : null}
        {code === "session_absente" ? <p><a href="/connexion">Se reconnecter</a></p> : null}
        <details className="ins-detail">
          <summary>Détail à transmettre à l'équipe technique</summary>
          <dl className="nt-definitions ins-detail-corps">
            <dt>Code</dt><dd><span className="nt-fixe">{code}</span></dd>
            <dt>Message exact</dt><dd><span className="nt-fixe">{message}</span></dd>
          </dl>
        </details>
      </div>
    </div>
  );
}

export default function FormulaireTravail({ commande, slug, champs = [], sections = null, fixe = {}, bouton = "Lancer l'action", principal = true, note = null }) {
  const prefixe = useId();
  const router = useRouter();
  const [etat, setEtat] = useState({ saisie: null, refus: null, travail: null, envoi: false });
  // Choix faits dans les champs `choix` : aucun au départ.
  const [choisis, setChoisis] = useState({});
  const visible = (c) => !c.visibleSi || choisis[c.visibleSi.champ] === c.visibleSi.valeur;
  const tous = (sections ? sections.flatMap((s) => s.champs) : champs).filter(visible);
  const suivre = async (id) => {
    for (;;) {
      let r;
      let t = null;
      try {
        r = await fetch(`/api/travaux/${id}`);
        t = await r.json();
      } catch {
        r = null;
      }
      if (!r || !r.ok || typeof t?.etat !== "string") {
        // Le suivi est perdu (connexion finie, outil injoignable) : l'action lancée, elle, n'est pas annulée.
        setEtat({ saisie: null, refus: { code: "suivi_interrompu", message: r ? `réponse ${r.status} à la lecture de ${id} : ${t?.error?.code ?? "sans code"}` : `aucune réponse à la lecture de ${id}` }, travail: null, envoi: false });
        return;
      }
      setEtat({ saisie: null, refus: null, travail: t, envoi: false });
      if (["fini", "refuse", "abandonne"].includes(t.etat)) return;
      await new Promise((ok) => setTimeout(ok, ATTENTE_MS));
    }
  };
  const envoyer = async (ev) => {
    ev.preventDefault();
    const formulaire = ev.currentTarget;
    const f = new FormData(formulaire);
    const parametres = { ...fixe };
    /** Refuse la saisie d'un champ : le message sous le champ, le bloc replié ouvert, le champ visé ; rien n'est envoyé. */
    const refuser = (c, message, regle) => {
      setEtat({ saisie: { champ: c.nom, message, regle }, refus: null, travail: null, envoi: false });
      const fautif = document.getElementById(`${prefixe}-${c.nom}`);
      fautif?.closest("details")?.setAttribute("open", "");
      if (c.choix) formulaire.querySelector(`[data-choix="${c.nom}"] button`)?.focus();
      else fautif?.focus();
    };
    for (const c of tous) {
      const brut = String(f.get(c.nom) ?? "");
      const cle = c.parametre ?? c.nom;
      if (c.choix && brut === "") return refuser(c, c.choixManquant ?? CHOIX_MANQUANT, "choix_absent");
      if (c.requisSi && String(f.get(c.requisSi.champ) ?? "") === c.requisSi.valeur && brut.trim() === "") return refuser(c, c.requisSi.message, "requis_avec_ce_choix");
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
        // La phrase dit quoi corriger et, dans une liste, la ligne fautive ; la valeur refusée n'est jamais recopiée.
        const rang = /^[^ ]*\[([0-9]+)\]/.exec(v.erreur);
        return refuser(c, `${explicationSaisie(c.type)}${rang ? ` Regardez la ligne ${Number(rang[1]) + 1}.` : ""}`, v.erreur);
      }
      if (c.nullSiVide && (v.valeur === "" || (Array.isArray(v.valeur) && v.valeur.length === 0))) parametres[cle] = null;
      else parametres[cle] = v.valeur;
    }
    setEtat({ saisie: null, refus: null, travail: null, envoi: true });
    const slugTravail = commande === "inscrire-client-preparer" ? parametres.org : slug;
    let r;
    try {
      r = await fetch("/api/travaux", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ commande, slug: slugTravail, parametres }) });
    } catch {
      setEtat({ saisie: null, refus: { code: "outil_injoignable", message: "aucune réponse de l'outil à l'envoi de l'action" }, travail: null, envoi: false });
      return;
    }
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
  const rendreChamp = (c) => (visible(c) ? <Champ key={c.nom} champ={c} prefixe={prefixe} erreur={etat.saisie?.champ === c.nom ? etat.saisie.message : null} regle={etat.saisie?.champ === c.nom ? etat.saisie.regle : undefined} choisi={choisis[c.nom] ?? ""} setChoisi={(v) => setChoisis((avant) => ({ ...avant, [c.nom]: v }))} /> : null);
  const rendreSection = (s) => {
    const groupe = (
      <fieldset className="nt-groupe-champs ins-section" key={s.titre}>
        <legend>{s.titre}</legend>
        {s.texte ? <p className="nt-aide">{s.texte}</p> : null}
        {s.champs.map(rendreChamp)}
      </fieldset>
    );
    if (!s.replie) return groupe;
    return (
      <details className="nt-detail" key={s.titre} data-reglages-avances="">
        <summary>{s.replie}<span className="nt-detail-note">à laisser tels quels, sauf consigne contraire</span></summary>
        <div className="nt-detail-corps">{groupe}</div>
      </details>
    );
  };
  return (
    <div className="nt-pile">
      <form className="nt-formulaire" onSubmit={envoyer} data-commande={commande}>
        {sections ? sections.map(rendreSection) : champs.map(rendreChamp)}
        {note ? <p className="nt-aide" data-apres-clic="">{note}</p> : null}
        <div className="nt-actions">
          <button type="submit" className={principal ? "nt-bouton nt-bouton-principal" : "nt-bouton"} disabled={enCours}>{bouton}</button>
        </div>
      </form>
      <div className="nt-pile" role="status" aria-live="polite">
        {etat.saisie ? <p className="nt-attenue nt-petit" data-saisie-refusee="">Rien n'a été envoyé : un champ est à corriger, il est signalé en rouge.</p> : null}
        {etat.envoi ? <p className="nt-attenue nt-petit">Envoi de l'action au service d'inscription…</p> : null}
        {t && !(e.termine && e.ton === "succes") ? (
          <p className="ins-etat-travail" data-etat-travail={e.code}>
            <Pastille ton={e.ton} icone={e.icone}>{e.libelle}</Pastille>
            <span className="nt-attenue nt-petit">{libelleCommande(t.commande)}. {e.explication}</span>
          </p>
        ) : null}
        {t && e.termine && e.ton === "succes" ? (
          <div className="nt-bandeau nt-bandeau-succes" data-etat-travail={e.code}>
            <Icone nom="coche" />
            <div className="nt-bandeau-texte"><p className="nt-bandeau-titre">{libelleCommande(t.commande)} : {e.libelle.toLowerCase()}.</p><p>{e.explication} Cette page est à jour.</p>{t.commande === "inscrire-client-preparer" && t.slug ? <p><a href={`/clients/${t.slug}`}>Ouvrir la fiche du client pour continuer</a></p> : null}</div>
          </div>
        ) : null}
      </div>
      {etat.refus ? <Refus code={etat.refus.code} message={etat.refus.message} slug={slug} /> : null}
      {echec && codeEchec ? <Refus code={codeEchec} message={messageEchec ?? ""} slug={slug} /> : null}
      {t?.sortie ? (
        <details className="nt-detail">
          <summary>Détail technique de l'action<span className="nt-detail-note">réponse exacte du service d'inscription</span></summary>
          <div className="nt-detail-corps"><pre className="nt-pre">{JSON.stringify(t.sortie, null, 2)}</pre></div>
        </details>
      ) : null}
    </div>
  );
}
