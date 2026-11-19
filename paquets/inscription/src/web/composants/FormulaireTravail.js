"use client";
// Formulaire d'un travail typé (INTERFACES.md 3.3) : chaque champ a un type déclaré de la liste close d'EX-7.25
// (attribut data-type), contrôlé dans la page pour l'affichage puis par le serveur et l'agent. Un champ à `options`
// est une liste de choix de ce type ; `parametre` nomme le paramètre du travail quand il diffère du champ ; `fixe`
// porte les paramètres que le bouton envoie d'office. Le travail est remis par POST /api/travaux ; la page
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
// Troisième lecture des écrans (même complément) : aucun choix à faire avant un envoi, aucune case ni aucun bouton
// présélectionné. Le bouton dit lui-même ce qu'il fait (« Envoyer par notre compte d'envoi ») et `sousBouton` le
// redit dessous ; une valeur que le bouton porte d'office (`fixe`, par exemple `relayeur: true`) s'ajoute après les
// champs, à la place où le paramètre se trouvait déjà dans le corps envoyé. Un champ `obligatoire` est refusé vide
// par la page, avec sa phrase. Un champ `fiches` (les fiches d'enregistreur, `liste_documents`) a une zone par
// fiche, où l'on colle le contenu d'un fichier du client tel quel, et un bouton « Ajouter une autre fiche » ; la
// page assemble la liste, la même que donnait la saisie à la main de « [ fiche, fiche ] ». Ce que la route reçoit
// ne change pas.
//
// Quatrième lecture des écrans (même complément) : une section `credits` dit, sous son texte, ce que sont les crédits
// d'écriture ; un refus `transaction_annulee` dit ce qui a échoué d'après la vérification qui l'a rendu (`check`).

import { useId, useState } from "react";
import { useRouter } from "next/navigation";
import { lireChamp, lireFiches } from "./champs-page.js";
import Icone from "./Icone.js";
import Pastille from "./Pastille.js";
import { CREDITS_EN_CLAIR, etatTravail, explicationErreur, explicationFiche, explicationSaisie, libelleCommande } from "../lib/parcours.mjs";

const ATTENTE_MS = 1000;
/** Types saisis en chasse fixe : identifiants, adresses, empreintes, références, documents. */
const TYPES_FIXES = new Set(["adresse", "liste_adresses", "hachage", "cle_publique_ed25519", "slug", "nom_journal", "liste_noms_journal", "reference_cle", "chemin", "document", "liste_documents", "origine", "identite", "liste_identites", "montant"]);
const ZONES = ["liste_adresses", "liste_noms_journal", "document", "liste_documents", "liste_identites"];
/** Nombre de fiches d'enregistreur au plus (`parametres.cles_enregistreur`, 16 éléments : src/commun/travaux.mjs). */
const FICHES_MAX = 16;

/** Nom court tiré au hasard dans la page, de la forme des clients de production (CT-4 EX-6.2) : « o- » et 32 chiffres hexadécimaux. */
function tirerNomCourt() {
  const o = new Uint8Array(16);
  window.crypto.getRandomValues(o);
  return `o-${[...o].map((x) => x.toString(16).padStart(2, "0")).join("")}`;
}

/** Identifiant de la zone `k` du champ des fiches (la première porte celui du champ). */
const idZone = (id, k) => (k === 0 ? id : `${id}-${k + 1}`);

/**
 * Champ des fiches d'enregistreur : une zone par fiche, chacune avec son libellé ; les zones ajoutées peuvent se
 * retirer. Toutes portent le nom et le type déclaré du champ (`liste_documents`) : ce sont les éléments d'une même
 * liste. Aucune n'est requise par le navigateur : une zone vide est refusée par la page, avec sa phrase.
 */
function ChampFiches({ champ, id, saisie, zones, ajouter, retirer }) {
  const decrit = (k) => [`${id}-aide`, champ.exemple ? `${id}-exemple` : null, saisie?.zone === k ? `${idZone(id, k)}-erreur` : null].filter(Boolean).join(" ");
  return (
    <div className="nt-champ" data-fiches={champ.nom}>
      {zones.map((cle, k) => (
        <div className="ins-fiche-zone" key={cle} data-zone={k}>
          <label className="nt-libelle" htmlFor={idZone(id, k)}>{k === 0 ? champ.libelle : `${champ.libelleAutre} (fiche ${k + 1})`}</label>
          <textarea id={idZone(id, k)} name={champ.nom} className="nt-saisie nt-saisie-fixe" data-type={champ.type} autoComplete="off" spellCheck={false} aria-required="true" aria-describedby={decrit(k)} aria-invalid={saisie?.zone === k ? "true" : undefined} />
          {saisie?.zone === k ? <p className="nt-erreur" id={`${idZone(id, k)}-erreur`} role="alert" data-regle={saisie.regle}><Icone nom="alerte" /><span>{saisie.message}</span></p> : null}
          {k > 0 ? <div className="nt-actions"><button type="button" className="nt-bouton nt-bouton-petit" onClick={() => retirer(cle)} data-retirer-fiche={k}>Retirer cette zone</button></div> : null}
        </div>
      ))}
      {zones.length < FICHES_MAX ? (
        <div className="nt-actions">
          <button type="button" className="nt-bouton nt-bouton-petit" onClick={ajouter} data-ajouter-fiche="">Ajouter une autre fiche</button>
        </div>
      ) : null}
      <p className="nt-aide" id={`${id}-aide`}>{champ.aide}</p>
      {champ.exemple ? <p className="nt-aide ins-exemple" id={`${id}-exemple`} data-exemple="">Exemple : <span className="nt-fixe" data-valeur="">{champ.exemple}</span></p> : null}
    </div>
  );
}

function Champ({ champ, prefixe, erreur, regle, saisie, zones, ajouter, retirer }) {
  const id = `${prefixe}-${champ.nom}`;
  if (champ.fiches) return <ChampFiches champ={champ} id={id} saisie={saisie} zones={zones} ajouter={ajouter} retirer={retirer} />;
  const decrit = [champ.aide ? `${id}-aide` : null, champ.exemple ? `${id}-exemple` : null, erreur ? `${id}-erreur` : null].filter(Boolean).join(" ") || undefined;
  const classes = ["nt-saisie", TYPES_FIXES.has(champ.type) ? "nt-saisie-fixe" : ""].filter(Boolean).join(" ");
  const commun = { id, name: champ.nom, className: classes, "data-type": champ.type, required: !champ.facultatif && !champ.obligatoire, "aria-required": champ.obligatoire ? "true" : undefined, defaultValue: champ.defaut ?? undefined, autoComplete: "off", spellCheck: false, "aria-describedby": decrit, "aria-invalid": erreur ? "true" : undefined };
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
      <label className="nt-libelle" htmlFor={id}>{champ.libelle}{champ.facultatif ? <span className="nt-facultatif">(facultatif)</span> : null}</label>
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
export function Refus({ code, message, slug = null, titre = null, verification = null }) {
  const x = explicationErreur(code, { verification });
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

export default function FormulaireTravail({ commande, slug, champs = [], sections = null, fixe = {}, bouton = "Lancer l'action", sousBouton = null, principal = true, note = null, classe = "" }) {
  const prefixe = useId();
  const router = useRouter();
  const [etat, setEtat] = useState({ saisie: null, refus: null, travail: null, envoi: false });
  // Zones du champ des fiches : une clé stable par zone (une zone retirée garde le texte des autres).
  const [zones, setZones] = useState([0]);
  const [prochaineZone, setProchaineZone] = useState(1);
  const ajouterZone = () => {
    setZones((l) => [...l, prochaineZone]);
    setProchaineZone((n) => n + 1);
  };
  const retirerZone = (cle) => {
    setZones((l) => l.filter((x) => x !== cle));
    setEtat((e) => ({ ...e, saisie: null }));
  };
  const tous = sections ? sections.flatMap((s) => s.champs) : champs;
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
    const parametres = {};
    /** Refuse la saisie d'un champ (ou d'une zone du champ des fiches) : le message sous le champ, le bloc replié ouvert, le champ visé ; rien n'est envoyé. */
    const refuser = (c, message, regle, zone = null) => {
      setEtat({ saisie: { champ: c.nom, message, regle, zone }, refus: null, travail: null, envoi: false });
      const fautif = document.getElementById(zone === null ? `${prefixe}-${c.nom}` : idZone(`${prefixe}-${c.nom}`, zone));
      fautif?.closest("details")?.setAttribute("open", "");
      fautif?.focus();
    };
    for (const c of tous) {
      const brut = String(f.get(c.nom) ?? "");
      const cle = c.parametre ?? c.nom;
      if (c.fiches) {
        const v = lireFiches(c, f.getAll(c.nom));
        if (v.erreur) return refuser(c, explicationFiche(v.regle, v.zone > 0), v.regle, v.zone);
        parametres[cle] = v.valeur;
        continue;
      }
      if (c.obligatoire && brut.trim() === "") return refuser(c, c.obligatoire, "obligatoire");
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
    // Ce que le bouton porte d'office vient après les champs, comme le paramètre que portait autrefois un champ.
    Object.assign(parametres, fixe);
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
  const rendreChamp = (c) => <Champ key={c.nom} champ={c} prefixe={prefixe} erreur={etat.saisie?.champ === c.nom ? etat.saisie.message : null} regle={etat.saisie?.champ === c.nom ? etat.saisie.regle : undefined} saisie={etat.saisie?.champ === c.nom ? etat.saisie : null} zones={zones} ajouter={ajouterZone} retirer={retirerZone} />;
  const rendreSection = (s) => {
    const groupe = (
      <fieldset className="nt-groupe-champs ins-section" key={s.titre}>
        <legend>{s.titre}</legend>
        {s.texte ? <p className="nt-aide">{s.texte}</p> : null}
        {s.credits ? <p className="nt-aide ins-credits" data-credits-en-clair="">{CREDITS_EN_CLAIR}</p> : null}
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
    <div className={["nt-pile", classe].filter(Boolean).join(" ")}>
      <form className="nt-formulaire" onSubmit={envoyer} data-commande={commande}>
        {sections ? sections.map(rendreSection) : champs.map(rendreChamp)}
        {note ? <p className="nt-aide" data-apres-clic="">{note}</p> : null}
        <div className="nt-actions ins-actions-bouton">
          <button type="submit" className={principal ? "nt-bouton nt-bouton-principal" : "nt-bouton"} disabled={enCours} aria-describedby={sousBouton ? `${prefixe}-sous-bouton` : undefined}>{bouton}</button>
          {sousBouton ? <p className="nt-aide" id={`${prefixe}-sous-bouton`} data-sous-bouton="">{sousBouton}</p> : null}
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
      {echec && codeEchec ? <Refus code={codeEchec} message={messageEchec ?? ""} slug={slug} verification={t?.sortie?.error?.check ?? null} /> : null}
      {t?.sortie ? (
        <details className="nt-detail">
          <summary>Détail technique de l'action<span className="nt-detail-note">réponse exacte du service d'inscription</span></summary>
          <div className="nt-detail-corps"><pre className="nt-pre">{JSON.stringify(t.sortie, null, 2)}</pre></div>
        </details>
      ) : null}
    </div>
  );
}
