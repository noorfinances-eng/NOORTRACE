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
//
// Cinquième lecture des écrans (même complément) : l'explication des crédits est un bloc replié (`CreditsEnClair`).
// Une saisie refusée l'est en entier : la page contrôle tous les champs, signale sous chacun ce qui est à corriger
// (pour les fiches d'enregistreur, chaque zone fautive) et nomme, sous le bouton, les champs à corriger ; elle ne
// s'arrête plus au premier. Le contrôle natif du navigateur, qui ne montrait que le premier champ vide, est remplacé
// par celui de la page (`noValidate`) : un champ requis laissé vide est refusé par sa phrase. Rien n'est envoyé tant
// qu'un champ est refusé ; ce que la route reçoit ne change pas.
//
// Sixième lecture (même complément ; CT-4 EX-7.23, complément du 2026-11-19, et EX-7.25) : deux ajouts, pour l'écran du
// pas 1, qui ne changent rien à ce que la route des travaux reçoit.
// - Un champ `note: "nom_interne"` (le nom interne du client, type texte, 80 caractères au plus) se contrôle avec les
//   autres mais n'entre jamais dans les paramètres du travail : une fois le travail fini « réussi », et seulement
//   alors, la page le remet par POST /api/clients/<slug>/notes, au corps `{ sorte: "nom_interne", nom }`, celui de la
//   fiche. S'il n'est pas noté, la page le dit, et la fiche le redemande.
// - Une section `releve` porte, au-dessus de ses champs, une consigne mise en avant et une case à cocher, sans nom de
//   champ, jamais cochée d'avance, envoyée à aucune route ; tant qu'elle n'est pas cochée, la page refuse de remettre
//   le travail, comme une saisie refusée. La case ne prouve rien : elle dit que la personne déclare avoir fait la
//   relecture, que l'outil ne peut pas vérifier (CT-4 EX-7.8).
//
// Décisions du porteur du 2026-11-25 (CT-4 EX-7.8) : un champ `note: "noms_approbateurs"` (liste de textes, un nom par
// ligne dans l'ordre des adresses, facultatif) se contrôle avec les autres mais n'entre jamais dans les paramètres du
// travail ; une fois le dossier préparé « réussi », la page remet les noms par POST /api/clients/<slug>/notes, au corps
// `{ sorte: "noms_approbateurs", noms: [{ adresse, nom }] }`, chaque nom apparié à l'adresse de la même ligne.
//
// Décisions du porteur du 2026-11-25 (CT-4 EX-7.9) : un formulaire qui verse (`duree` : la consommation prévue du
// dossier, les frais que l'agent applique, le champ où une autre consommation peut s'écrire) dit, avant le clic, la
// durée que le versement complétera, d'après la valeur écrite dans le champ ou, à défaut, celle du dossier, et, le
// versement fait, ce que le montant versé représente (`dureeVersement`, phrases fixées par CT-4). Rien de ce qui est
// envoyé ne change.

import { useId, useState } from "react";
import { useRouter } from "next/navigation";
import { lireChamp, lireFiches } from "./champs-page.js";
import CreditsEnClair from "./CreditsEnClair.js";
import Icone from "./Icone.js";
import Pastille from "./Pastille.js";
import { NOM_INTERNE_MAX } from "../../commun/notes.mjs";
import { CHAMP_VIDE, dureeVersement, etatTravail, explicationErreur, explicationFiche, explicationSaisie, libelleCommande } from "../lib/parcours.mjs";

const ATTENTE_MS = 1000;
/** Types saisis en chasse fixe : identifiants, adresses, empreintes, références, documents. */
const TYPES_FIXES = new Set(["adresse", "liste_adresses", "hachage", "cle_publique_ed25519", "slug", "nom_journal", "liste_noms_journal", "reference_cle", "chemin", "document", "liste_documents", "origine", "identite", "liste_identites", "montant"]);
const ZONES = ["liste_adresses", "liste_noms_journal", "document", "liste_documents", "liste_identites", "liste_textes"];
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
function ChampFiches({ champ, id, saisies = [], zones, ajouter, retirer }) {
  const erreurDe = (k) => saisies.find((x) => x.zone === k) ?? null;
  const decrit = (k) => [`${id}-aide`, champ.exemple ? `${id}-exemple` : null, erreurDe(k) ? `${idZone(id, k)}-erreur` : null].filter(Boolean).join(" ");
  return (
    <div className="nt-champ" data-fiches={champ.nom}>
      {zones.map((cle, k) => (
        <div className="ins-fiche-zone" key={cle} data-zone={k}>
          <label className="nt-libelle" htmlFor={idZone(id, k)}>{k === 0 ? champ.libelle : `${champ.libelleAutre} (fiche ${k + 1})`}</label>
          <textarea id={idZone(id, k)} name={champ.nom} className="nt-saisie nt-saisie-fixe" data-type={champ.type} autoComplete="off" spellCheck={false} aria-required="true" aria-describedby={decrit(k)} aria-invalid={erreurDe(k) ? "true" : undefined} />
          {erreurDe(k) ? <p className="nt-erreur" id={`${idZone(id, k)}-erreur`} role="alert" data-regle={erreurDe(k).regle}><Icone nom="alerte" /><span>{erreurDe(k).message}</span></p> : null}
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

function Champ({ champ, prefixe, erreur, regle, saisies, zones, ajouter, retirer }) {
  const id = `${prefixe}-${champ.nom}`;
  if (champ.fiches) return <ChampFiches champ={champ} id={id} saisies={saisies} zones={zones} ajouter={ajouter} retirer={retirer} />;
  const decrit = [champ.aide ? `${id}-aide` : null, champ.exemple ? `${id}-exemple` : null, erreur ? `${id}-erreur` : null].filter(Boolean).join(" ") || undefined;
  const classes = ["nt-saisie", TYPES_FIXES.has(champ.type) ? "nt-saisie-fixe" : ""].filter(Boolean).join(" ");
  const commun = { id, name: champ.nom, className: classes, "data-type": champ.type, "data-nom-interne-creation": champ.note === "nom_interne" ? "" : undefined, required: !champ.facultatif && !champ.obligatoire, "aria-required": champ.obligatoire ? "true" : undefined, defaultValue: champ.defaut ?? undefined, autoComplete: "off", spellCheck: false, "aria-describedby": decrit, "aria-invalid": erreur ? "true" : undefined };
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
 * Consigne mise en avant au-dessus des champs d'une section, avec sa case à cocher (sixième lecture) : la case n'a pas
 * de nom de champ, n'est jamais cochée d'avance et n'est envoyée à aucune route ; la page la contrôle avant d'envoyer.
 */
function Releve({ r, id, erreur }) {
  return (
    <div className="nt-bandeau nt-bandeau-avertissement ins-releve" data-releve-consigne={r.nom}>
      <Icone nom="alerte" />
      <div className="nt-bandeau-texte ins-releve-texte">
        <p className="nt-bandeau-titre">{r.titre}</p>
        <p>{r.texte}</p>
        <div className="ins-case">
          <input type="checkbox" id={id} data-releve={r.nom} data-adresses-relues="" aria-describedby={[`${id}-aide`, erreur ? `${id}-erreur` : null].filter(Boolean).join(" ")} aria-invalid={erreur ? "true" : undefined} />
          <label htmlFor={id}>{r.libelle}</label>
        </div>
        <p className="nt-aide" id={`${id}-aide`}>{r.aide}</p>
        {erreur ? <p className="nt-erreur" id={`${id}-erreur`} role="alert" data-regle="releve"><Icone nom="alerte" /><span>{erreur}</span></p> : null}
      </div>
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

export default function FormulaireTravail({ commande, slug, champs = [], sections = null, fixe = {}, bouton = "Lancer l'action", sousBouton = null, principal = true, note = null, classe = "", duree = null }) {
  const prefixe = useId();
  const router = useRouter();
  const [etat, setEtat] = useState({ saisie: null, refus: null, travail: null, envoi: false });
  // Le nom interne remis après le travail : null, `{ fait: nom }` ou `{ refus: { code, message } }`.
  const [noteNom, setNoteNom] = useState(null);
  // Les noms des approbateurs remis après le travail : null, `{ fait: n }` ou `{ refus: { code, message } }`.
  const [noteNoms, setNoteNoms] = useState(null);
  // La consommation prévue écrite dans le champ (vide : celle du dossier), pour la phrase de la durée.
  const [parJourSaisi, setParJourSaisi] = useState("");
  const parJourEnVigueur = duree ? (parJourSaisi.trim() === "" ? duree.parJour : /^[0-9]+$/.test(parJourSaisi.trim()) ? parJourSaisi.trim() : null) : null;
  const phraseDuree = duree ? dureeVersement({ parJour: parJourEnVigueur, frais: duree.frais, complement: duree.complement === true }) : null;
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
        return null;
      }
      setEtat({ saisie: null, refus: null, travail: t, envoi: false });
      if (["fini", "refuse", "abandonne"].includes(t.etat)) return t;
      await new Promise((ok) => setTimeout(ok, ATTENTE_MS));
    }
  };
  const envoyer = async (ev) => {
    ev.preventDefault();
    const formulaire = ev.currentTarget;
    const f = new FormData(formulaire);
    const parametres = {};
    /**
     * Saisies refusées : tous les champs sont contrôlés, et chaque refus est noté (le champ, ou la zone du champ des
     * fiches, avec sa phrase) ; s'il y en a, le premier champ fautif est visé, chaque bloc replié qui en cache un
     * s'ouvre, et rien n'est envoyé.
     */
    const refuses = [];
    const refuser = (c, message, regle, zone = null) => { refuses.push({ champ: c.nom, libelle: c.libelle, message, regle, zone }); };
    // La case de relecture d'une section, contrôlée à sa place, avant les champs de sa section : non cochée, rien ne
    // part (elle n'est pas un paramètre du travail).
    const releves = new Map((sections ?? []).filter((s) => s.releve && s.champs.length > 0).map((s) => [s.champs[0], s.releve]));
    let nomInterne = null;
    let nomsApprobateurs = null;
    for (const c of tous) {
      const rel = releves.get(c);
      if (rel && !formulaire.querySelector(`input[data-releve="${rel.nom}"]`)?.checked) refuser({ nom: rel.nom, libelle: rel.libelle }, rel.refus, "releve");
      const brut = String(f.get(c.nom) ?? "");
      const cle = c.parametre ?? c.nom;
      if (c.note === "nom_interne") {
        // Contrôlé comme sur la fiche (texte d'EX-7.25, 80 caractères au plus), gardé à part : jamais dans le travail.
        const t = brut.trim();
        if (t === "") { refuser(c, CHAMP_VIDE, "vide"); continue; }
        if ([...t].length > NOM_INTERNE_MAX) { refuser(c, `Ce texte est trop long : ${NOM_INTERNE_MAX} caractères au plus.`, "texte"); continue; }
        const v = lireChamp({ nom: c.nom, type: "texte" }, t);
        if (v.erreur) { refuser(c, explicationSaisie("texte"), v.erreur); continue; }
        nomInterne = v.valeur;
        continue;
      }
      if (c.note === "noms_approbateurs") {
        // Une ligne par adresse, dans l'ordre ; gardés à part, jamais dans le travail (décisions du 2026-11-25).
        if (brut.trim() === "") continue;
        const v = lireChamp({ nom: c.nom, type: "liste_textes" }, brut);
        if (v.erreur) { refuser(c, explicationSaisie("liste_textes"), v.erreur); continue; }
        nomsApprobateurs = v.valeur;
        continue;
      }
      if (c.fiches) {
        const v = lireFiches(c, f.getAll(c.nom));
        if (v.erreur) {
          for (const x of v.erreurs) refuser(c, explicationFiche(x.regle, x.zone > 0), x.regle, x.zone);
          continue;
        }
        parametres[cle] = v.valeur;
        continue;
      }
      if (c.obligatoire && brut.trim() === "") { refuser(c, c.obligatoire, "obligatoire"); continue; }
      // Un champ requis laissé vide (le navigateur ne le contrôle plus : `noValidate`).
      if (!c.obligatoire && !c.facultatif && brut.trim() === "") { refuser(c, CHAMP_VIDE, "vide"); continue; }
      if (c.nullSiVide && brut.trim() === "") {
        parametres[cle] = null;
        continue;
      }
      if (c.facultatif && brut.trim() === "") continue;
      const v = lireChamp(c, brut);
      if (v.erreur) {
        // La phrase dit quoi corriger et, dans une liste, la ligne fautive ; la valeur refusée n'est jamais recopiée.
        const rang = /^[^ ]*\[([0-9]+)\]/.exec(v.erreur);
        refuser(c, `${explicationSaisie(c.type)}${rang ? ` Regardez la ligne ${Number(rang[1]) + 1}.` : ""}`, v.erreur);
        continue;
      }
      if (c.nullSiVide && (v.valeur === "" || (Array.isArray(v.valeur) && v.valeur.length === 0))) parametres[cle] = null;
      else parametres[cle] = v.valeur;
    }
    if (refuses.length > 0) {
      setEtat({ saisie: refuses, refus: null, travail: null, envoi: false });
      for (const x of refuses) document.getElementById(x.zone === null ? `${prefixe}-${x.champ}` : idZone(`${prefixe}-${x.champ}`, x.zone))?.closest("details")?.setAttribute("open", "");
      const premier = refuses[0];
      document.getElementById(premier.zone === null ? `${prefixe}-${premier.champ}` : idZone(`${prefixe}-${premier.champ}`, premier.zone))?.focus();
      return;
    }
    // Ce que le bouton porte d'office vient après les champs, comme le paramètre que portait autrefois un champ.
    Object.assign(parametres, fixe);
    setNoteNom(null);
    setNoteNoms(null);
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
    const fin = await suivre(corps.id);
    // Le nom interne, seulement si le dossier vient d'être préparé par ce travail (jamais pour un dossier qui existait).
    if (nomInterne !== null && commande === "inscrire-client-preparer" && fin?.etat === "fini" && fin.sortie?.result === "reussi") {
      let rn = null;
      try {
        rn = await fetch(`/api/clients/${encodeURIComponent(slugTravail)}/notes`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ sorte: "nom_interne", nom: nomInterne }) });
      } catch {
        rn = null;
      }
      if (rn?.ok) setNoteNom({ fait: nomInterne });
      else {
        const j = rn ? await rn.json().catch(() => null) : null;
        setNoteNom({ refus: { code: j?.error?.code ?? (rn ? `http_${rn.status}` : "outil_injoignable"), message: j?.error?.message ?? (rn ? `refus (${rn.status})` : "aucune réponse de l'outil à l'envoi du nom interne") } });
      }
    }
    // Les noms des approbateurs, de même, appariés aux adresses du travail dans l'ordre des lignes.
    const adresses = Array.isArray(parametres.approbateurs) ? parametres.approbateurs : [];
    const noms = nomsApprobateurs ? nomsApprobateurs.map((nom, k) => ({ adresse: adresses[k] ?? null, nom })).filter((x) => x.adresse !== null && x.nom !== "") : [];
    if (noms.length > 0 && commande === "inscrire-client-preparer" && fin?.etat === "fini" && fin.sortie?.result === "reussi") {
      let rn = null;
      try {
        rn = await fetch(`/api/clients/${encodeURIComponent(slugTravail)}/notes`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ sorte: "noms_approbateurs", noms }) });
      } catch {
        rn = null;
      }
      if (rn?.ok) setNoteNoms({ fait: noms.length });
      else {
        const j = rn ? await rn.json().catch(() => null) : null;
        setNoteNoms({ refus: { code: j?.error?.code ?? (rn ? `http_${rn.status}` : "outil_injoignable"), message: j?.error?.message ?? (rn ? `refus (${rn.status})` : "aucune réponse de l'outil à l'envoi des noms des approbateurs") } });
      }
    }
    // Le dossier a pu changer : la fiche rendue par le serveur est relue.
    router.refresh();
  };
  const t = etat.travail;
  const e = t ? etatTravail(t) : null;
  const echec = t && e.termine && e.ton !== "succes";
  const codeEchec = t?.motif?.code ?? t?.sortie?.error?.code ?? null;
  const messageEchec = t?.motif?.message ?? t?.sortie?.error?.message ?? null;
  const enCours = etat.envoi || (t !== null && !e.termine);
  const refusDe = (c) => (etat.saisie ?? []).filter((x) => x.champ === c.nom);
  const rendreChamp = (c) => <Champ key={c.nom} champ={c} prefixe={prefixe} erreur={refusDe(c)[0]?.message ?? null} regle={refusDe(c)[0]?.regle} saisies={refusDe(c)} zones={zones} ajouter={ajouterZone} retirer={retirerZone} />;
  // Les champs à corriger, nommés une fois chacun, dans l'ordre du formulaire.
  const aCorriger = [...new Set((etat.saisie ?? []).map((x) => x.libelle))];
  const rendreSection = (s) => {
    const groupe = (
      <fieldset className="nt-groupe-champs ins-section" key={s.titre}>
        <legend>{s.titre}</legend>
        {s.texte ? <p className="nt-aide">{s.texte}</p> : null}
        {s.releve ? <Releve r={s.releve} id={`${prefixe}-${s.releve.nom}`} erreur={refusDe(s.releve)[0]?.message ?? null} /> : null}
        {s.credits ? <CreditsEnClair /> : null}
        {s.champs.map(rendreChamp)}
      </fieldset>
    );
    if (!s.replie) return groupe;
    return (
      <details className="nt-detail ins-replie" key={s.titre} data-reglages-avances="">
        <summary>{s.replie}<span className="nt-detail-note">à laisser tels quels, sauf consigne contraire</span></summary>
        <div className="nt-detail-corps">{groupe}</div>
      </details>
    );
  };
  return (
    <div className={["nt-pile", classe].filter(Boolean).join(" ")}>
      <form className="nt-formulaire" onSubmit={envoyer} noValidate data-commande={commande} onInput={duree?.champ ? (ev) => { if (ev.target?.name === duree.champ) setParJourSaisi(String(ev.target.value ?? "")); } : undefined}>
        {sections ? sections.map(rendreSection) : champs.map(rendreChamp)}
        {phraseDuree ? <p className="nt-aide ins-a-retenir" data-duree-versement=""><Icone nom="info" /><span>{phraseDuree}</span></p> : null}
        {note ? <p className="nt-aide" data-apres-clic="">{note}</p> : null}
        <div className="nt-actions ins-actions-bouton">
          <button type="submit" className={principal ? "nt-bouton nt-bouton-principal" : "nt-bouton"} disabled={enCours} aria-describedby={sousBouton ? `${prefixe}-sous-bouton` : undefined}>{bouton}</button>
          {sousBouton ? <p className="nt-aide" id={`${prefixe}-sous-bouton`} data-sous-bouton="">{sousBouton}</p> : null}
        </div>
      </form>
      <div className="nt-pile" role="status" aria-live="polite">
        {etat.saisie ? <p className="nt-attenue nt-petit" data-saisie-refusee="">{aCorriger.length > 1 ? `Rien n'a été envoyé : ${aCorriger.length} champs sont à corriger, chacun signalé en rouge : ${aCorriger.map((x) => `« ${x} »`).join(", ")}.` : `Rien n'a été envoyé : un champ est à corriger, il est signalé en rouge : « ${aCorriger[0]} ».`}</p> : null}
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
            <div className="nt-bandeau-texte"><p className="nt-bandeau-titre">{libelleCommande(t.commande)} : {e.libelle.toLowerCase()}.</p><p>{e.explication} Cette page est à jour.</p>{t.commande === "approvisionner" && t.sortie?.result === "reussi" && t.sortie.outputs?.amount_wei !== undefined ? <p data-duree-versee="">{dureeVersement({ montant: t.sortie.outputs.amount_wei, parJour: t.sortie.outputs.daily_budget_gas, verse: true })}</p> : null}{noteNom?.fait ? <p data-nom-interne-note="">Le nom interne « <span data-valeur="">{noteNom.fait}</span> » est enregistré : seule notre équipe le voit.</p> : null}{noteNoms?.fait ? <p data-noms-approbateurs-note={noteNoms.fait}>{noteNoms.fait > 1 ? `Les noms de ${noteNoms.fait} approbateurs sont enregistrés` : "Le nom d'un approbateur est enregistré"} pour la fiche de contrôle : ils ne partent jamais vers le registre public.</p> : null}{t.commande === "inscrire-client-preparer" && t.slug ? <p><a href={`/clients/${t.slug}`}>Ouvrir la fiche du client pour continuer</a></p> : null}</div>
          </div>
        ) : null}
        {noteNoms?.refus ? (
          <div className="nt-bandeau nt-bandeau-avertissement" data-noms-approbateurs-refus={noteNoms.refus.code}>
            <Icone nom="alerte" />
            <div className="nt-bandeau-texte">
              <p className="nt-bandeau-titre">Le dossier est préparé, mais les noms des approbateurs ne sont pas enregistrés.</p>
              <p>Rien n'a été envoyé au registre public. Ouvrez la fiche du client, puis sa fiche de contrôle des adresses (sous « Confirmations et paquet ») : vous pouvez y donner ces noms, sous « Noms des approbateurs ».</p>
              <details className="ins-detail">
                <summary>Détail à transmettre à l'équipe technique</summary>
                <dl className="nt-definitions ins-detail-corps">
                  <dt>Code</dt><dd><span className="nt-fixe">{noteNoms.refus.code}</span></dd>
                  <dt>Message exact</dt><dd><span className="nt-fixe">{noteNoms.refus.message}</span></dd>
                </dl>
              </details>
            </div>
          </div>
        ) : null}
        {noteNom?.refus ? (
          <div className="nt-bandeau nt-bandeau-avertissement" data-nom-interne-refus={noteNom.refus.code}>
            <Icone nom="alerte" />
            <div className="nt-bandeau-texte">
              <p className="nt-bandeau-titre">Le dossier est préparé, mais le nom interne n'est pas enregistré.</p>
              <p>Rien n'a été envoyé au registre public. Ouvrez la fiche du client : elle vous redemande son nom interne.</p>
              <details className="ins-detail">
                <summary>Détail à transmettre à l'équipe technique</summary>
                <dl className="nt-definitions ins-detail-corps">
                  <dt>Code</dt><dd><span className="nt-fixe">{noteNom.refus.code}</span></dd>
                  <dt>Message exact</dt><dd><span className="nt-fixe">{noteNom.refus.message}</span></dd>
                </dl>
              </details>
            </div>
          </div>
        ) : null}
      </div>
      {etat.refus ? <Refus code={etat.refus.code} message={etat.refus.message} slug={slug} /> : null}
      {echec && codeEchec ? <Refus code={codeEchec} message={messageEchec ?? ""} slug={slug} verification={t?.sortie?.error?.check ?? null} /> : null}
      {t?.sortie ? (
        <details className="nt-detail ins-replie">
          <summary>Détail technique de l'action<span className="nt-detail-note">réponse exacte du service d'inscription</span></summary>
          <div className="nt-detail-corps"><pre className="nt-pre">{JSON.stringify(t.sortie, null, 2)}</pre></div>
        </details>
      ) : null}
    </div>
  );
}
