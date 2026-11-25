"use client";
// Notes internes sur un client (CT-4 EX-7.23, complément du 2026-11-19, décision du porteur sur le suivi interne des
// clients ; INTERFACES.md 2.6) : son nom interne, et la remise de son paquet. Chaque note part par
// POST /api/clients/<slug>/notes, au nom de la personne connectée ; l'agent la garde avec ses données internes,
// et elle ne part jamais vers le registre public ni dans le paquet. Aucun bouton n'est enfoncé d'avance, aucune case
// n'est cochée : chaque note part d'un clic de la personne. Une note refusée se dit en clair, avec le code au détail.
//
// - `NomInterne` : le nom que l'équipe donne au client pour le reconnaître (texte de 1 à 80 caractères, type texte
//   d'EX-7.25) ; corps `{ sorte: "nom_interne", nom }`, et `{ sorte: "nom_interne", nom: null }` pour le retirer.
// - `RemisePaquet` : « J'ai remis le paquet au client » ; corps `{ sorte: "remise_paquet", manifest_sha256 }`, celui
//   du paquet affiché. Une remise ne s'efface pas ; « Corriger cette note » envoie `{ sorte: "correction_remise",
//   remise, motif }`, et la remise corrigée reste lisible.
// - `NomsApprobateurs` (décisions du 2026-11-25, CT-4 EX-7.8) : le nom de chaque approbateur, tel que le client l'a
//   donné, pour la fiche de contrôle ; corps `{ sorte: "noms_approbateurs", noms: [{ adresse, nom }] }` (`nom` null
//   pour retirer) ; modifiable tant que les approbateurs ne sont pas enregistrés ; la fiche change avec les noms.

import { useId, useState } from "react";
import { useRouter } from "next/navigation";
import { lireChamp } from "./champs-page.js";
import Icone from "./Icone.js";
import { Refus } from "./FormulaireTravail.js";
import { CHAMP_VIDE, explicationSaisie } from "../lib/parcours.mjs";

/** Longueurs bornées (src/commun/notes.mjs) : la page les dit avant d'envoyer, l'agent les refait. */
const NOM_MAX = 80;
const MOTIF_MAX = 300;

/** Remet une note ; rend null (notée) ou `{ code, message }`. */
async function noter(slug, corps) {
  let r;
  try {
    r = await fetch(`/api/clients/${slug}/notes`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(corps) });
  } catch {
    return { code: "outil_injoignable", message: "aucune réponse de l'outil à l'envoi de la note" };
  }
  if (r.ok) return null;
  const j = await r.json().catch(() => null);
  return { code: j?.error?.code ?? `http_${r.status}`, message: j?.error?.message ?? `refus (${r.status})` };
}

/** Un texte saisi : `{ valeur }` ou `{ erreur }` (phrase sans la valeur). */
function lireTexte(nom, brut, max, vide = CHAMP_VIDE) {
  const t = String(brut ?? "").trim();
  if (t === "") return { erreur: vide };
  if ([...t].length > max) return { erreur: `Ce texte est trop long : ${max} caractères au plus.` };
  const v = lireChamp({ nom, type: "texte" }, t);
  return v.erreur ? { erreur: explicationSaisie("texte") } : { valeur: v.valeur };
}

/** Champ texte d'une note : libellé, saisie, refus, aide, exemple. */
function ChampTexte({ id, nom, libelle, aide, exemple, erreur, zone = false, libelleAttributs = {} }) {
  const decrit = [aide ? `${id}-aide` : null, exemple ? `${id}-exemple` : null, erreur ? `${id}-erreur` : null].filter(Boolean).join(" ") || undefined;
  const commun = { id, name: nom, className: "nt-saisie", "data-type": "texte", autoComplete: "off", "aria-required": "true", "aria-describedby": decrit, "aria-invalid": erreur ? "true" : undefined };
  return (
    <div className="nt-champ">
      <label className="nt-libelle" htmlFor={id} {...libelleAttributs}>{libelle}</label>
      {zone ? <textarea {...commun} rows={3} /> : <input {...commun} type="text" />}
      {erreur ? <p className="nt-erreur" id={`${id}-erreur`} role="alert"><Icone nom="alerte" /><span>{erreur}</span></p> : null}
      {aide ? <p className="nt-aide" id={`${id}-aide`}>{aide}</p> : null}
      {exemple ? <p className="nt-aide ins-exemple" id={`${id}-exemple`} data-exemple="">Exemple : <span className="nt-fixe" data-valeur="">{exemple}</span></p> : null}
    </div>
  );
}

/**
 * Donner, changer ou retirer le nom interne d'un client. `nom` : le nom en vigueur, ou null. `compact` (sixième lecture :
 * sans nom interne, le formulaire est sur la fiche, sous la consigne, sans repli) : le champ et son bouton sur une ligne ; le libellé est l'invitation que la fiche donne (`invite`).
 */
export function NomInterne({ slug, nom = null, compact = false, invite = null }) {
  const id = useId();
  const router = useRouter();
  const [etat, setEtat] = useState({ erreur: null, refus: null, envoi: false, fait: null });
  const envoyer = async (corps, fait) => {
    setEtat({ erreur: null, refus: null, envoi: true, fait: null });
    const refus = await noter(slug, corps);
    if (refus) return setEtat({ erreur: null, refus, envoi: false, fait: null });
    setEtat({ erreur: null, refus: null, envoi: false, fait });
    router.refresh();
  };
  const enregistrer = async (ev) => {
    ev.preventDefault();
    const formulaire = ev.currentTarget;
    // Le formulaire compact n'a pas d'aide dessous : le refus d'un champ vide n'y renvoie pas.
    const v = lireTexte("nom", new FormData(formulaire).get("nom"), NOM_MAX, compact ? "Ce champ est vide : écrivez le nom sous lequel notre équipe reconnaîtra ce client." : CHAMP_VIDE);
    if (v.erreur) {
      setEtat({ erreur: v.erreur, refus: null, envoi: false, fait: null });
      document.getElementById(`${id}-nom`)?.focus();
      return;
    }
    await envoyer({ sorte: "nom_interne", nom: v.valeur }, "Le nom interne est enregistré.");
    formulaire.reset();
  };
  return (
    <div className="nt-pile" data-nom-interne-formulaire="">
      <form className={compact ? "nt-formulaire ins-nom-compact" : "nt-formulaire"} onSubmit={enregistrer} noValidate data-note="nom_interne">
        <ChampTexte
          id={`${id}-nom`}
          nom="nom"
          libelle={nom ? "Nouveau nom interne" : invite ?? "Nom interne"}
          libelleAttributs={invite ? { "data-nom-tire": "" } : {}}
          erreur={etat.erreur}
          aide={compact ? null : "Le nom sous lequel notre équipe reconnaît ce client, en 80 caractères au plus. Seule notre équipe le voit, dans cet outil : il ne part jamais vers le registre public, ni dans le paquet du client. Vous pourrez le changer."}
          exemple={compact ? null : "Assurances du Léman"}
        />
        <div className="nt-actions ins-actions-bouton">
          <button type="submit" className="nt-bouton" disabled={etat.envoi}>{nom ? "Changer le nom interne" : "Enregistrer ce nom"}</button>
          {nom ? <button type="button" className="nt-bouton" disabled={etat.envoi} onClick={() => envoyer({ sorte: "nom_interne", nom: null }, "Le nom interne est retiré : la liste et la fiche montrent de nouveau le nom court.")} data-retirer-nom="">Retirer le nom interne</button> : null}
        </div>
      </form>
      <div role="status" aria-live="polite">
        {etat.envoi ? <p className="nt-attenue nt-petit">Envoi de la note…</p> : null}
        {etat.fait ? <p className="nt-attenue nt-petit" data-note-faite="">{etat.fait}</p> : null}
      </div>
      {etat.refus ? <Refus code={etat.refus.code} message={etat.refus.message} slug={slug} /> : null}
    </div>
  );
}

/**
 * Noms des approbateurs de la fiche de contrôle : un champ par adresse du dossier (`adresses`), rempli du nom en
 * vigueur (`noms`, par adresse) ; « Enregistrer les noms » remet une note pour chaque adresse dont le nom change
 * (vidé : retiré). La fiche de contrôle change avec les noms : l'écran le dit.
 */
export function NomsApprobateurs({ slug, adresses, noms = {} }) {
  const id = useId();
  const router = useRouter();
  const [etat, setEtat] = useState({ erreurs: {}, refus: null, envoi: false, fait: null });
  const enregistrer = async (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.currentTarget);
    const erreurs = {};
    const liste = [];
    for (const adresse of adresses) {
      const brut = String(f.get(`nom-${adresse}`) ?? "").trim();
      const actuel = noms[adresse] ?? null;
      if (brut === "") {
        if (actuel !== null) liste.push({ adresse, nom: null });
        continue;
      }
      const v = lireTexte(`nom-${adresse}`, brut, NOM_MAX);
      if (v.erreur) erreurs[adresse] = v.erreur;
      else if (v.valeur !== actuel) liste.push({ adresse, nom: v.valeur });
    }
    if (Object.keys(erreurs).length > 0) {
      setEtat({ erreurs, refus: null, envoi: false, fait: null });
      document.getElementById(`${id}-${Object.keys(erreurs)[0]}`)?.focus();
      return;
    }
    if (liste.length === 0) return setEtat({ erreurs: {}, refus: null, envoi: false, fait: "Aucun nom n'a changé." });
    setEtat({ erreurs: {}, refus: null, envoi: true, fait: null });
    const refus = await noter(slug, { sorte: "noms_approbateurs", noms: liste });
    if (refus) return setEtat({ erreurs: {}, refus, envoi: false, fait: null });
    setEtat({ erreurs: {}, refus: null, envoi: false, fait: "Les noms sont enregistrés : la fiche de contrôle est refaite avec eux, et c'est elle que le client confirme." });
    router.refresh();
  };
  return (
    <div className="nt-pile" data-noms-approbateurs-formulaire="">
      <p className="nt-aide">Le nom de chaque approbateur, tel que le client vous l'a écrit, pour la fiche de contrôle que chaque approbateur relit. Ces noms ne partent jamais vers le registre public ni dans le paquet du client. Un nom changé refait la fiche : le client la confirme de nouveau.</p>
      <form className="nt-formulaire" onSubmit={enregistrer} noValidate data-note="noms_approbateurs">
        {adresses.map((adresse, k) => (
          <div className="nt-champ" key={adresse}>
            <label className="nt-libelle" htmlFor={`${id}-${adresse}`}>Approbateur {k + 1} <span className="nt-fixe ins-adresse" data-valeur="">{adresse}</span></label>
            <input id={`${id}-${adresse}`} name={`nom-${adresse}`} className="nt-saisie" data-type="texte" type="text" autoComplete="off" defaultValue={noms[adresse] ?? ""} aria-describedby={etat.erreurs[adresse] ? `${id}-${adresse}-erreur` : undefined} aria-invalid={etat.erreurs[adresse] ? "true" : undefined} data-nom-approbateur={adresse} />
            {etat.erreurs[adresse] ? <p className="nt-erreur" id={`${id}-${adresse}-erreur`} role="alert"><Icone nom="alerte" /><span>{etat.erreurs[adresse]}</span></p> : null}
          </div>
        ))}
        <div className="nt-actions ins-actions-bouton">
          <button type="submit" className="nt-bouton" disabled={etat.envoi} data-enregistrer-noms="">Enregistrer les noms</button>
        </div>
      </form>
      <div role="status" aria-live="polite">
        {etat.envoi ? <p className="nt-attenue nt-petit">Envoi de la note…</p> : null}
        {etat.fait ? <p className="nt-attenue nt-petit" data-note-faite="">{etat.fait}</p> : null}
      </div>
      {etat.refus ? <Refus code={etat.refus.code} message={etat.refus.message} slug={slug} /> : null}
    </div>
  );
}

/**
 * Remise du paquet : `manifeste`, l'empreinte du paquet affiché ; `enVigueur`, la remise non corrigée de ce paquet
 * (`{ id }`), ou null. Sans remise en vigueur : le bouton « J'ai remis le paquet au client ». Avec : « Corriger cette
 * note », replié, qui demande un motif.
 */
export function RemisePaquet({ slug, manifeste, enVigueur = null }) {
  const id = useId();
  const router = useRouter();
  const [etat, setEtat] = useState({ erreur: null, refus: null, envoi: false });
  const envoyer = async (corps) => {
    setEtat({ erreur: null, refus: null, envoi: true });
    const refus = await noter(slug, corps);
    if (refus) return setEtat({ erreur: null, refus, envoi: false });
    setEtat({ erreur: null, refus: null, envoi: false });
    router.refresh();
  };
  const corriger = async (ev) => {
    ev.preventDefault();
    const v = lireTexte("motif", new FormData(ev.currentTarget).get("motif"), MOTIF_MAX);
    if (v.erreur) {
      setEtat({ erreur: v.erreur, refus: null, envoi: false });
      document.getElementById(`${id}-motif`)?.focus();
      return;
    }
    await envoyer({ sorte: "correction_remise", remise: enVigueur.id, motif: v.valeur });
  };
  return (
    <div className="nt-pile">
      {enVigueur ? (
        <details className="nt-detail ins-replie" data-corriger-remise="">
          <summary>Corriger cette note<span className="nt-detail-note">seulement si la remise est notée par erreur</span></summary>
          <div className="nt-detail-corps nt-pile">
            <p>La note de remise ne s'efface pas : la correction s'ajoute à côté d'elle, avec votre nom, la date et le motif, et les deux restent lisibles. Le paquet est alors de nouveau « à remettre ».</p>
            <form className="nt-formulaire" onSubmit={corriger} noValidate data-note="correction_remise">
              <ChampTexte id={`${id}-motif`} nom="motif" libelle="Motif de la correction" erreur={etat.erreur} aide="Ce qui était faux dans la note, en 300 caractères au plus. Seule notre équipe le lit." exemple="Bouton cliqué par erreur : le paquet n'est pas encore remis." />
              <div className="nt-actions ins-actions-bouton">
                <button type="submit" className="nt-bouton" disabled={etat.envoi}>Noter la correction</button>
              </div>
            </form>
          </div>
        </details>
      ) : (
        <div className="nt-actions ins-actions-bouton">
          <button type="button" className="nt-bouton nt-bouton-principal" disabled={etat.envoi || !manifeste} onClick={() => envoyer({ sorte: "remise_paquet", manifest_sha256: manifeste })} data-noter-remise="" aria-describedby={`${id}-remise`}>J'ai remis le paquet au client</button>
          <p className="nt-aide" id={`${id}-remise`} data-sous-bouton="">Ce bouton note que vous avez remis ce paquet au client, avec la date, l'heure et votre nom. C'est votre déclaration : l'outil ne peut pas savoir si le client l'a reçu. Rien n'est envoyé au client ni au registre public. La note ne s'efface pas ; une erreur se corrige par une nouvelle note.</p>
        </div>
      )}
      <div role="status" aria-live="polite">{etat.envoi ? <p className="nt-attenue nt-petit">Envoi de la note…</p> : null}</div>
      {etat.refus ? <Refus code={etat.refus.code} message={etat.refus.message} slug={slug} /> : null}
    </div>
  );
}
