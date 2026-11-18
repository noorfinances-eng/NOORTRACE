"use client";
// Formulaire d'ajout d'une confirmation hors bande (EX-7.26) : opération, objet (clé de chaîne visée par un
// approvisionnement, ou condensé de la demande d'administration du jeu), personne du client qui a confirmé, canal (hors
// de l'application), instant, SHA-256 de la pièce qui la porte. L'agent y ajoute l'exploitant de la session et
// l'instant de réception. Chaque champ porte un type de la liste close d'EX-7.25.
//
// Présentation (complément du 2026-11-17) : trois sections courtes, un libellé et une aide par champ ; l'objet
// demandé suit l'opération choisie (clé de chaîne pour un approvisionnement, condensé pour une administration du
// jeu) ; la saisie refusée se dit en clair sous le champ, sans la valeur.
//
// Langage et aides de saisie (complément du 2026-11-18, décision du porteur sur le langage des écrans ; CT-4
// EX-7.25, complément de même date). Ce qui est envoyé à la route ne change pas. Deux aides remplissent un champ
// sans rien envoyer elles-mêmes ; elles n'ont pas de nom de champ :
// - « Choisir la pièce » : le fichier choisi est lu dans la page, son SHA-256 est calculé par le navigateur
//   (`crypto.subtle.digest`) et écrit dans le champ de l'empreinte ; le fichier ne part nulle part et n'est gardé
//   nulle part ; la saisie à la main reste possible ;
// - « Date et heure » et « Maintenant » : la date et l'heure du poste sont converties en temps universel, à la
//   forme exacte que la route attend (AAAA-MM-JJThh:mm:ss.sssZ), écrite dans le champ de l'instant, sous l'aide.
//   Sous le champ, l'aide dit que c'est l'heure du poste et que l'outil la convertit, puis montre la valeur
//   convertie en clair, pour que les deux horloges ne se confondent pas. Le champ natif s'affiche dans la langue
//   du navigateur : la date choisie est donc toujours redite dessous, en toutes lettres et en français.
//
// Relecture avant de noter (même complément, seconde lecture) : une confirmation notée ne s'efface pas. Le haut du
// formulaire redit ce que le client confirme (le montant et le compte, ou le document) ; le premier clic ne fait que
// contrôler la saisie et afficher un récapitulatif à relire ; seul le second clic, « C'est exact, noter la
// confirmation », envoie, et il envoie l'objet relu, celui que la route recevait déjà. Toute retouche d'un champ
// annule la relecture.

import { useId, useRef, useState } from "react";
import { lireChamp } from "./champs-page.js";
import Icone from "./Icone.js";
import { Refus } from "./FormulaireTravail.js";
import { ADRESSE_A_CONFIRMER, CREDITS_EN_CLAIR, OPERATIONS_CONFIRMATION, dateLisible, explicationSaisie, jourLisible, nombreLisible } from "../lib/parcours.mjs";

const MOTIF_INSTANT = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;
const deux = (n) => String(n).padStart(2, "0");
/** Date du poste à la forme d'un champ « date et heure » (`AAAA-MM-JJThh:mm`, heure locale). */
const versChampLocal = (d) => `${d.getFullYear()}-${deux(d.getMonth() + 1)}-${deux(d.getDate())}T${deux(d.getHours())}:${deux(d.getMinutes())}`;
/** Valeur d'un champ « date et heure » (heure du poste) en instant universel exact, ou "" si elle est illisible. */
function versInstant(local) {
  const d = new Date(local);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString();
}
/** Valeur d'un champ « date et heure » en toutes lettres, en français : « 18 novembre 2026 à 10 h 12 » ; illisible : "". */
function localEnClair(local) {
  const m = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2})/.exec(String(local ?? ""));
  if (!m) return "";
  const jour = jourLisible(`${m[1]}-${m[2]}-${m[3]}T00:00:00Z`);
  return /^[0-9]/.test(jour) && !jour.includes("T") ? `${jour} à ${Number(m[4])} h ${m[5]}` : "";
}
const taille = (n) => (n < 1024 ? "moins de 1 Ko" : n < 1024 * 1024 ? `${Math.round(n / 1024)} Ko` : `${(n / 1024 / 1024).toFixed(1).replace(".", ",")} Mo`);

export default function FormulaireConfirmation({ slug, orgId, comptes, montant = null }) {
  const prefixe = useId();
  const fichier = useRef(null);
  const [operation, setOperation] = useState("approvisionnement");
  const [local, setLocal] = useState("");
  const [instant, setInstant] = useState("");
  const [empreinte, setEmpreinte] = useState("");
  const [piece, setPiece] = useState(null);
  const [compte, setCompte] = useState(comptes[0]?.adresse ?? "");
  const [etat, setEtat] = useState({ saisie: null, refus: null, inscrite: null, envoi: false });
  // La confirmation contrôlée, à relire : c'est cet objet, et lui seul, que le second clic envoie.
  const [relecture, setRelecture] = useState(null);
  const administration = operation === "administrer-jeu";
  const choisi = comptes.find((c) => c.adresse === compte) ?? null;
  const choisirLocal = (valeur) => {
    setRelecture(null);
    setLocal(valeur);
    setInstant(versInstant(valeur));
  };
  const maintenant = () => {
    const d = new Date();
    setRelecture(null);
    setLocal(versChampLocal(d));
    setInstant(d.toISOString());
  };
  // Le fichier est lu ici, dans la page ; seule son empreinte va dans le champ. Rien n'est envoyé ni gardé.
  const calculer = async (ev) => {
    const f = ev.target.files?.[0];
    ev.target.value = "";
    if (!f) return;
    setRelecture(null);
    if (!window.crypto?.subtle) {
      setPiece({ erreur: "Ce navigateur ne sait pas calculer l'empreinte ici. Demandez à l'équipe technique de la calculer pour vous, puis collez-la dans le champ ci-dessous." });
      return;
    }
    try {
      const condense = await window.crypto.subtle.digest("SHA-256", await f.arrayBuffer());
      setEmpreinte(`0x${[...new Uint8Array(condense)].map((x) => x.toString(16).padStart(2, "0")).join("")}`);
      setPiece({ nom: f.name, taille: f.size });
    } catch {
      setPiece({ erreur: "Le fichier n'a pas pu être lu. Vérifiez qu'il est bien sur votre poste et réessayez." });
    }
  };
  /** Premier clic : la saisie est contrôlée et le récapitulatif s'affiche ; rien n'est envoyé. */
  const relire = (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.currentTarget);
    const refuser = (champ, type) => {
      setRelecture(null);
      setEtat({ saisie: { champ, message: explicationSaisie(type) }, refus: null, inscrite: null, envoi: false });
      document.getElementById(`${prefixe}-${champ}`)?.focus();
    };
    const v = {};
    const champs = [administration ? { nom: "digest", type: "hachage" } : { nom: "cle_chaine", type: "adresse" }, { nom: "personne_client", type: "texte" }, { nom: "canal", type: "texte" }];
    for (const c of champs) {
      const r = lireChamp(c, String(f.get(c.nom) ?? ""));
      if (r.erreur) return refuser(c.nom, c.type);
      v[c.nom] = r.valeur;
    }
    const saisi = String(f.get("instant") ?? "").trim();
    if (!MOTIF_INSTANT.test(saisi)) return refuser("instant", "horodatage");
    const lue = lireChamp({ nom: "piece_sha256", type: "hachage" }, String(f.get("piece_sha256") ?? ""));
    if (lue.erreur) return refuser("piece_sha256", "hachage");
    const objet = administration ? { org_id: orgId, digest: v.digest } : { org_id: orgId, cle_chaine: v.cle_chaine };
    const confirmation = { operation, objet, personne_client: v.personne_client, canal: v.canal, instant: saisi, piece_sha256: lue.valeur };
    setEtat({ saisie: null, refus: null, inscrite: null, envoi: false });
    // L'heure du poste n'est redite que si elle est bien celle de l'instant relu (elle ne l'est plus après une retouche à la main).
    setRelecture({ confirmation, local: versInstant(local).slice(0, 16) === saisi.slice(0, 16) ? localEnClair(local) : "", piece: piece?.nom && empreinte.trim().toLowerCase() === lue.valeur ? piece.nom : null });
  };
  /** Second clic : l'objet relu part tel quel, comme avant. */
  const envoyer = async () => {
    if (!relecture) return;
    const confirmation = relecture.confirmation;
    setEtat({ saisie: null, refus: null, inscrite: null, envoi: true });
    let r;
    try {
      r = await fetch(`/api/clients/${slug}/confirmations`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(confirmation) });
    } catch {
      return setEtat({ saisie: null, refus: { code: "outil_injoignable", message: "aucune réponse de l'outil à l'envoi de la confirmation" }, inscrite: null, envoi: false });
    }
    const corps = await r.json().catch(() => null);
    if (!r.ok) return setEtat({ saisie: null, refus: { code: corps?.error?.code ?? `http_${r.status}`, message: corps?.error?.message ?? `refus (${r.status})` }, inscrite: null, envoi: false });
    setEtat({ saisie: null, refus: null, inscrite: corps.id, envoi: false });
    window.location.reload();
  };
  const champ = (nom, libelle, aide, entree, { exemple = null, avant = null } = {}) => {
    const id = `${prefixe}-${nom}`;
    const erreur = etat.saisie?.champ === nom ? etat.saisie.message : null;
    const decrit = [aide ? `${id}-aide` : null, exemple ? `${id}-exemple` : null, erreur ? `${id}-erreur` : null].filter(Boolean).join(" ") || undefined;
    return (
      <div className="nt-champ" key={nom}>
        <label className="nt-libelle" htmlFor={id}>{libelle}</label>
        {avant}
        {entree({ id, name: nom, "aria-describedby": decrit, "aria-invalid": erreur ? "true" : undefined, autoComplete: "off", spellCheck: false })}
        {erreur ? <p className="nt-erreur" id={`${id}-erreur`} role="alert"><Icone nom="alerte" /><span>{erreur}</span></p> : null}
        {aide ? <p className="nt-aide" id={`${id}-aide`}>{aide}</p> : null}
        {exemple ? <p className="nt-aide ins-exemple" id={`${id}-exemple`} data-exemple="">Exemple : <span data-valeur="">{exemple}</span></p> : null}
      </div>
    );
  };
  return (
    <form className="nt-formulaire" onSubmit={relire} onInput={() => { if (relecture) setRelecture(null); }} data-formulaire="confirmation">
      <fieldset className="nt-groupe-champs ins-section">
        <legend>Ce que le client a confirmé</legend>
        {champ("operation", "Opération confirmée", "Une confirmation ne vaut que pour une seule opération. Pour une inscription en cours, c'est le premier choix.", (a) => (
          <select {...a} className="nt-saisie" data-type="texte" value={operation} onChange={(ev) => setOperation(ev.target.value)}>
            {Object.entries(OPERATIONS_CONFIRMATION).map(([code, libelle]) => <option key={code} value={code}>{libelle}</option>)}
          </select>
        ))}
        {administration
          ? champ("digest", "Empreinte du document de changement", "L'empreinte du document que le client a confirmé. Elle est écrite dans le document préparé : fiche du client, « Documents à faire signer par le client », ligne « digest ». Copiez-la sans la retaper : « 0x » suivi de 64 caractères.", (a) => <input {...a} className="nt-saisie nt-saisie-fixe" data-type="hachage" required />)
          : champ("cle_chaine", "Compte technique concerné", "Le compte technique de l'enregistreur du client, sur lequel portera le versement. C'est ce compte, avec son adresse entière, que le client confirme.", (a) => (
            <select {...a} className="nt-saisie nt-saisie-fixe" data-type="adresse" data-valeur="" value={compte} onChange={(ev) => setCompte(ev.target.value)}>{comptes.map((c) => <option key={c.adresse} value={c.adresse}>{c.nom ? `${c.nom} · ${c.adresse}` : c.adresse}</option>)}</select>
          ))}
        <div className="nt-encart nt-pile" data-ce-que-confirme={operation}>
          <p className="nt-sur-titre">Ce que le client confirme</p>
          {administration ? (
            <p>Le changement de la liste de ses approbateurs que décrit le document dont vous donnez l'empreinte ci-dessus, et aucun autre.</p>
          ) : (
            <>
              <p>
                {operation === "approvisionnement" ? "Le versement de " : "Un nouveau versement, qui complète le compte jusqu'à "}
                {montant ? <><span data-valeur="">{nombreLisible(montant)}</span> crédits d'écriture</> : "crédits d'écriture"}
                {operation === "approvisionnement" ? " sur le compte technique" : ", sur le compte technique"}{choisi?.nom ? <> de son enregistreur <span className="nt-fixe" data-valeur="">{choisi.nom}</span></> : null}, dont l'adresse est <span className="nt-fixe" data-valeur="">{compte}</span>.
              </p>
              <p className="nt-aide">{CREDITS_EN_CLAIR}</p>
              <p className="nt-aide">L'adresse : {ADRESSE_A_CONFIRMER.charAt(0).toLowerCase()}{ADRESSE_A_CONFIRMER.slice(1)}</p>
            </>
          )}
        </div>
      </fieldset>
      <fieldset className="nt-groupe-champs ins-section">
        <legend>Qui a confirmé, et comment</legend>
        {champ("personne_client", "Personne qui a confirmé", "Son nom et sa fonction chez le client.", (a) => <input {...a} className="nt-saisie" data-type="texte" required maxLength={256} />, { exemple: "Camille Durand, responsable de la conformité" })}
        {champ("canal", "Moyen de la confirmation", "Un moyen autre que cet outil, que le client ne peut pas confondre avec lui.", (a) => <input {...a} className="nt-saisie" data-type="texte" required maxLength={256} />, { exemple: "appel au numéro du contrat" })}
        <div className="nt-champ">
          <label className="nt-libelle" htmlFor={`${prefixe}-date`}>Date et heure de la confirmation</label>
          <div className="ins-aide-saisie">
            <input id={`${prefixe}-date`} className="nt-saisie" type="datetime-local" data-type="texte" value={local} onChange={(ev) => choisirLocal(ev.target.value)} aria-describedby={`${prefixe}-date-aide`} data-aide-saisie="date" />
            <button type="button" className="nt-bouton" onClick={maintenant} data-aide-saisie="maintenant">Maintenant</button>
          </div>
          <p className="nt-aide" id={`${prefixe}-date-aide`}>Heure de votre poste ; l'outil la convertit. Donnez la date et l'heure à votre montre, ou cliquez sur « Maintenant » si le client vient de confirmer : le champ suivant se remplit pour vous.</p>
          {localEnClair(local) ? <p className="nt-aide" data-date-en-clair="" aria-live="polite">Vous avez choisi : <strong>{localEnClair(local)}</strong>, heure de votre poste.</p> : null}
          {MOTIF_INSTANT.test(instant) ? <p className="nt-aide" data-instant-converti="" aria-live="polite">Converti en temps universel (UTC) : <strong>{dateLisible(instant)}</strong>. C'est cette heure, et non celle de votre poste, que l'outil enregistre et affiche partout.</p> : null}
        </div>
        {champ("instant", "Instant enregistré", "C'est cette valeur, en temps universel (UTC), qui sera enregistrée. Elle se remplit toute seule ; ne la modifiez que si l'équipe technique vous le demande.", (a) => <input {...a} className="nt-saisie nt-saisie-fixe" data-type="texte" required value={instant} onChange={(ev) => setInstant(ev.target.value)} />)}
      </fieldset>
      <fieldset className="nt-groupe-champs ins-section">
        <legend>La pièce qui garde la trace de la confirmation</legend>
        <p className="nt-aide">La pièce est le courrier signé du client, ou votre compte rendu de l'appel. Rangez-la dans le dossier du client : l'outil ne la reçoit pas. Il n'en garde que l'empreinte : une suite de caractères qui identifie la pièce sans erreur possible, et qui prouvera plus tard que c'est bien celle-là.</p>
        {champ("piece_sha256", "Empreinte de la pièce", "Remplie par le bouton « Choisir la pièce ». Vous pouvez aussi la coller si quelqu'un l'a calculée pour vous : « 0x » suivi de 64 caractères.", (a) => <input {...a} className="nt-saisie nt-saisie-fixe" data-type="hachage" required value={empreinte} onChange={(ev) => { setEmpreinte(ev.target.value); setPiece(null); }} />, {
          avant: (
            <div className="ins-aide-saisie">
              <input ref={fichier} type="file" hidden tabIndex={-1} data-type="hachage" onChange={calculer} data-aide-saisie="piece" aria-hidden="true" />
              <button type="button" className="nt-bouton" onClick={() => fichier.current?.click()} data-aide-saisie="choisir-piece">Choisir la pièce</button>
              <p className="nt-aide" role="status" data-piece-choisie="">
                {piece?.erreur ? piece.erreur : piece ? <>Empreinte calculée sur votre poste pour <span className="nt-fixe" data-valeur="">{piece.nom}</span> ({taille(piece.taille)}). Le fichier n'a pas quitté votre poste.</> : "Le fichier ne quitte pas votre poste : l'outil calcule son empreinte ici même, sans l'envoyer."}
              </p>
            </div>
          ),
        })}
      </fieldset>
      <div className="nt-bandeau nt-bandeau-avertissement">
        <Icone nom="alerte" />
        <div className="nt-bandeau-texte">
          <p className="nt-bandeau-titre">Une confirmation notée ne s'efface pas.</p>
          <p>C'est pourquoi l'outil vous fait relire avant de noter : le premier bouton n'envoie rien, il affiche ce que vous allez noter. Si vous découvrez une erreur après coup, ne lancez rien : prévenez l'équipe technique, car une confirmation fausse reste dans la liste et peut encore autoriser l'opération.</p>
        </div>
      </div>
      {relecture ? (
        <section className="nt-encart ins-relecture" data-relecture="" aria-labelledby={`${prefixe}-relecture`}>
          <h3 id={`${prefixe}-relecture`}>Relisez avant de noter</h3>
          <p className="nt-aide">Rien n'est encore envoyé. Comparez chaque ligne à la pièce que vous avez sous les yeux.</p>
          <dl className="nt-definitions">
            <dt>Le client confirme</dt>
            <dd data-relu="objet">
              {relecture.confirmation.operation === "administrer-jeu" ? (
                <span>un changement de la liste de ses approbateurs ; empreinte du document : <span className="nt-fixe" data-valeur="">{relecture.confirmation.objet.digest}</span></span>
              ) : (
                <span>
                  {relecture.confirmation.operation === "approvisionnement" ? "le versement de " : "un nouveau versement, qui complète le compte jusqu'à "}
                  {montant ? <><span data-valeur="">{nombreLisible(montant)}</span> crédits d'écriture</> : "crédits d'écriture"}
                  {" "}sur le compte technique{comptes.find((c) => c.adresse === relecture.confirmation.objet.cle_chaine)?.nom ? <> de son enregistreur <span className="nt-fixe" data-valeur="">{comptes.find((c) => c.adresse === relecture.confirmation.objet.cle_chaine).nom}</span></> : null}, adresse <span className="nt-fixe" data-valeur="">{relecture.confirmation.objet.cle_chaine}</span>
                </span>
              )}
            </dd>
            <dt>Personne qui a confirmé</dt><dd data-relu="personne"><span data-valeur="">{relecture.confirmation.personne_client}</span></dd>
            <dt>Moyen</dt><dd data-relu="moyen"><span data-valeur="">{relecture.confirmation.canal}</span></dd>
            <dt>Date et heure</dt>
            <dd data-relu="date">
              {relecture.local ? <span>{relecture.local}, heure de votre poste</span> : null}
              <span>{relecture.local ? "soit, en temps universel : " : "en temps universel : "}<strong>{dateLisible(relecture.confirmation.instant)}</strong></span>
            </dd>
            <dt>Pièce</dt>
            <dd data-relu="piece">
              {relecture.piece ? <span>le fichier <span className="nt-fixe" data-valeur="">{relecture.piece}</span></span> : <span>empreinte saisie à la main</span>}
              <span>son empreinte commence par <span className="nt-fixe" data-valeur="">{relecture.confirmation.piece_sha256.slice(0, 10)}</span> et finit par <span className="nt-fixe" data-valeur="">{relecture.confirmation.piece_sha256.slice(-8)}</span></span>
            </dd>
          </dl>
          <div className="nt-actions">
            <button type="button" className="nt-bouton nt-bouton-principal" onClick={envoyer} disabled={etat.envoi} data-noter="">C'est exact, noter la confirmation</button>
            <button type="button" className="nt-bouton" onClick={() => setRelecture(null)} disabled={etat.envoi} data-corriger="">Corriger</button>
          </div>
          <p className="nt-aide">Après ce clic : la confirmation rejoint la liste, et elle n'en sortira plus.</p>
        </section>
      ) : (
        <div className="nt-actions">
          <button type="submit" className="nt-bouton nt-bouton-principal" disabled={etat.envoi}>Relire avant de noter</button>
        </div>
      )}
      {etat.refus ? <Refus code={etat.refus.code} message={etat.refus.message} titre="La confirmation n'a pas été notée." /> : null}
      <p className={etat.inscrite || etat.envoi || etat.saisie ? "nt-attenue nt-petit" : "nt-masque"} role="status">{etat.inscrite ? "Confirmation notée. La page se recharge." : etat.envoi ? "Envoi au service d'inscription…" : etat.saisie ? "Rien n'a été envoyé : un champ est à corriger, il est signalé en rouge." : ""}</p>
    </form>
  );
}
