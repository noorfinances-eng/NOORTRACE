"use client";
// Formulaire d'ajout d'une confirmation hors bande (EX-7.26) : opération, objet (clé de chaîne visée par un
// approvisionnement, ou condensé de la demande d'administration du jeu), personne du client qui a confirmé, canal (hors
// de l'application), instant, SHA-256 de la pièce qui la porte. L'agent y ajoute l'exploitant de la session et
// l'instant de réception. Chaque champ porte un type de la liste close d'EX-7.25.
//
// Présentation (complément du 2026-11-17) : trois sections courtes, un libellé et une aide par champ ; l'objet
// demandé suit l'opération choisie (clé de chaîne pour un approvisionnement, condensé pour une administration du
// jeu) ; la saisie refusée se dit en clair sous le champ, sans la valeur.

import { useId, useState } from "react";
import { lireChamp } from "./champs-page.js";
import Icone from "./Icone.js";
import { OPERATIONS_CONFIRMATION, explicationErreur, explicationSaisie } from "../lib/parcours.mjs";

const MOTIF_INSTANT = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;

export default function FormulaireConfirmation({ slug, orgId, clesChaine }) {
  const prefixe = useId();
  const [operation, setOperation] = useState("approvisionnement");
  const [etat, setEtat] = useState({ saisie: null, refus: null, inscrite: null });
  const administration = operation === "administrer-jeu";
  const envoyer = async (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.currentTarget);
    const refuser = (champ, type) => setEtat({ saisie: { champ, message: explicationSaisie(type) }, refus: null, inscrite: null });
    const v = {};
    const champs = [administration ? { nom: "digest", type: "hachage" } : { nom: "cle_chaine", type: "adresse" }, { nom: "personne_client", type: "texte" }, { nom: "canal", type: "texte" }];
    for (const c of champs) {
      const r = lireChamp(c, String(f.get(c.nom) ?? ""));
      if (r.erreur) return refuser(c.nom, c.type);
      v[c.nom] = r.valeur;
    }
    const instant = String(f.get("instant") ?? "").trim();
    if (!MOTIF_INSTANT.test(instant)) return refuser("instant", "horodatage");
    const piece = lireChamp({ nom: "piece_sha256", type: "hachage" }, String(f.get("piece_sha256") ?? ""));
    if (piece.erreur) return refuser("piece_sha256", "hachage");
    const objet = administration ? { org_id: orgId, digest: v.digest } : { org_id: orgId, cle_chaine: v.cle_chaine };
    const confirmation = { operation, objet, personne_client: v.personne_client, canal: v.canal, instant, piece_sha256: piece.valeur };
    const r = await fetch(`/api/clients/${slug}/confirmations`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(confirmation) });
    const corps = await r.json().catch(() => null);
    if (!r.ok) return setEtat({ saisie: null, refus: { code: corps?.error?.code ?? `http_${r.status}`, message: corps?.error?.message ?? `refus (${r.status})` }, inscrite: null });
    setEtat({ saisie: null, refus: null, inscrite: corps.id });
    window.location.reload();
  };
  const champ = (nom, libelle, aide, entree) => {
    const id = `${prefixe}-${nom}`;
    const erreur = etat.saisie?.champ === nom ? etat.saisie.message : null;
    const decrit = [aide ? `${id}-aide` : null, erreur ? `${id}-erreur` : null].filter(Boolean).join(" ") || undefined;
    return (
      <div className="nt-champ" key={nom}>
        <label className="nt-libelle" htmlFor={id}>{libelle}</label>
        {entree({ id, name: nom, "aria-describedby": decrit, "aria-invalid": erreur ? "true" : undefined, autoComplete: "off", spellCheck: false })}
        {aide ? <p className="nt-aide" id={`${id}-aide`}>{aide}</p> : null}
        {erreur ? <p className="nt-erreur" id={`${id}-erreur`} role="alert"><Icone nom="alerte" /><span>{erreur}</span></p> : null}
      </div>
    );
  };
  const refus = etat.refus ? explicationErreur(etat.refus.code) : null;
  return (
    <form className="nt-formulaire" onSubmit={envoyer} data-formulaire="confirmation">
      <fieldset className="nt-groupe-champs ins-section">
        <legend>Ce que le client a confirmé</legend>
        {champ("operation", "Opération confirmée", "Une confirmation ne vaut que pour une opération : un versement, ou un changement du jeu.", (a) => (
          <select {...a} className="nt-saisie" data-type="texte" value={operation} onChange={(ev) => setOperation(ev.target.value)}>
            {Object.entries(OPERATIONS_CONFIRMATION).map(([code, libelle]) => <option key={code} value={code}>{libelle}</option>)}
          </select>
        ))}
        {administration
          ? champ("digest", "Condensé de la demande d'administration du jeu", "« 0x » suivi de 64 chiffres hexadécimaux : le condensé de la demande que le client a confirmée.", (a) => <input {...a} className="nt-saisie nt-saisie-fixe" data-type="hachage" required />)
          : champ("cle_chaine", "Clé de chaîne à approvisionner", "La clé de chaîne du dossier que le versement visera.", (a) => (
            <select {...a} className="nt-saisie nt-saisie-fixe" data-type="adresse">{clesChaine.map((c) => <option key={c} value={c}>{c}</option>)}</select>
          ))}
      </fieldset>
      <fieldset className="nt-groupe-champs ins-section">
        <legend>Qui a confirmé, et comment</legend>
        {champ("personne_client", "Personne du client qui a confirmé", "Son nom et sa fonction.", (a) => <input {...a} className="nt-saisie" data-type="texte" required maxLength={256} placeholder="Camille Durand, responsable de la conformité" />)}
        {champ("canal", "Canal de la confirmation", "Un canal hors de cette application : appel au numéro du contrat, courrier signé.", (a) => <input {...a} className="nt-saisie" data-type="texte" required maxLength={256} placeholder="appel au numéro du contrat" />)}
        {champ("instant", "Instant de la confirmation", "En temps universel (UTC), sous la forme AAAA-MM-JJThh:mm:ss.sssZ.", (a) => <input {...a} className="nt-saisie nt-saisie-fixe" data-type="texte" required placeholder="2026-11-17T09:12:00.000Z" />)}
      </fieldset>
      <fieldset className="nt-groupe-champs ins-section">
        <legend>La pièce qui porte la confirmation</legend>
        {champ("piece_sha256", "Empreinte SHA-256 de la pièce", "« 0x » suivi de 64 chiffres hexadécimaux. La pièce elle-même (courrier signé, procès-verbal) reste hors de l'application : seule son empreinte est consignée.", (a) => <input {...a} className="nt-saisie nt-saisie-fixe" data-type="hachage" required />)}
      </fieldset>
      <div className="nt-bandeau nt-bandeau-avertissement">
        <Icone nom="alerte" />
        <div className="nt-bandeau-texte">
          <p className="nt-bandeau-titre">Une confirmation consignée ne s'efface pas.</p>
          <p>Le registre des confirmations est en ajout seul. Relisez la personne, le canal, l'instant et l'empreinte avant de consigner.</p>
        </div>
      </div>
      <div className="nt-actions">
        <button type="submit" className="nt-bouton nt-bouton-principal">Consigner la confirmation</button>
      </div>
      {refus ? (
        <div className="nt-bandeau nt-bandeau-erreur" role="alert">
          <Icone nom="alerte" />
          <div className="nt-bandeau-texte">
            <p className="nt-bandeau-titre">La confirmation n'a pas été consignée. {refus.phrase}</p>
            <p>{refus.quoiFaire}</p>
            <details className="ins-detail">
              <summary>Détail technique</summary>
              <dl className="nt-definitions ins-detail-corps">
                <dt>Code</dt><dd><span className="nt-fixe">{etat.refus.code}</span></dd>
                <dt>Message exact</dt><dd><span className="nt-fixe">{etat.refus.message}</span></dd>
              </dl>
            </details>
          </div>
        </div>
      ) : null}
      <p className={etat.inscrite ? "nt-attenue nt-petit" : "nt-masque"} role="status">{etat.inscrite ? `Confirmation ${etat.inscrite} consignée.` : ""}</p>
    </form>
  );
}
