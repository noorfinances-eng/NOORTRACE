// /clients/<slug>/paquet : production du paquet client (CT-4 §7.13), son contrôle (EX-7.22), et le gabarit du service
// d'approbation (console_origin et administrators, donnés par écrit par le client, ou null : EX-7.20).

import { notFound } from "next/navigation";
import { client } from "../../../../lib/donnees.mjs";
import { exigerSession } from "../../../../lib/page.mjs";
import FormulaireTravail from "../../../../composants/FormulaireTravail.js";

export const dynamic = "force-dynamic";

export default async function PagePaquet({ params }) {
  await exigerSession();
  const { slug } = await params;
  const c = client(slug);
  if (!c) notFound();
  const dernier = c.paquet.dernier;
  return (
    <>
      <h1>Paquet client · {slug}</h1>
      <p><a href={`/clients/${slug}`}>Retour au dossier</a></p>
      <p>{c.paquet.present ? <a href={`/api/clients/${slug}/paquet`}>Télécharger l'archive du paquet (tar)</a> : "Aucun paquet produit."}</p>
      {dernier ? <pre>{JSON.stringify(dernier, null, 2)}</pre> : null}
      <FormulaireTravail
        titre="Produire le paquet"
        commande="paquet"
        slug={slug}
        champs={[
          { nom: "prepared_by", libelle: "Producteur du paquet (texte)", type: "texte" },
          { nom: "console_origin", libelle: "Origine HTTPS de la console du client, donnée par écrit (vide : null)", type: "origine", facultatif: true, nullSiVide: true },
          { nom: "administrators", libelle: "Identités de session des administrateurs de l'annuaire, une par ligne (vide : null)", type: "liste_identites", facultatif: true, nullSiVide: true },
        ]}
        bouton="Produire et contrôler le paquet"
      />
    </>
  );
}
