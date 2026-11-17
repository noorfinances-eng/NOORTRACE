// /clients/<slug>/confirmations : registre des confirmations hors bande du client (EX-7.26) et formulaire d'ajout.
//
// Présentation (complément du 2026-11-17) : une carte par confirmation. Ce qui engage reste visible et exact,
// hors de tout bloc replié : la personne du client, le canal, l'instant exact, l'objet visé (clé de chaîne ou
// condensé), l'empreinte SHA-256 de la pièce en entier, l'exploitant qui l'a recueillie, le travail qui l'a
// consommée. L'état (disponible ou consommée) se lit par un mot et une icône.

import { notFound } from "next/navigation";
import { client, confirmations } from "../../../../lib/donnees.mjs";
import { exigerSession } from "../../../../lib/page.mjs";
import { OPERATIONS_CONFIRMATION, dateLisible } from "../../../../lib/parcours.mjs";
import FormulaireConfirmation from "../../../../composants/FormulaireConfirmation.js";
import Icone from "../../../../composants/Icone.js";
import Pastille from "../../../../composants/Pastille.js";

export const dynamic = "force-dynamic";

export default async function PageConfirmations({ params }) {
  await exigerSession();
  const { slug } = await params;
  const c = client(slug);
  if (!c) notFound();
  const liste = confirmations(slug);
  const disponibles = liste.filter((x) => !x.consommee_par).length;
  return (
    <main className="nt-page">
      <a className="nt-fil" href={`/clients/${slug}`}><Icone nom="retour" />Fiche du client</a>
      <header className="nt-entete">
        <div className="nt-entete-texte">
          <p className="nt-sur-titre">Client <span className="nt-fixe">{slug}</span></p>
          <h1>Confirmations hors bande</h1>
          <p className="nt-sous-titre">Avant tout versement à une clé de chaîne et avant tout changement du jeu d'approbateurs, le client confirme l'opération par un autre canal que cette application. Ce registre en garde la trace ; rien ne s'en efface.</p>
        </div>
        <div className="nt-entete-etat">
          <Pastille ton={disponibles > 0 ? "info" : ""} icone={disponibles > 0 ? "info" : "tiret"} grande>{disponibles === 0 ? "Aucune disponible" : `${disponibles} ${disponibles > 1 ? "disponibles" : "disponible"}`}</Pastille>
        </div>
      </header>

      <section className="nt-pile" aria-labelledby="registre-titre">
        <h2 id="registre-titre">Registre</h2>
        {liste.length === 0 ? (
          <div className="nt-vide">
            <Icone nom="dossier" />
            <p className="nt-vide-titre">Aucune confirmation consignée.</p>
            <p className="nt-vide-texte">Sans confirmation, l'agent n'approvisionne aucune clé et ne relaie aucun changement du jeu.</p>
          </div>
        ) : liste.map((x) => (
          <article className="nt-carte" key={x.id} data-confirmation={x.id}>
            <div className="nt-carte-titre">
              <h3>{OPERATIONS_CONFIRMATION[x.operation] ?? x.operation}</h3>
              {x.consommee_par ? <Pastille icone="coche">Consommée</Pastille> : <Pastille ton="info" icone="info">Disponible</Pastille>}
            </div>
            <dl className="nt-definitions">
              <dt>Personne du client</dt><dd>{x.personne_client}</dd>
              <dt>Canal</dt><dd>{x.canal}</dd>
              <dt>Instant de la confirmation</dt><dd><time dateTime={x.instant}>{dateLisible(x.instant)}</time><span className="nt-fixe nt-attenue">{x.instant}</span></dd>
              {x.objet?.cle_chaine ? <div className="ins-contenu"><dt>Clé de chaîne visée</dt><dd><span className="nt-fixe">{x.objet.cle_chaine}</span></dd></div> : null}
              {x.objet?.digest ? <div className="ins-contenu"><dt>Condensé de la demande visée</dt><dd><span className="nt-fixe">{x.objet.digest}</span></dd></div> : null}
              <dt>Empreinte SHA-256 de la pièce</dt><dd><span className="nt-fixe" data-piece>{x.piece_sha256}</span></dd>
              <dt>Recueillie par</dt><dd><span className="nt-fixe">{x.exploitant}</span></dd>
              <dt>Consignée</dt><dd><time dateTime={x.recu_a}>{dateLisible(x.recu_a)}</time><span className="nt-fixe nt-attenue">{x.recu_a}</span></dd>
              <dt>Emploi</dt><dd>{x.consommee_par ? <span>consommée par le travail <span className="nt-fixe">{x.consommee_par}</span></span> : "pas encore employée : elle autorise une opération"}</dd>
            </dl>
            <details className="ins-detail">
              <summary>Détail technique</summary>
              <dl className="nt-definitions ins-detail-corps">
                <dt>Confirmation</dt><dd><span className="nt-fixe">{x.id}</span></dd>
                <dt>Opération</dt><dd><span className="nt-fixe">{x.operation}</span></dd>
                <dt>Organisation</dt><dd><span className="nt-fixe">{x.objet?.org_id}</span></dd>
              </dl>
            </details>
          </article>
        ))}
      </section>

      <section className="nt-carte" aria-labelledby="ajout-titre">
        <h2 id="ajout-titre">Consigner une confirmation</h2>
        <p className="nt-attenue">Consignez ce que le client a confirmé, à qui, par quel canal et quand. La pièce qui porte la confirmation reste hors de l'application : seule son empreinte entre ici.</p>
        <FormulaireConfirmation slug={slug} orgId={c.dossier.organisation.org_id} clesChaine={c.dossier.recorders.map((r) => r.chain_key)} />
      </section>
    </main>
  );
}
