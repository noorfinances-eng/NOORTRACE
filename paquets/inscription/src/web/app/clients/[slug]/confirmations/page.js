// /clients/<slug>/confirmations : registre des confirmations hors bande du client (EX-7.26) et formulaire d'ajout.
//
// Présentation (complément du 2026-11-17) : une carte par confirmation. Ce qui engage reste visible et exact,
// hors de tout bloc replié : la personne du client, le canal, l'instant exact, l'objet visé (clé de chaîne ou
// condensé), l'empreinte SHA-256 de la pièce en entier, l'exploitant qui l'a recueillie, le travail qui l'a
// consommée. L'état (disponible ou consommée) se lit par un mot et une icône.
//
// Langage (complément du 2026-11-18, décision du porteur sur le langage des écrans) : l'écran s'appelle
// « Confirmations du client » et dit ce qu'est une confirmation, à quoi elle sert et ce qu'on y note. Chaque
// valeur qui engage garde sa place, avec une demi-phrase qui dit pourquoi on la montre. La mention que CT-4 fixe
// mot pour mot (« confirmation hors bande absente », EX-7.26) reste celle du refus, sous sa phrase courante.
//
// Troisième lecture des écrans (même complément) : quand aucune confirmation n'est attendue pour ce client (le
// versement de l'inscription est fait, ou une confirmation prête à servir l'attend déjà ; aucun changement des
// approbateurs préparé n'en attend), l'écran le dit et le formulaire se range dans un bloc replié, « Noter une autre
// confirmation (rare) » : on ne note pas par mégarde une confirmation inutile, qui ne s'effacerait pas. L'adresse du
// compte et les empreintes d'une carte se copient d'un bouton.

import { notFound } from "next/navigation";
import { client, confirmations } from "../../../../lib/donnees.mjs";
import { exigerSession } from "../../../../lib/page.mjs";
import { OPERATIONS_CONFIRMATION, confirmationsAttendues, dateLisible, libelleCommande } from "../../../../lib/parcours.mjs";
import { CopierValeur } from "../../../../composants/CopierTexte.js";
import FormulaireConfirmation from "../../../../composants/FormulaireConfirmation.js";
import Icone from "../../../../composants/Icone.js";
import Lexique from "../../../../composants/Lexique.js";
import Pastille from "../../../../composants/Pastille.js";
import Valeur from "../../../../composants/Valeur.js";

export const dynamic = "force-dynamic";

export default async function PageConfirmations({ params }) {
  await exigerSession();
  const { slug } = await params;
  const c = client(slug);
  if (!c) notFound();
  const liste = confirmations(slug);
  const disponibles = liste.filter((x) => !x.consommee_par).length;
  const comptes = c.dossier.recorders.map((r) => ({ adresse: r.chain_key, nom: r.key_id }));
  const nomDe = (adresse) => comptes.find((x) => x.adresse === adresse)?.nom ?? null;
  const attendues = confirmationsAttendues({ dossier: c.dossier, confirmations: liste, demandes: c.demandes });
  const texteAjout = "Notez ce que le client a confirmé, qui l'a confirmé, par quel moyen et quand, puis désignez la pièce qui en garde la trace. L'outil vous fait relire le tout avant de noter. Une fois notée, la confirmation rejoint la liste ci-dessus et l'opération qu'elle autorise peut être lancée depuis la fiche du client.";
  const formulaire = <FormulaireConfirmation slug={slug} orgId={c.dossier.organisation.org_id} comptes={comptes} montant={c.dossier.funding?.amount_wei ?? null} />;
  return (
    <main className="nt-page">
      <a className="nt-fil" href={`/clients/${slug}`}><Icone nom="retour" />Fiche du client</a>
      <header className="nt-entete">
        <div className="nt-entete-texte">
          <p className="nt-sur-titre">Client <Valeur>{slug}</Valeur></p>
          <h1>Confirmations du client</h1>
          <p className="nt-sous-titre">Avant tout versement sur son compte technique, et avant tout changement de la liste de ses approbateurs, le client confirme l'opération par un autre moyen que cet outil : un appel, un courrier signé. Vous notez ici chaque confirmation ; sans elle, l'outil n'envoie rien. La liste garde tout : rien ne s'en efface.</p>
        </div>
        <div className="nt-entete-etat">
          <Pastille ton={disponibles > 0 ? "info" : ""} icone={disponibles > 0 ? "info" : "tiret"} grande>{disponibles === 0 ? "Aucune prête à servir" : `${disponibles} ${disponibles > 1 ? "prêtes à servir" : "prête à servir"}`}</Pastille>
        </div>
      </header>

      <section className="nt-pile" aria-labelledby="registre-titre">
        <h2 id="registre-titre">Confirmations déjà notées</h2>
        <p className="nt-attenue">Une confirmation « prête à servir » autorise une seule opération. Dès que l'opération est faite, elle devient « déjà utilisée » et ne peut plus servir.</p>
        {liste.length === 0 ? (
          <div className="nt-vide">
            <Icone nom="dossier" />
            <p className="nt-vide-titre">Aucune confirmation notée pour ce client.</p>
            <p className="nt-vide-texte">Tant qu'aucune confirmation n'est notée, l'outil ne verse rien sur le compte technique du client et n'envoie aucun changement de ses approbateurs. Notez-la avec le formulaire ci-dessous.</p>
          </div>
        ) : liste.map((x) => {
          const travail = x.consommee_par ? c.travaux.find((t) => t.id === x.consommee_par) ?? null : null;
          return (
            <article className="nt-carte" key={x.id} data-confirmation={x.id}>
              <div className="nt-carte-titre">
                <h3>{OPERATIONS_CONFIRMATION[x.operation] ?? x.operation}</h3>
                {x.consommee_par ? <Pastille icone="coche">Déjà utilisée</Pastille> : <Pastille ton="info" icone="info">Prête à servir</Pastille>}
              </div>
              <dl className="nt-definitions">
                <dt>Personne qui a confirmé</dt><dd><span data-valeur="">{x.personne_client}</span></dd>
                <dt>Moyen de la confirmation</dt><dd><span data-valeur="">{x.canal}</span></dd>
                <dt>Date de la confirmation</dt><dd><time dateTime={x.instant}>{dateLisible(x.instant)}</time><span className="nt-attenue nt-petit">valeur enregistrée : <Valeur>{x.instant}</Valeur></span></dd>
                {x.objet?.cle_chaine ? <div className="ins-contenu"><dt>Compte technique concerné</dt><dd>{nomDe(x.objet.cle_chaine) ? <span>celui de l'enregistreur <Valeur>{nomDe(x.objet.cle_chaine)}</Valeur></span> : null}<CopierValeur valeur={x.objet.cle_chaine} forme="adresse" libelle="Copier l'adresse" /></dd></div> : null}
                {x.objet?.digest ? <div className="ins-contenu"><dt>Empreinte du document concerné</dt><dd><CopierValeur valeur={x.objet.digest} forme="empreinte" libelle="Copier l'empreinte" /></dd></div> : null}
                <dt>Empreinte de la pièce</dt><dd><CopierValeur valeur={x.piece_sha256} forme="empreinte" libelle="Copier l'empreinte" data-piece="" /><span className="nt-attenue nt-petit">à comparer avec celle de la pièce rangée dans le dossier du client : identiques, c'est bien la même pièce. Pour la recalculer, choisissez la pièce avec « Choisir la pièce », dans le formulaire {attendues.length > 0 ? "plus bas" : "replié « Noter une autre confirmation (rare) », plus bas"}, sans rien noter : ce choix n'enregistre rien.</span></dd>
                <dt>Notée par</dt><dd><Valeur>{x.exploitant}</Valeur></dd>
                <dt>Notée le</dt><dd><time dateTime={x.recu_a}>{dateLisible(x.recu_a)}</time><span className="nt-attenue nt-petit">valeur enregistrée : <Valeur>{x.recu_a}</Valeur></span></dd>
                <dt>À quoi elle a servi</dt>
                <dd>
                  {x.consommee_par ? (
                    <>
                      <span>{x.operation === "administrer-jeu" ? "au changement des approbateurs envoyé" : "au versement fait"} {travail ? <>pendant l'action « {libelleCommande(travail.commande)} » du <time dateTime={travail.recu_a}>{dateLisible(travail.recu_a)}</time></> : "pendant une action dont l'outil n'a plus la trace"} ; elle ne peut plus servir</span>
                      <span className="nt-attenue nt-petit">identifiant de cette action : <Valeur>{x.consommee_par}</Valeur></span>
                    </>
                  ) : "à rien encore : elle autorise une opération, une seule"}
                </dd>
              </dl>
              <details className="ins-detail">
                <summary>Détail technique</summary>
                <dl className="nt-definitions ins-detail-corps">
                  <dt>Confirmation</dt><dd><span className="nt-fixe">{x.id}</span></dd>
                  <dt>Opération</dt><dd><span className="nt-fixe">{x.operation}</span></dd>
                  <dt>Identifiant du client sur le registre public</dt><dd><span className="nt-fixe">{x.objet?.org_id}</span></dd>
                  <dt>Algorithme de l'empreinte de la pièce</dt><dd><span className="nt-fixe">SHA-256</span></dd>
                </dl>
              </details>
            </article>
          );
        })}
      </section>

      {attendues.length > 0 ? (
        <section className="nt-carte" aria-labelledby="ajout-titre" data-confirmation-attendue={attendues.map((x) => x.operation).join(" ")}>
          <h2 id="ajout-titre">Noter une confirmation</h2>
          <p className="nt-attenue">{texteAjout}</p>
          {formulaire}
        </section>
      ) : (
        <section className="nt-pile" aria-labelledby="ajout-titre" data-aucune-attendue="">
          <h2 id="ajout-titre">Noter une confirmation</h2>
          <p className="nt-encart">Aucune confirmation n'est attendue pour ce client pour l'instant.</p>
          <details className="nt-detail" data-autre-confirmation="">
            <summary>Noter une autre confirmation (rare)<span className="nt-detail-note">seulement si le client a confirmé une autre opération</span></summary>
            <div className="nt-detail-corps nt-pile">
              <p className="nt-attenue">{texteAjout}</p>
              {formulaire}
            </div>
          </details>
        </section>
      )}
      <Lexique />
    </main>
  );
}
