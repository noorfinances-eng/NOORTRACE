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
//
// Quatrième lecture des écrans (même complément) : vérifier une pièce ne passe plus par le formulaire qui note ; un
// bouton à part, « Calculer l'empreinte d'une pièce — rien n'est enregistré », calcule l'empreinte dans la page et la
// compare aux pièces de la liste. Sur une carte, les dates se lisent en mots, la personne qui a noté par le nom de son
// compte (comme dans la barre), l'action qui a utilisé la confirmation par son nom et sa date. Ce qui engage ne se
// replie pas (INTERFACES.md 2.4) : l'instant exact de la confirmation, l'identité de session entière de qui l'a notée
// et l'identifiant de l'action qui l'a utilisée restent lisibles sans rien ouvrir, en petit, sous ces mots ; l'instant
// exact où elle a été notée est dans le détail technique de la carte.
//
// Cinquième lecture des écrans (même complément) : l'écran dit exactement ce qu'une confirmation autorise (EX-7.26) :
// un versement sur un compte technique, ou un changement des approbateurs d'un client dont la liste est déjà
// enregistrée ; une seule opération chacune. Pour l'inscription, c'est le versement de l'étape 5 ; les étapes 2 à 4
// n'en demandent pas, mais l'action qui fait les étapes 2 à 5 ne commence pas sans elle (le service d'inscription
// refuse de l'admettre). Les valeurs qui engagent, sur chaque carte, restent où elles sont.
//
// Sixième lecture (même complément) : la pastille du haut dit l'action attendue, d'après la même règle que le
// formulaire (`confirmationsAttendues`) : « Confirmation à noter » quand une confirmation est attendue ; sinon le
// nombre de celles qui sont prêtes à servir ; sinon « Rien à noter », sans ton d'alerte. Les mots viennent de la
// table unique de `parcours.mjs`.
//
// Décisions du porteur du 2026-11-25 (CT-4 EX-7.8, EX-7.26) : la fiche de contrôle des adresses des approbateurs,
// renvoyée confirmée par le client, se note ici comme une confirmation de plus (opération `jeu_approbateurs`, objet
// l'empreinte de la fiche, pièce la fiche renvoyée telle que reçue) ; elle est attendue avant celle du versement, dans
// l'ordre des étapes qu'elles débloquent. Une confirmation qui cite une autre version de la fiche que celle du
// dossier « ne vaut plus », et l'écran le dit. Sous le versement, la durée qu'il couvre (EX-7.9).

import { notFound } from "next/navigation";
import { client, confirmations } from "../../../../lib/donnees.mjs";
import { exigerSession } from "../../../../lib/page.mjs";
import { OPERATIONS_CONFIRMATION, PASTILLES, confirmationsAttendues, dateLisible, libelleCommande, pretesAServir } from "../../../../lib/parcours.mjs";
import { lignesFiche } from "../../../../../commun/fiche-controle.mjs";
import { CopierValeur } from "../../../../composants/CopierTexte.js";
import CalculerEmpreinte from "../../../../composants/CalculerEmpreinte.js";
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
  const disponibles = liste.filter((x) => !x.consommee_par && !x.perimee).length;
  const comptes = c.dossier.recorders.map((r) => ({ adresse: r.chain_key, nom: r.key_id }));
  const nomDe = (adresse) => comptes.find((x) => x.adresse === adresse)?.nom ?? null;
  const attendues = confirmationsAttendues({ dossier: c.dossier, confirmations: liste, demandes: c.demandes, fiche: c.fiche });
  const ficheEnClair = lignesFiche(c.dossier, c.fiche.noms).find((x) => x.cle === "approbations").valeur;
  const versionDe = (sha) => c.fiche.versions.find((x) => x.fiche_sha256 === sha) ?? null;
  const courante = c.fiche.versions.find((x) => x.courante) ?? null;
  const texteAjout = "Notez ce que le client a confirmé, qui l'a confirmé, par quel moyen et quand, puis désignez la pièce qui en garde la trace. L'outil vous fait relire le tout avant de noter. Une fois notée, la confirmation rejoint la liste ci-dessus et l'opération qu'elle autorise peut être lancée depuis la fiche du client.";
  /** Nom du compte d'une identité de session (`exploitant <nom>`), comme la barre l'affiche. */
  const nomDuCompte = (identite) => String(identite ?? "").replace(/^exploitant /, "");
  const pieces = liste.map((x) => ({ empreinte: x.piece_sha256, libelle: `« ${OPERATIONS_CONFIRMATION[x.operation] ?? x.operation} », notée le ${dateLisible(x.recu_a)}` }));
  const formulaire = <FormulaireConfirmation slug={slug} orgId={c.dossier.organisation.org_id} comptes={comptes} montant={c.dossier.funding?.amount_wei ?? null} parJour={c.dossier.funding?.daily_budget_gas ?? null} frais={c.frais} fiche={{ sha256: c.fiche.sha256, approbations: ficheEnClair, versions: c.fiche.versions }} />;
  return (
    <main className="nt-page">
      <a className="nt-fil" href={`/clients/${slug}`}><Icone nom="retour" />Fiche du client</a>
      <header className="nt-entete">
        <div className="nt-entete-texte">
          <p className="nt-sur-titre">Client <Valeur>{slug}</Valeur></p>
          <h1>Confirmations du client</h1>
          <p className="nt-sous-titre">Le client confirme par un autre moyen que cet outil (un appel, un courrier signé) la liste des adresses de ses approbateurs avant qu'elle parte vers le registre public (il renvoie la fiche de contrôle confirmée), chaque versement sur son compte technique et, une fois ses approbateurs enregistrés, chaque changement de leur liste. Vous notez ici chaque confirmation ; sans elle, l'outil n'envoie pas l'opération. La liste garde tout : rien ne s'en efface.</p>
        </div>
        <div className="nt-entete-etat">
          {(() => {
            const cle = attendues.length > 0 ? "confirmation_a_noter" : disponibles > 0 ? "confirmation_prete" : "confirmation_rien_a_noter";
            const p = PASTILLES[cle];
            return <Pastille ton={p.ton} icone={p.icone} grande data-etat-confirmations={cle}>{cle === "confirmation_prete" ? pretesAServir(disponibles) : p.libelle}</Pastille>;
          })()}
        </div>
      </header>

      <section className="nt-pile" aria-labelledby="registre-titre">
        <h2 id="registre-titre">Confirmations déjà notées</h2>
        <p className="nt-attenue" data-une-operation="">Une confirmation « prête à servir » autorise une seule opération : l'enregistrement des approbateurs dont la fiche de contrôle a été renvoyée, un versement, ou un changement des approbateurs. Dès que l'opération est faite, elle devient « déjà utilisée » et ne peut plus servir. Pour l'inscription, il en faut deux : celle de la fiche de contrôle des adresses des approbateurs (étape 2) et celle du versement (étape 5). Les étapes 3 et 4 n'en demandent pas, mais l'outil fait les étapes 2 à 5 en une seule action, qu'il ne commence pas sans ces deux confirmations.</p>
        {liste.length > 0 ? <CalculerEmpreinte pieces={pieces} /> : null}
        {liste.length === 0 ? (
          <div className="nt-vide">
            <Icone nom="dossier" />
            <p className="nt-vide-titre">Aucune confirmation notée pour ce client.</p>
            <p className="nt-vide-texte">Tant qu'aucune confirmation n'est notée, l'outil n'enregistre pas les approbateurs du client sur le registre public, ne verse rien sur son compte technique et n'envoie aucun changement de ses approbateurs. Notez-les avec le formulaire ci-dessous.</p>
          </div>
        ) : liste.map((x) => {
          const travail = x.consommee_par ? c.travaux.find((t) => t.id === x.consommee_par) ?? null : null;
          return (
            <article className="nt-carte" key={x.id} data-confirmation={x.id} data-perimee={x.perimee ? "" : undefined}>
              <div className="nt-carte-titre">
                <h3>{OPERATIONS_CONFIRMATION[x.operation] ?? x.operation}</h3>
                {(() => { const p = PASTILLES[x.consommee_par ? "confirmation_utilisee" : x.perimee ? "confirmation_perimee" : "confirmation_prete"]; return <Pastille ton={p.ton} icone={p.icone}>{p.libelle}</Pastille>; })()}
              </div>
              {x.perimee ? (
                <div className="nt-bandeau nt-bandeau-avertissement" role="status">
                  <Icone nom="alerte" />
                  <div className="nt-bandeau-texte"><p data-phrase-perimee="">{PASTILLES.confirmation_perimee.sens} Fiche changée depuis : cette confirmation cite {versionDe(x.objet.fiche_sha256)?.version ? `la version ${versionDe(x.objet.fiche_sha256).version}` : "une version d'avant"}{courante?.version ? `, et la fiche actuelle est la version ${courante.version}` : ""}. Remettez au client la fiche actuelle, sur <a href={`/clients/${slug}/fiche-controle`}>sa page</a>, et notez sa nouvelle confirmation.</p></div>
                </div>
              ) : null}
              <dl className="nt-definitions">
                <dt>Personne qui a confirmé</dt><dd><span data-valeur="">{x.personne_client}</span></dd>
                <dt>Moyen de la confirmation</dt><dd><span data-valeur="">{x.canal}</span></dd>
                <dt>Date de la confirmation</dt><dd><time dateTime={x.instant}>{dateLisible(x.instant)}</time><span className="nt-attenue nt-petit">valeur enregistrée : <Valeur>{x.instant}</Valeur></span></dd>
                {x.objet?.cle_chaine ? <div className="ins-contenu"><dt>Compte technique concerné</dt><dd>{nomDe(x.objet.cle_chaine) ? <span>celui de l'enregistreur <Valeur>{nomDe(x.objet.cle_chaine)}</Valeur></span> : null}<CopierValeur valeur={x.objet.cle_chaine} forme="adresse" libelle="Copier l'adresse" /></dd></div> : null}
                {x.objet?.digest ? <div className="ins-contenu"><dt>Empreinte du document concerné</dt><dd><CopierValeur valeur={x.objet.digest} forme="empreinte" libelle="Copier l'empreinte" /></dd></div> : null}
                {x.objet?.fiche_sha256 ? <div className="ins-contenu"><dt>Fiche de contrôle concernée</dt><dd><span>{x.objet.fiche_sha256 === c.fiche.sha256 ? `la fiche actuelle du dossier${courante?.version ? ` (version ${courante.version})` : ""}` : `une version d'avant de la fiche${versionDe(x.objet.fiche_sha256)?.version ? ` (version ${versionDe(x.objet.fiche_sha256).version})` : ""}, qui n'est plus celle du dossier`} ; son empreinte :</span><CopierValeur valeur={x.objet.fiche_sha256} forme="empreinte" libelle="Copier l'empreinte" data-fiche-concernee="" /></dd></div> : null}
                <dt>Empreinte de la pièce</dt><dd><CopierValeur valeur={x.piece_sha256} forme="empreinte" libelle="Copier l'empreinte" data-piece="" /><span className="nt-attenue nt-petit">à comparer avec celle de la pièce rangée dans le dossier du client : identiques, c'est bien la même pièce. Pour la calculer sur le fichier de la pièce, servez-vous du bouton « Calculer l'empreinte d'une pièce — rien n'est enregistré », plus haut.</span></dd>
                <dt>Notée par</dt><dd><Valeur>{nomDuCompte(x.exploitant)}</Valeur><span className="nt-attenue nt-petit">identité enregistrée : <Valeur>{x.exploitant}</Valeur></span></dd>
                <dt>Notée le</dt><dd><time dateTime={x.recu_a}>{dateLisible(x.recu_a)}</time></dd>
                <dt>À quoi elle a servi</dt>
                <dd>
                  {x.consommee_par ? (
                    <>
                      <span>{x.operation === "administrer-jeu" ? "au changement des approbateurs envoyé" : x.operation === "jeu_approbateurs" ? "à l'enregistrement des approbateurs sur le registre public" : "au versement fait"} {travail ? <>pendant l'action « {libelleCommande(travail.commande)} » du <time dateTime={travail.recu_a}>{dateLisible(travail.recu_a)}</time></> : "pendant une action dont l'outil n'a plus la trace"} ; elle ne peut plus servir</span>
                      <span className="nt-attenue nt-petit">identifiant de cette action : <Valeur>{x.consommee_par}</Valeur></span>
                    </>
                  ) : x.perimee ? "à rien : elle ne vaut plus et n'autorise plus rien" : "à rien encore : elle autorise une opération, une seule"}
                </dd>
              </dl>
              <details className="ins-detail">
                <summary>Détail technique</summary>
                <dl className="nt-definitions ins-detail-corps">
                  <dt>Confirmation</dt><dd><span className="nt-fixe">{x.id}</span></dd>
                  <dt>Opération</dt><dd><span className="nt-fixe">{x.operation}</span></dd>
                  <dt>Notée le, tel qu'enregistré</dt><dd><span className="nt-fixe">{x.recu_a}</span></dd>
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
          <details className="nt-detail ins-replie" data-autre-confirmation="">
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
