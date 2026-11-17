// /clients : clients connus, slug, org_id, état de chaque étape (EX-7.16), dernier travail.
//
// Présentation (complément du 2026-11-17) : une carte par client : son nom, son état et son avancement en mots,
// la prochaine action à faire, la date de sa dernière action. L'identifiant de l'organisation et le code de l'état
// de chaque étape restent lisibles, tels quels, dans le détail replié de la carte.

import { client, clients, confirmations } from "../../lib/donnees.mjs";
import { exigerSession } from "../../lib/page.mjs";
import { avancement, dateLisible, etatTravail, libelleCommande, prochaineAction } from "../../lib/parcours.mjs";
import Icone from "../../composants/Icone.js";
import Pastille from "../../composants/Pastille.js";

export const dynamic = "force-dynamic";

export default async function PageClients() {
  await exigerSession();
  const liste = clients().map((resume) => {
    const c = client(resume.slug);
    return c ? { resume, c, a: avancement(c.dossier), action: prochaineAction({ ...c, confirmations: confirmations(resume.slug) }) } : null;
  }).filter(Boolean);
  return (
    <main className="nt-page">
      <header className="nt-entete">
        <div className="nt-entete-texte">
          <p className="nt-sur-titre">Inscription des clients</p>
          <h1>Clients</h1>
          <p className="nt-sous-titre">
            {liste.length === 0 ? "Aucun client pour l'instant." : `${liste.length} ${liste.length > 1 ? "clients" : "client"}. Chaque carte dit où en est l'inscription et ce qu'il reste à faire.`}
          </p>
        </div>
        <div className="nt-entete-etat">
          <a className="nt-bouton nt-bouton-principal" href="/clients/nouveau">Nouveau client</a>
        </div>
      </header>
      {liste.length === 0 ? (
        <div className="nt-vide">
          <Icone nom="dossier" />
          <p className="nt-vide-titre">Aucun client pour l'instant.</p>
          <p className="nt-vide-texte">L'inscription d'un client commence par la préparation de son dossier.</p>
          <a className="nt-bouton nt-bouton-principal" href="/clients/nouveau">Préparer un premier dossier</a>
        </div>
      ) : (
        <div className="ins-clients">
          {liste.map(({ resume, c, a, action }) => {
            const dernier = resume.dernier_travail ? c.travaux.find((t) => t.id === resume.dernier_travail.id) ?? null : null;
            const e = dernier ? etatTravail(dernier) : null;
            return (
              <article className="nt-carte" key={resume.slug} data-client={resume.slug}>
                <div className="ins-carte-tete">
                  <h2 className="ins-nom"><a href={`/clients/${resume.slug}`}>{resume.slug}</a></h2>
                  <div className="ins-pastilles">
                    <Pastille ton={a.ton} icone={a.icone}>{a.libelle}</Pastille>
                    <Pastille data-avancement>{a.phrase}</Pastille>
                  </div>
                  <progress className="nt-jauge" value={a.faites} max={a.total} aria-label={`${a.phrase} faites`} />
                </div>
                <div className="nt-encart ins-prochaine">
                  <p className="nt-sur-titre">Prochaine action</p>
                  <p className="ins-action" data-prochaine-action={action.code}>{action.titre}</p>
                </div>
                <p className="nt-attenue nt-petit">
                  {dernier ? (<>Dernière action : {libelleCommande(dernier.commande)} ({e.libelle.toLowerCase()}), le <time dateTime={dernier.recu_a}>{dateLisible(dernier.recu_a)}</time>.</>) : "Aucune action pour l'instant."}
                </p>
                <div className="nt-actions">
                  <a className="nt-bouton" href={`/clients/${resume.slug}`}>Ouvrir la fiche</a>
                </div>
                <details className="ins-detail">
                  <summary>Détail technique</summary>
                  <dl className="nt-definitions ins-detail-corps">
                    <dt>Identifiant de l'organisation</dt><dd><span className="nt-fixe">{resume.org_id}</span></dd>
                    {resume.steps.map((s, k) => (
                      <div className="ins-contenu" key={k}>
                        <dt><span className="nt-fixe">{s.step}</span></dt>
                        <dd><span className="nt-fixe">{s.state}</span><span className="nt-attenue nt-petit">objet {s.subject}</span></dd>
                      </div>
                    ))}
                  </dl>
                </details>
              </article>
            );
          })}
        </div>
      )}
    </main>
  );
}
