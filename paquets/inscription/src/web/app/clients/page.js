// /clients : clients connus, slug, org_id, état de chaque étape (EX-7.16), dernier travail.
//
// Présentation (complément du 2026-11-17) : une carte par client : son nom, son état et son avancement en mots,
// la prochaine action à faire, la date de sa dernière action. L'identifiant de l'organisation et le code de l'état
// de chaque étape restent lisibles, tels quels, dans le détail replié de la carte.
//
// Langage (complément du 2026-11-18, décision du porteur sur le langage des écrans) : c'est l'écran d'accueil de
// l'outil. Il dit à quoi il sert, explique le parcours une fois (« Comment ça marche », cinq lignes) et nomme les
// huit étapes avec les mots employés partout ailleurs. La dernière action d'un client ne se dit jamais « réussi »
// quand une de ses étapes est en échec.

import { client, clients, confirmations } from "../../lib/donnees.mjs";
import { exigerSession } from "../../lib/page.mjs";
import { ETAPES, ETAPE_PREPARATION, avancement, dateLisible, etatsTravaux, libelleCommande, prochaineAction } from "../../lib/parcours.mjs";
import Icone from "../../composants/Icone.js";
import Lexique from "../../composants/Lexique.js";
import Pastille from "../../composants/Pastille.js";
import Valeur from "../../composants/Valeur.js";

export const dynamic = "force-dynamic";

const PARCOURS = [ETAPE_PREPARATION, ...Object.values(ETAPES)];

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
            Cet écran montre où en est l'inscription de chaque client et ce qu'il vous reste à faire pour lui. Inscrire un client, c'est le faire exister, avec ses approbateurs et son enregistreur, sur le registre public : un registre que personne ne peut modifier après coup.
          </p>
        </div>
        <div className="nt-entete-etat">
          <a className="nt-bouton nt-bouton-principal" href="/clients/nouveau">Inscrire un nouveau client</a>
        </div>
      </header>
      <details className="nt-detail ins-replie" data-comment-ca-marche="">
        <summary>Comment ça marche<span className="nt-detail-note">l'inscription en cinq lignes</span></summary>
        <div className="nt-detail-corps nt-pile">
          <ol className="ins-lignes">
            <li>Vous préparez le dossier du client avec ce qu'il vous a transmis : son nom, ses journaux, ses approbateurs et son enregistreur (étape 1).</li>
            <li>Le client confirme par un autre moyen que cet outil ; l'outil enregistre alors ses approbateurs sur le registre public et alimente le compte technique de son enregistreur (étapes 2 à 5).</li>
            <li>Les approbateurs du client signent le document d'inscription de son enregistreur, et vous l'envoyez au registre public (étape 6).</li>
            <li>Chez le client, l'enregistreur dépose sa première preuve de date, puis les approbateurs closent la première période (étapes 7 et 8).</li>
            <li>Vous remettez au client son paquet : les fichiers avec lesquels il règle ses outils et contrôle lui-même son inscription.</li>
          </ol>
        </div>
      </details>
      <details className="nt-detail ins-replie" data-les-etapes="">
        <summary>Les huit étapes, une par une<span className="nt-detail-note">leur nom et ce qu'elles font</span></summary>
        <ol className="nt-detail-corps ins-lignes">
          {PARCOURS.map((e) => <li key={e.titre}><strong>{e.titre}.</strong> {e.phrase}</li>)}
        </ol>
      </details>
      <h2 className="nt-masque">Liste des clients</h2>
      {liste.length === 0 ? (
        <div className="nt-vide">
          <Icone nom="dossier" />
          <p className="nt-vide-titre">Aucun client pour l'instant.</p>
          <p className="nt-vide-texte">Pour inscrire votre premier client, commencez par préparer son dossier, avec les informations qu'il vous a transmises par écrit.</p>
          <a className="nt-bouton nt-bouton-principal" href="/clients/nouveau">Préparer le dossier d'un premier client</a>
        </div>
      ) : (
        <div className="ins-clients">
          {liste.map(({ resume, c, a, action }) => {
            const k = resume.dernier_travail ? c.travaux.findIndex((t) => t.id === resume.dernier_travail.id) : -1;
            const dernier = k >= 0 ? c.travaux[k] : null;
            const e = dernier ? etatsTravaux(c.travaux, c.dossier)[k] : null;
            return (
              <article className="nt-carte" key={resume.slug} data-client={resume.slug}>
                <div className="ins-carte-tete">
                  <h3 className="ins-nom"><a href={`/clients/${resume.slug}`} data-valeur="">{resume.slug}</a></h3>
                  <div className="ins-pastilles">
                    <Pastille ton={a.ton} icone={a.icone}>{a.libelle}</Pastille>
                    <Pastille data-avancement>{a.phrase}</Pastille>
                  </div>
                  <progress className="nt-jauge" value={a.faites} max={a.total} aria-label={a.phraseFaites} />
                </div>
                <div className="nt-encart ins-prochaine">
                  <p className="nt-sur-titre">{action.surTitre}</p>
                  <p className="ins-action" data-prochaine-action={action.code}>{action.titre}</p>
                </div>
                <p className="nt-attenue nt-petit" data-dates-client="">
                  <span className="ins-ligne">Dossier préparé le <time dateTime={c.dossier.prepared_at}>{dateLisible(c.dossier.prepared_at)}</time>.</span>
                  <span className="ins-ligne" data-derniere-action="">{dernier ? (<>Dernière action : {libelleCommande(dernier.commande)} ({e.libelle.toLowerCase()}), le <time dateTime={dernier.recu_a}>{dateLisible(dernier.recu_a)}</time>.</>) : "Vous n'avez encore rien lancé pour ce client."}</span>
                </p>
                <div className="nt-actions">
                  <a className="nt-bouton" href={`/clients/${resume.slug}`}>Ouvrir la fiche</a>
                </div>
                <details className="ins-detail">
                  <summary>Détail technique</summary>
                  <dl className="nt-definitions ins-detail-corps">
                    <dt>Identifiant du client sur le registre public</dt><dd><Valeur>{resume.org_id}</Valeur></dd>
                    {resume.steps.map((s, n) => (
                      <div className="ins-contenu" key={n}>
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
      <Lexique />
    </main>
  );
}
