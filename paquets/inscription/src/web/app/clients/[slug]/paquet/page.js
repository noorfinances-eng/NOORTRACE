// /clients/<slug>/paquet : production du paquet client (CT-4 §7.13), son contrôle (EX-7.22), et le gabarit du service
// d'approbation (console_origin et administrators, donnés par écrit par le client, ou null : EX-7.20).
//
// Présentation (complément du 2026-11-17) : l'état du paquet se lit d'abord (produit ou non) ; ce qui engage reste
// visible et exact, hors de tout bloc replié : l'empreinte SHA-256 du manifeste du paquet, en entier, le nombre de
// fichiers, l'instant de production. La sortie du travail reste lisible telle quelle dans un bloc replié.

import { notFound } from "next/navigation";
import { client } from "../../../../lib/donnees.mjs";
import { exigerSession } from "../../../../lib/page.mjs";
import { avancement, dateLisible, etatTravail, explicationErreur } from "../../../../lib/parcours.mjs";
import FormulaireTravail from "../../../../composants/FormulaireTravail.js";
import Icone from "../../../../composants/Icone.js";
import Pastille from "../../../../composants/Pastille.js";

export const dynamic = "force-dynamic";

export default async function PagePaquet({ params }) {
  await exigerSession();
  const { slug } = await params;
  const c = client(slug);
  if (!c) notFound();
  const dernier = c.travaux.find((t) => t.commande === "paquet") ?? null;
  const e = dernier ? etatTravail(dernier) : null;
  const sortie = dernier?.sortie ?? null;
  const produit = c.paquet.present;
  const a = avancement(c.dossier);
  const refuse = dernier && e.termine && e.ton !== "succes";
  const code = dernier?.motif?.code ?? sortie?.error?.code ?? "";
  const o = sortie?.result === "reussi" ? sortie.outputs ?? {} : {};
  return (
    <main className="nt-page">
      <a className="nt-fil" href={`/clients/${slug}`}><Icone nom="retour" />Fiche du client</a>
      <header className="nt-entete">
        <div className="nt-entete-texte">
          <p className="nt-sur-titre">Client <span className="nt-fixe">{slug}</span></p>
          <h1>Paquet client</h1>
          <p className="nt-sous-titre">Ce que le client reçoit pour configurer son service d'approbation et son enregistreur, et pour contrôler son inscription. Le paquet ne contient aucune clé.</p>
        </div>
        <div className="nt-entete-etat">
          {produit ? <Pastille ton="succes" icone="coche" grande>Produit</Pastille> : <Pastille icone="tiret" grande>Pas encore produit</Pastille>}
        </div>
      </header>

      {refuse ? (
        <div className="nt-bandeau nt-bandeau-erreur" role="alert">
          <Icone nom="alerte" />
          <div className="nt-bandeau-texte">
            <p className="nt-bandeau-titre">La dernière production n'a pas abouti ({e.libelle.toLowerCase()}).</p>
            <p>{explicationErreur(code).phrase} {explicationErreur(code).quoiFaire}</p>
          </div>
        </div>
      ) : null}

      {produit ? (
        <section className="nt-essentiel" aria-labelledby="paquet-titre">
          <p className="nt-sur-titre">Paquet à remettre</p>
          <h2 className="nt-essentiel-phrase" id="paquet-titre">Le paquet de {slug} est prêt à être remis au client.</h2>
          <dl className="nt-faits">
            {o.manifest_sha256 ? (
              <div className="nt-fait ins-fait-large">
                <dt>Empreinte SHA-256 du manifeste du paquet</dt>
                <dd><span className="nt-fixe" data-manifeste-paquet>{o.manifest_sha256}</span></dd>
              </div>
            ) : null}
            {o.files !== undefined ? <div className="nt-fait"><dt>Fichiers</dt><dd>{o.files}</dd></div> : null}
            {dernier ? <div className="nt-fait"><dt>Dernière production</dt><dd><time dateTime={dernier.recu_a}>{dateLisible(dernier.recu_a)}</time></dd></div> : null}
            {o.secrets_checked ? <div className="nt-fait"><dt>Secrets recherchés dans le paquet</dt><dd>{o.secrets_checked.count} {o.secrets_checked.count > 1 ? "références contrôlées" : "référence contrôlée"}, aucun secret trouvé</dd></div> : null}
          </dl>
          <div className="nt-actions">
            <a className="nt-bouton nt-bouton-principal" href={`/api/clients/${slug}/paquet`}>Télécharger l'archive du paquet</a>
          </div>
          <p className="nt-attenue nt-petit">Archive au format tar. Le paquet est contrôlé de nouveau à chaque téléchargement.</p>
        </section>
      ) : (
        <div className="nt-vide">
          <Icone nom="boite" />
          <p className="nt-vide-titre">Aucun paquet produit pour l'instant.</p>
          <p className="nt-vide-texte">
            {a.etat === "inscrit" ? "Toutes les étapes de l'inscription sont faites : le paquet peut être produit ci-dessous." : `Le paquet se produit quand toutes les étapes de l'inscription sont faites (${a.phrase} pour l'instant).`}
          </p>
        </div>
      )}

      <section className="nt-carte" aria-labelledby="produire-titre">
        <h2 id="produire-titre">{produit ? "Produire le paquet de nouveau" : "Produire le paquet"}</h2>
        <p className="nt-attenue">L'outil réunit le dossier fini, l'extrait du jeu d'approbateurs et le gabarit du service d'approbation, puis contrôle le paquet comme le client le fera à la réception.</p>
        <FormulaireTravail
          commande="paquet"
          slug={slug}
          sections={[
            { titre: "Qui produit le paquet", champs: [{ nom: "prepared_by", libelle: "Producteur du paquet", type: "texte", exemple: "Exploitant du registre", aide: "Le nom qui figurera dans le paquet comme son producteur." }] },
            {
              titre: "Le service d'approbation du client",
              texte: "Ces deux valeurs engagent le client : ne les saisissez que s'il vous les a données par écrit. Sinon laissez vide ; le client les remplira lui-même.",
              champs: [
                { nom: "console_origin", libelle: "Adresse de la console du client", type: "origine", facultatif: true, nullSiVide: true, exemple: "https://console.assureur-demo.example", aide: "L'origine HTTPS de sa console d'approbation, sans chemin." },
                { nom: "administrators", libelle: "Administrateurs de l'annuaire du client", type: "liste_identites", facultatif: true, nullSiVide: true, exemple: "oidc https://idp.assureur-demo.example admin-1", aide: "Une identité de session par ligne, telle que le client l'a écrite." },
              ],
            },
          ]}
          bouton="Produire et contrôler le paquet"
          principal={!produit}
        />
      </section>

      {dernier ? (
        <details className="nt-detail">
          <summary>Dernier travail de production<span className="nt-detail-note">sortie telle que l'agent l'a rendue</span></summary>
          <div className="nt-detail-corps">
            <dl className="nt-definitions">
              <dt>Travail</dt><dd><span className="nt-fixe">{dernier.id}</span></dd>
              <dt>État</dt><dd><span className="nt-fixe">{dernier.etat}</span></dd>
              <dt>Reçu</dt><dd><span className="nt-fixe">{dernier.recu_a}</span></dd>
            </dl>
            <pre className="nt-pre">{JSON.stringify(sortie ?? dernier.motif ?? null, null, 2)}</pre>
          </div>
        </details>
      ) : null}
    </main>
  );
}
