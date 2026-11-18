// /clients/<slug>/paquet : production du paquet client (CT-4 §7.13), son contrôle (EX-7.22), et le gabarit du service
// d'approbation (console_origin et administrators, donnés par écrit par le client, ou null : EX-7.20).
//
// Présentation (complément du 2026-11-17) : l'état du paquet se lit d'abord (produit ou non) ; ce qui engage reste
// visible et exact, hors de tout bloc replié : l'empreinte SHA-256 du manifeste du paquet, en entier, le nombre de
// fichiers, l'instant de production. La sortie du travail reste lisible telle quelle dans un bloc replié.
//
// Langage (complément du 2026-11-18, décision du porteur sur le langage des écrans) : l'écran dit ce qu'est le
// paquet, ce qu'il contient (EX-7.18), à qui on le remet et comment le client contrôle qu'il a reçu le bon :
// l'empreinte affichée est celle du fichier `paquet-client.json`, qui liste tous les autres avec leur empreinte
// (EX-7.19). Un paquet déjà produit ne se refait que sur une raison dite ; son formulaire est alors replié.

import { notFound } from "next/navigation";
import { client } from "../../../../lib/donnees.mjs";
import { exigerSession } from "../../../../lib/page.mjs";
import { avancement, dateLisible, etatTravail, explicationErreur } from "../../../../lib/parcours.mjs";
import FormulaireTravail from "../../../../composants/FormulaireTravail.js";
import Icone from "../../../../composants/Icone.js";
import Lexique from "../../../../composants/Lexique.js";
import Pastille from "../../../../composants/Pastille.js";
import TelechargerPaquet from "../../../../composants/TelechargerPaquet.js";
import Valeur from "../../../../composants/Valeur.js";

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
  const x = refuse ? explicationErreur(code) : null;
  // Exemples fictifs au nom du client de la page, sous le domaine réservé « .example ».
  const console_ = `console.${slug}.example`;
  const annuaire = `idp.${slug}.example`;
  const formulaire = (
    <FormulaireTravail
      commande="paquet"
      slug={slug}
      sections={[
        { titre: "Qui produit le paquet", champs: [{ nom: "prepared_by", libelle: "Nom de celui qui produit le paquet", type: "texte", exemple: "Société Exemple, service des inscriptions", aide: "Le nom de notre société, tel que le client le connaît. Il sera écrit dans le paquet." }] },
        {
          titre: "Ce que le client vous a donné par écrit",
          texte: "Ces deux informations engagent le client : ne les saisissez que s'il vous les a données par écrit, et recopiez-les telles quelles. Sinon laissez vide : le client les remplira lui-même.",
          champs: [
            { nom: "console_origin", libelle: "Adresse de la console d'approbation du client", type: "origine", facultatif: true, nullSiVide: true, exemple: `https://${console_}`, aide: "L'adresse du site où les approbateurs du client donnent leur accord. Elle commence par « https:// » et s'arrête au nom du site, sans rien après." },
            { nom: "administrators", libelle: "Administrateurs de l'annuaire du client", type: "liste_identites", facultatif: true, nullSiVide: true, exemple: `oidc https://${annuaire} admin-1`, aide: "Les personnes du client qui tiennent la liste de ses approbateurs dans sa console. Une ligne par personne, recopiée exactement comme le client l'a écrite." },
          ],
        },
      ]}
      note="Après le clic : l'outil réunit les fichiers, puis contrôle le paquet comme le client le fera en le recevant. Rien n'est envoyé au registre public, rien n'est dépensé."
      bouton={produit ? "Produire le paquet de nouveau" : "Produire le paquet"}
      principal={!produit}
    />
  );
  return (
    <main className="nt-page">
      <a className="nt-fil" href={`/clients/${slug}`}><Icone nom="retour" />Fiche du client</a>
      <header className="nt-entete">
        <div className="nt-entete-texte">
          <p className="nt-sur-titre">Client <Valeur>{slug}</Valeur></p>
          <h1>Paquet du client</h1>
          <p className="nt-sous-titre">Le paquet est l'ensemble des fichiers que nous remettons au client à la fin de l'inscription. Avec lui, le client règle son service d'approbation et son enregistreur, et contrôle lui-même que son inscription est exacte. Il ne contient aucun secret.</p>
        </div>
        <div className="nt-entete-etat">
          {produit ? <Pastille ton="succes" icone="coche" grande>Produit</Pastille> : <Pastille icone="tiret" grande>Pas encore produit</Pastille>}
        </div>
      </header>

      {refuse ? (
        <div className="nt-bandeau nt-bandeau-erreur" role="alert">
          <Icone nom="alerte" />
          <div className="nt-bandeau-texte">
            <p className="nt-bandeau-titre">La dernière production du paquet n'a pas abouti ({e.libelle.toLowerCase()}).</p>
            <p>{x.phrase} {x.effet}</p>
            <p><strong>Que faire :</strong> {x.quoiFaire}</p>
          </div>
        </div>
      ) : null}

      {produit ? (
        <section className="nt-essentiel" aria-labelledby="paquet-titre">
          <p className="nt-sur-titre">Paquet à remettre</p>
          <h2 className="nt-essentiel-phrase" id="paquet-titre">Le paquet est prêt : téléchargez-le, remettez-le au client, et donnez-lui son empreinte.</h2>
          <dl className="nt-faits">
            {o.manifest_sha256 ? (
              <div className="nt-fait ins-fait-large">
                <dt>Empreinte du paquet</dt>
                <dd>
                  <Valeur data-manifeste-paquet>{o.manifest_sha256}</Valeur>
                  <span className="ins-ligne nt-petit nt-attenue">À donner au client par un autre moyen que le paquet lui-même, et par écrit : 66 caractères ne se dictent pas sans erreur. C'est l'empreinte du fichier <Valeur>paquet-client.json</Valeur>, qui liste tous les autres fichiers du paquet : si le client retrouve la même sur le fichier qu'il a reçu, il a le bon paquet.</span>
                </dd>
              </div>
            ) : null}
            {o.files !== undefined ? <div className="nt-fait"><dt>Fichiers</dt><dd>{o.files}</dd></div> : null}
            {dernier ? <div className="nt-fait"><dt>Produit le</dt><dd><time dateTime={dernier.recu_a}>{dateLisible(dernier.recu_a)}</time></dd></div> : null}
          </dl>
          <dl className="nt-definitions ins-paquet-en-clair" data-paquet-en-clair="">
            <dt>Ce qu'il contient</dt>
            <dd>Le dossier d'inscription terminé ; la liste des approbateurs du client, qu'il recopie dans ses réglages ; un modèle de réglages pour son service d'approbation ; la preuve de chaque opération inscrite sur le registre public ; et la liste de tous ces fichiers, avec l'empreinte de chacun.</dd>
            <dt>Ce qu'il ne contient pas</dt>
            <dd data-sans-secret={o.secrets_checked ? o.secrets_checked.count : undefined}>
              <span>
                Aucune clé secrète et aucun mot de passe : ni les nôtres, ni ceux du client.
                {o.secrets_checked ? (o.secrets_checked.count > 0
                  ? ` Avant de vous le proposer, l'outil a cherché dans chaque fichier ${o.secrets_checked.count > 1 ? `les ${o.secrets_checked.count} clés secrètes de notre société qui ont servi` : "la clé secrète de notre société qui a servi"} à cette inscription : il n'en a trouvé aucune.`
                  : " L'outil n'a eu aucune clé secrète de notre société à y chercher : aucune n'a servi à cette inscription depuis cet outil.") : ""}
              </span>
            </dd>
            <dt>À qui le remettre</dt>
            <dd>Au client, et à lui seul : le paquet n'a rien de secret pour lui, mais il porte aussi la trace d'opérations d'autres clients inscrites au même moment sur le registre public. Remettez-le par le moyen convenu avec lui ; si vous ne le connaissez pas, demandez-le à l'équipe technique.</dd>
            <dt>Ce que le client vérifie</dt>
            <dd>Que l'empreinte ci-dessus est bien celle du paquet reçu, puis que les adresses du paquet (ses approbateurs, leur responsable, son enregistreur et son compte technique) sont bien les siennes. S'il relève un écart, il vous le signale, et rien ne doit être signé tant que l'écart n'est pas éclairci.</dd>
          </dl>
          <TelechargerPaquet slug={slug} />
          <p className="nt-attenue nt-petit">Le fichier téléchargé est une archive « .tar », que le client sait ouvrir. Le paquet est contrôlé de nouveau à chaque téléchargement.</p>
        </section>
      ) : (
        <div className="nt-vide">
          <Icone nom="boite" />
          <p className="nt-vide-titre">Aucun paquet produit pour l'instant.</p>
          <p className="nt-vide-texte">
            {a.etat === "inscrit" ? "Toutes les étapes de l'inscription sont faites : vous pouvez produire le paquet avec le formulaire ci-dessous." : `Le paquet ne se produit que lorsque toutes les étapes de l'inscription sont faites ; pour l'instant, ${a.phraseFaites}. Revenez à la fiche du client pour continuer.`}
          </p>
          {a.etat === "inscrit" ? null : <a className="nt-bouton" href={`/clients/${slug}`}>Revenir à la fiche du client</a>}
        </div>
      )}

      {produit ? (
        <details className="nt-detail" data-produire-de-nouveau="">
          <summary>Produire le paquet de nouveau<span className="nt-detail-note">seulement si le client vous a donné de nouvelles informations</span></summary>
          <div className="nt-detail-corps nt-pile">
            <p>Le paquet est déjà produit : vous n'avez pas à le refaire. Refaites-le seulement si le client vous a donné par écrit l'adresse de sa console ou ses administrateurs après coup, ou si un contrôle a refusé le paquet. Le nouveau paquet aura une nouvelle empreinte, à redonner au client.</p>
            {formulaire}
          </div>
        </details>
      ) : (
        <section className="nt-carte" aria-labelledby="produire-titre">
          <h2 id="produire-titre">Produire le paquet</h2>
          <p className="nt-attenue">L'outil réunit le dossier terminé, la liste des approbateurs et le modèle de réglages, puis contrôle le paquet comme le client le fera à la réception.</p>
          {formulaire}
        </section>
      )}

      {dernier ? (
        <details className="nt-detail" data-derniere-production="">
          <summary>Détail technique de la dernière production<span className="nt-detail-note">réponse exacte du service d'inscription</span></summary>
          <div className="nt-detail-corps">
            <dl className="nt-definitions">
              <dt>Travail</dt><dd><span className="nt-fixe">{dernier.id}</span></dd>
              <dt>État</dt><dd><span className="nt-fixe">{dernier.etat}</span></dd>
              <dt>Reçu</dt><dd><span className="nt-fixe">{dernier.recu_a}</span></dd>
              <dt>Algorithme de l'empreinte du paquet</dt><dd><span className="nt-fixe">SHA-256</span></dd>
            </dl>
            <pre className="nt-pre">{JSON.stringify(sortie ?? dernier.motif ?? null, null, 2)}</pre>
          </div>
        </details>
      ) : null}
      <Lexique />
    </main>
  );
}
