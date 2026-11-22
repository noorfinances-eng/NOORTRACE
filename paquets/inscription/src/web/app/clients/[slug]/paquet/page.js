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
// Troisième lecture (même complément) : l'empreinte, qui se transmet au client par écrit, se copie d'un bouton.
// Quatrième lecture (même complément) : les quatre lignes disent ce que le paquet contient vraiment (EX-7.18 : la
// description du registre seulement quand le dossier en nomme une), qu'aucun de ses fichiers n'est fait pour porter
// un secret (EX-7.21) et que l'outil y a cherché ceux dont il s'est servi (`secrets_checked`), et pourquoi il porte
// aussi la trace d'opérations d'autres clients (EX-7.21, EX-9.5 : les reçus de tout le bloc, sans lesquels la preuve
// d'une opération ne se contrôle pas, CP-3). Rien de plus n'est affirmé.
// Cinquième lecture (même complément) : la recherche de secrets se dit sans contredire « aucune clé secrète n'est
// demandée dans cet outil » : ce que l'outil a cherché, ce sont les clés secrètes et le jeton d'accès dont le service
// d'inscription s'est servi pour ce client (EX-7.21 : chaque référence de clé employée par ses travaux, et le jeton
// `--jeton` ; `secrets_checked` les compte par option, jamais par valeur) ; il les garde lui-même, personne ne les
// saisit ici. Ce que le paquet porte des autres clients se dit exactement : les opérations inscrites dans les mêmes
// lots que les siennes, telles que le registre public les a inscrites (EX-9.5 : reçus et transactions brutes de tout
// le bloc) ; on y lit leur identifiant sur le registre (un code, `org_id = keccak256(slug)`, qui pour un client du
// registre réel ne permet pas de le reconnaître, EX-6.2), des adresses, des empreintes, des montants de crédits, et
// le texte libre qu'un client joint à une clôture de période (`uri`, CT-4 5.7) ; rien de ce qu'ils nous ont transmis
// hors du registre (le paquet ne prend que le dossier de ce client et les captures de ses étapes).
//
// Remise du paquet (complément du 2026-11-19, décision du porteur sur le suivi interne des clients ; CT-4 EX-7.23) :
// sous le téléchargement, « J'ai remis le paquet au client » note la remise du paquet affiché (son empreinte), avec
// la date, l'heure et la personne connectée ; c'est une déclaration de cette personne, rien de plus. Une remise
// notée se lit « Paquet remis le … par … » ; elle ne s'efface pas : « Corriger cette note » ajoute une correction,
// avec son motif, et la remise reste lisible, barrée d'un « corrigée ». Le titre porte le nom interne du client.

import { notFound } from "next/navigation";
import { client, notes } from "../../../../lib/donnees.mjs";
import { remiseEnVigueur } from "../../../../../commun/notes.mjs";
import { exigerSession } from "../../../../lib/page.mjs";
import { avancement, dateLisible, etatTravail, explicationErreur, manifesteDuPaquet, nomDuCompte, phraseRemise } from "../../../../lib/parcours.mjs";
import { RemisePaquet } from "../../../../composants/NoteInterne.js";
import FormulaireTravail from "../../../../composants/FormulaireTravail.js";
import Icone from "../../../../composants/Icone.js";
import Lexique from "../../../../composants/Lexique.js";
import Pastille from "../../../../composants/Pastille.js";
import TelechargerPaquet from "../../../../composants/TelechargerPaquet.js";
import { CopierValeur } from "../../../../composants/CopierTexte.js";
import CreditsEnClair from "../../../../composants/CreditsEnClair.js";
import Valeur from "../../../../composants/Valeur.js";

export const dynamic = "force-dynamic";

/**
 * Ce que l'outil a cherché dans le paquet (EX-7.21), dit sans contredire « aucune clé secrète n'est demandée dans cet
 * outil » : les clés secrètes et le jeton d'accès dont le service d'inscription s'est servi pour ce client, qu'il
 * garde lui-même. `secrets_checked` : `{ count, references: [{ option, reference }] }` ; l'option `--jeton` est le
 * jeton d'accès au registre public, toute autre option une clé (EX-7.3, EX-7.30). Jamais une valeur.
 */
function phraseSecrets(sc) {
  const refs = Array.isArray(sc.references) ? sc.references : [];
  const jetons = refs.filter((r) => r.option === "--jeton").length;
  const cles = refs.length > 0 ? refs.length - jetons : sc.count;
  if (sc.count === 0) return "Pour cette inscription, le service d'inscription ne s'est servi d'aucune clé secrète ni d'aucun jeton d'accès : il n'avait rien à y chercher.";
  const parties = [cles > 0 ? (cles > 1 ? `${cles} clés secrètes` : "1 clé secrète") : null, jetons > 0 ? "son jeton d'accès au registre public" : null].filter(Boolean).join(" et de ");
  const pluriel = sc.count > 1;
  const pronom = pluriel ? "les" : cles > 0 ? "la" : "le";
  return `Pour cette inscription, le service d'inscription s'est servi de ${parties}, qu'il garde lui-même pour accéder au registre public ; personne ne ${pronom} saisit dans cet outil. Avant de vous proposer le paquet, l'outil a vérifié qu'aucun de ses fichiers n'en contient : il n'en a trouvé aucun${cles > 0 && jetons === 0 ? "e" : ""}.`;
}

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
  const suivi = notes(slug);
  const nom = suivi.nom?.valeur ?? null;
  const manifeste = manifesteDuPaquet(c);
  const remise = remiseEnVigueur(suivi, manifeste);
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
          <p className="nt-sur-titre">Client <Valeur>{nom ?? slug}</Valeur>{nom ? <span className="nt-attenue"> · nom court <Valeur>{slug}</Valeur></span> : null}</p>
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
                  <CopierValeur valeur={o.manifest_sha256} forme="empreinte" libelle="Copier l'empreinte" data-manifeste-paquet />
                  <span className="ins-ligne nt-petit nt-attenue">À donner au client par un autre moyen que le paquet lui-même, et par écrit : 66 caractères ne se dictent pas sans erreur. C'est l'empreinte du fichier <Valeur>paquet-client.json</Valeur>, qui liste tous les autres fichiers du paquet : si le client retrouve la même sur le fichier qu'il a reçu, il a le bon paquet.</span>
                </dd>
              </div>
            ) : null}
            {o.files !== undefined ? <div className="nt-fait"><dt>Fichiers</dt><dd>{o.files}</dd></div> : null}
            {dernier ? <div className="nt-fait"><dt>Produit le</dt><dd><time dateTime={dernier.recu_a}>{dateLisible(dernier.recu_a)}</time></dd></div> : null}
          </dl>
          <dl className="nt-definitions ins-paquet-en-clair" data-paquet-en-clair="">
            <dt>Ce qu'il contient</dt>
            <dd>Le dossier d'inscription terminé ; la liste des approbateurs du client, qu'il recopie dans ses réglages ; un modèle de réglages pour son service d'approbation ;{c.dossier.instance?.manifest_sha256 ? " la description du registre public en vigueur ;" : ""} la preuve de chaque opération de son inscription, telle que le registre public l'a donnée ; et la liste de tous ces fichiers, avec l'empreinte de chacun.</dd>
            <dt>Ce qu'il ne contient pas</dt>
            <dd data-sans-secret={o.secrets_checked ? o.secrets_checked.count : undefined}>
              <span>
                Aucune clé secrète, aucun jeton d'accès et aucun mot de passe : aucun de ses fichiers n'est fait pour en porter.
                {o.secrets_checked ? ` ${phraseSecrets(o.secrets_checked)}` : ""}
              </span>
            </dd>
            <dt>À qui le remettre</dt>
            <dd data-a-qui="">Au client seulement : c'est son paquet. Remettez-le par le moyen convenu avec lui ; si vous ne le connaissez pas, demandez-le à l'équipe technique.</dd>
            <dt>Ce qu'il montre d'autres clients</dt>
            <dd data-autres-clients="">Les autres opérations que le registre public a inscrites dans le même lot que les siennes, telles qu'il les a inscrites. On y lit, pour chacune : l'identifiant du client sur le registre public (un code qui, pour un client du registre réel, ne permet pas de le reconnaître), des adresses, des empreintes, des montants de crédits d'écriture, et le texte qu'un client joint parfois à une clôture de période. Rien d'autre : rien de ce que ces clients nous ont transmis hors du registre public. C'est voulu : le registre public ne prouve une opération qu'avec tout son lot, et le client en a besoin pour contrôler ses propres preuves. Tout dossier de preuve tiré du registre public porte de même ces traces.</dd>
            <dt>Ce que le client vérifie</dt>
            <dd>Que l'empreinte ci-dessus est bien celle du paquet reçu, puis que les adresses du paquet (ses approbateurs, leur responsable, son enregistreur et son compte technique) sont bien les siennes. S'il relève un écart, il vous le signale, et rien ne doit être signé tant que l'écart n'est pas éclairci.</dd>
          </dl>
          <CreditsEnClair />
          <TelechargerPaquet slug={slug} />
          <p className="nt-attenue nt-petit">Le fichier téléchargé est une archive « .tar », que le client sait ouvrir. Le paquet est contrôlé de nouveau à chaque téléchargement.</p>
          <div className="nt-encart ins-remise" data-remise={remise ? "notee" : "a-noter"} aria-labelledby="remise-titre">
            <h3 className="ins-groupe" id="remise-titre">Remise au client</h3>
            {remise ? (
              <p className="ins-essentiel-texte" data-remise-en-vigueur={remise.id}><Icone nom="coche" />{phraseRemise(remise)}</p>
            ) : (
              <p className="ins-essentiel-texte">{suivi.remises.some((r) => r.manifest_sha256 === manifeste) ? "La remise notée pour ce paquet a été corrigée : le paquet n'est plus noté comme remis." : "La remise de ce paquet n'est pas encore notée."}</p>
            )}
            {manifeste ? <RemisePaquet slug={slug} manifeste={manifeste} enVigueur={remise ? { id: remise.id } : null} /> : null}
          </div>
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
        <details className="nt-detail ins-replie" data-produire-de-nouveau="">
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

      {suivi.remises.length > 0 ? (
        <details className="nt-detail ins-replie" data-historique-remises="">
          <summary>Remises notées<span className="nt-detail-note">{suivi.remises.length} {suivi.remises.length > 1 ? "notes" : "note"}, les plus anciennes d'abord ; aucune ne s'efface</span></summary>
          <div className="nt-detail-corps">
          <ul className="ins-liste">
            {suivi.remises.map((r) => (
              <li key={r.id} data-remise-notee={r.id} data-corrigee={r.correction ? "oui" : "non"}>
                <p>{r.correction ? <s>{phraseRemise(r)}</s> : phraseRemise(r)}{r.manifest_sha256 === manifeste ? " C'est le paquet affiché sur cet écran." : " C'était un paquet produit avant celui-ci."}</p>
                {r.correction ? <p className="nt-attenue nt-petit" data-correction={r.correction.id}>Corrigée le {dateLisible(r.correction.recu_a)} par {nomDuCompte(r.correction.exploitant)} : « <span data-valeur="">{r.correction.motif}</span> ».</p> : null}
                <p className="nt-attenue nt-petit">Empreinte du paquet remis : <span className="nt-fixe" data-valeur="">{r.manifest_sha256}</span></p>
              </li>
            ))}
          </ul>
          </div>
        </details>
      ) : null}

      {dernier ? (
        <details className="nt-detail ins-replie" data-derniere-production="">
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
