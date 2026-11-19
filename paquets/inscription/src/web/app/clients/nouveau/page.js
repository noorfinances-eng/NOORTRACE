// /clients/nouveau : pas 1, les options de `inscrire-client --preparer` (CT-4 §7.5) ; en développement, le choix des
// clés d'essai ou des références. Les clés de l'exploitant se désignent par référence (EX-7.3), jamais par valeur.
//
// Présentation (complément du 2026-11-17) : le formulaire se lit en sections courtes ; chaque champ a un libellé
// en langage courant, une aide et, où il aide, un exemple fictif. Les renvois à la spécification (RG-1, RG-2,
// EX-4.19, CT-2 EX-11.13) restent ici, en commentaire, et dans INTERFACES.md.
//
// Langage (complément du 2026-11-18, décision du porteur sur le langage des écrans) : la personne qui remplit ce
// formulaire n'est pas développeuse. Chaque aide dit ce qu'on attend, d'où vient l'information (le client la donne
// par écrit, ou la valeur proposée se garde) et ce qui se passe si elle est fausse (CT-4 EX-7.8 : l'outil contrôle
// la forme, pas l'exactitude). Les exemples s'écrivent sous les champs. La consommation prévue par jour (le budget
// journalier d'EX-4.19) et la référence de notre réserve de crédits (la trésorerie), dont la valeur par défaut est
// sûre (EX-4.19, EX-8.20 : l'agent recalcule et plafonne), sont rangées dans « Réglages avancés », replié, sous ce
// que sont les crédits d'écriture (quatrième lecture des écrans).
//
// Cinquième lecture des écrans (même complément) : le mot « essai » n'a qu'un sens, celui du bandeau « Mode essai » :
// un registre d'essai, qui n'est pas le registre réel. L'aide du nom court dit d'abord le cas habituel (tirer un
// nom au hasard, EX-6.2) ; un nom libre n'est admis que sur un registre d'essai (EX-6.2 : « Les slugs d'essai sont
// libres »), et l'aide ne le dit qu'en mode essai. Le second formulaire, qui prend approbateurs et enregistreur dans
// le fichier de clés que l'équipe technique a déposé (réseau de développement seulement), s'appelle « client de
// démonstration ». L'explication des crédits ne paraît qu'une fois sur l'écran, dans le formulaire principal.

import FormulaireTravail from "../../../composants/FormulaireTravail.js";
import Icone from "../../../composants/Icone.js";
import Lexique from "../../../composants/Lexique.js";
import { exigerSession, nature } from "../../../lib/page.mjs";

export const dynamic = "force-dynamic";

// RG-1 : slug de l'organisation ; en production, « o- » et 32 chiffres hexadécimaux tirés au hasard (EX-6.2).
const AIDE_ORG = "Pour le remplir, cliquez sur « Tirer un nom au hasard ». C'est le nom sous lequel le client sera inscrit, et il ne pourra plus changer. Il sera visible de tous sur le registre public : il ne doit donc pas permettre de reconnaître le client.";
const AIDE_ORG_ESSAI = " En mode essai seulement, vous pouvez aussi écrire un nom libre, en minuscules, sans espace ni accent : sur le registre réel, l'outil le refuserait.";
const ORG = {
  nom: "org", libelle: "Nom court du client", type: "slug", tirage: "Tirer un nom au hasard",
  aide: AIDE_ORG,
  apres: "Ce nom ne dit pas qui est le client : notez-le dans votre fichier des clients, à côté de son vrai nom.",
};
/** En mode essai, l'aide dit aussi qu'un nom libre est admis, et l'exemple en montre un. */
const ORG_ESSAI = { ...ORG, aide: AIDE_ORG + AIDE_ORG_ESSAI, exemple: "assureur-demo" };
// RG-2 : noms des journaux.
const JOURNAUX = { nom: "journaux", libelle: "Noms des journaux du client", type: "liste_noms_journal", exemple: "journal-principal", aide: "Un journal est la suite des actions enregistrées chez le client, dans l'ordre. Le client vous donne par écrit le nom de chacun de ses journaux. Un nom par ligne ; recopiez-le exactement, car son enregistreur emploie ce même nom." };
const SEUIL = { nom: "seuil", libelle: "Nombre d'approbations requises", type: "seuil", exemple: "2", aide: "Combien d'approbateurs doivent signer pour qu'une décision du client soit valable. Le client vous donne ce nombre par écrit ; il ne dépasse pas le nombre d'approbateurs." };
// EX-4.19 : budget journalier b_k de chaque clé de chaîne, en gaz (1 crédit par unité, EX-4.15) ; défaut :
// 24 × (100 000 + 350 000), une ancre et une clôture par heure.
const BUDGET = { nom: "budget_jour", libelle: "Consommation prévue par jour", type: "montant", facultatif: true, exemple: "10800000", aide: "Le nombre de crédits d'écriture que l'enregistreur du client devrait employer chaque jour ; le versement est calculé à partir de lui. Laissez vide : la valeur habituelle, 10 800 000, est calculée pour une preuve de date et une clôture de période par heure. N'écrivez une autre valeur que si l'équipe technique vous la donne." };
// EX-7.3 : la trésorerie, désignée par sa référence ; défaut : celle de la configuration de l'agent.
const TRESORERIE = { nom: "tresorerie", libelle: "Référence de notre réserve de crédits d'écriture", type: "reference_cle", facultatif: true, exemple: "alias:tresorerie", aide: "Le compte de notre société d'où partent les crédits versés sur le compte technique du client. Laissez vide : c'est la réserve habituelle du service d'inscription. Ne remplissez ce champ que si l'équipe technique vous a donné une référence, qui commence par « fichier: » ou « alias: ». Une référence dit où une clé est rangée ; ce n'est jamais la clé secrète elle-même." };
const VERSEMENT = { titre: "Le versement sur le compte technique", replie: "Réglages avancés", texte: "Ce qui sera versé, en crédits d'écriture, sur le compte technique de l'enregistreur, pour qu'il puisse payer ses écritures. Les valeurs habituelles s'appliquent quand ces champs restent vides ; le service d'inscription recalcule lui-même le montant du versement.", credits: true, champs: [BUDGET, TRESORERIE] };
/** Le même, dans le formulaire du client de démonstration : l'explication des crédits est déjà sur l'écran. */
const VERSEMENT_DEMONSTRATION = { ...VERSEMENT, credits: false };
const APRES = "Après le clic : l'outil contrôle la forme de ce que vous avez saisi et crée le dossier ; le client apparaît dans la liste, à l'étape 1 sur 8. Rien n'est envoyé au registre public, rien n'est dépensé.";

export default async function PageNouveau() {
  await exigerSession();
  const developpement = nature() === "developpement";
  return (
    <main className="nt-page nt-page-etroite">
      <a className="nt-fil" href="/clients"><Icone nom="retour" />Tous les clients</a>
      <header className="nt-entete">
        <div className="nt-entete-texte">
          <p className="nt-sur-titre">Étape 1 sur 8</p>
          <h1>Nouveau client</h1>
          <p className="nt-sous-titre">Vous préparez ici le dossier d'inscription du client, avec les informations qu'il vous a transmises par écrit. Rien n'est envoyé au registre public à cette étape.</p>
        </div>
      </header>
      <div className="nt-bandeau nt-bandeau-avertissement" data-avant-de-commencer="">
        <Icone nom="info" />
        <div className="nt-bandeau-texte">
          <p className="nt-bandeau-titre">Ayez sous la main ce que le client vous a écrit.</p>
          <p>Il vous faut : le nom de ses journaux, l'adresse de signature de chacun de ses approbateurs, le nombre d'approbations requises, l'adresse de signature du responsable de ses approbateurs, et la fiche de son enregistreur. Copiez et collez au lieu de retaper : l'outil contrôle la forme de ce que vous saisissez, mais il ne peut pas savoir si une adresse est bien celle du client. Le client le contrôlera en recevant son paquet ; une erreur oblige alors à corriger l'inscription avec l'équipe technique.</p>
        </div>
      </div>
      <section className="nt-carte" aria-labelledby="dossier-titre">
        <h2 id="dossier-titre">Dossier d'inscription</h2>
        <FormulaireTravail
          commande="inscrire-client-preparer"
          sections={[
            { titre: "Le client", champs: [developpement ? ORG_ESSAI : ORG, JOURNAUX] },
            {
              titre: "Ses approbateurs",
              texte: "Les approbateurs sont les personnes du client qui donnent leur accord en signant. Chacun est désigné par son adresse de signature, qui n'est pas un secret.",
              champs: [
                { nom: "approbateurs", libelle: "Adresses de signature des approbateurs", type: "liste_adresses", exemple: "0x1111111111111111111111111111111111111111", aide: "Le client vous donne par écrit l'adresse de signature de chacun de ses approbateurs : « 0x » suivi de 40 caractères. Une adresse par ligne ; copiez-les sans les retaper. Si une adresse est fausse, l'outil ne peut pas le voir, et une autre personne que prévu pourrait approuver à la place du client." },
                SEUIL,
                { nom: "admin_jeu", libelle: "Adresse de signature du responsable des approbateurs", type: "adresse", exemple: "0x2222222222222222222222222222222222222222", aide: "La personne du client qui pourra, plus tard, ajouter ou retirer un approbateur. Le client vous donne son adresse par écrit. C'est toujours une adresse du client, jamais une des nôtres : sur le registre réel, l'outil refuse une de nos adresses." },
              ],
            },
            {
              titre: "Son enregistreur",
              // CT-2 EX-11.13 : documents cle_enregistreur fournis par le démon de l'enregistreur.
              texte: "L'enregistreur est le logiciel qui note chaque action de l'agent logiciel du client au moment où elle a lieu.",
              // Une zone par fiche, collée telle quelle ; la page assemble la liste (troisième lecture des écrans).
              champs: [{ nom: "cles_enregistreur", libelle: "Fiche de l'enregistreur du client", libelleAutre: "Fiche d'un autre enregistreur du client", type: "liste_documents", fiches: true, exemple: "{ tout le contenu du fichier, tel quel }", aide: "À son installation, l'enregistreur du client produit une fiche : un petit fichier de texte qui le décrit, lui et son compte technique, sans aucun secret. Le client vous envoie ce fichier. Ouvrez-le, copiez tout son contenu et collez-le ici, sans rien y ajouter ni retirer. Si le client a plusieurs enregistreurs, il vous envoie une fiche pour chacun : cliquez sur « Ajouter une autre fiche » pour chacune des suivantes." }],
            },
            VERSEMENT,
          ]}
          note={APRES}
          bouton="Préparer le dossier"
        />
      </section>
      {developpement ? (
        <details className="nt-detail ins-replie" data-action="cles-essai">
          <summary>Préparer un client de démonstration<span className="nt-detail-note">réservé à l'équipe technique</span></summary>
          <div className="nt-detail-corps">
            <p className="nt-attenue">Un client de démonstration n'a pas de vrais approbateurs ni de vrai enregistreur : ils viennent d'un fichier de clés que l'équipe technique a déposé auprès du service d'inscription. Ne vous servez de ce formulaire que si elle vous le demande.</p>
            <FormulaireTravail
              commande="inscrire-client-preparer"
              sections={[
                { titre: "Le client de démonstration", champs: [ORG_ESSAI, JOURNAUX, SEUIL] },
                { titre: "Le fichier de clés de démonstration", champs: [{ nom: "cles_essai", libelle: "Fichier des clés de démonstration", type: "chemin", defaut: "cles-essai.json", aide: "Le nom du fichier que l'équipe technique a déposé. Gardez la valeur proposée, sauf consigne contraire." }] },
                VERSEMENT_DEMONSTRATION,
              ]}
              note={APRES}
              bouton="Préparer le dossier de démonstration"
              principal={false}
            />
          </div>
        </details>
      ) : null}
      <Lexique />
    </main>
  );
}
