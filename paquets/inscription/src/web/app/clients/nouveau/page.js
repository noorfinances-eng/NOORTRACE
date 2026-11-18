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
// la forme, pas l'exactitude). Les exemples s'écrivent sous les champs. Le budget d'écriture et le compte de
// paiement, dont la valeur par défaut est sûre (EX-4.19, EX-8.20 : l'agent recalcule et plafonne), sont rangés
// dans « Réglages avancés », replié.

import FormulaireTravail from "../../../composants/FormulaireTravail.js";
import Icone from "../../../composants/Icone.js";
import Lexique from "../../../composants/Lexique.js";
import { exigerSession, nature } from "../../../lib/page.mjs";

export const dynamic = "force-dynamic";

// RG-1 : slug de l'organisation ; en production, « o- » et 32 chiffres hexadécimaux tirés au hasard (EX-6.2).
const ORG = {
  nom: "org", libelle: "Nom court du client", type: "slug", exemple: "assureur-demo", tirage: "Tirer un nom au hasard",
  aide: "Le nom sous lequel le client sera inscrit ; il ne pourra plus changer. Pour un vrai client, cliquez sur « Tirer un nom au hasard » : ce nom est visible de tous sur le registre public et ne doit pas permettre de reconnaître le client. Pour un essai, écrivez un nom libre, en minuscules, sans espace ni accent.",
  apres: "Ce nom ne dit pas qui est le client : notez la correspondance dans votre fichier des clients.",
};
// RG-2 : noms des journaux.
const JOURNAUX = { nom: "journaux", libelle: "Noms des journaux du client", type: "liste_noms_journal", exemple: "journal-principal", aide: "Un journal est la suite des actions enregistrées chez le client, dans l'ordre. Le client vous donne par écrit le nom de chacun de ses journaux. Un nom par ligne ; recopiez-le exactement, car son enregistreur emploie ce même nom." };
const SEUIL = { nom: "seuil", libelle: "Nombre d'approbations requises", type: "seuil", exemple: "2", aide: "Combien d'approbateurs doivent signer pour qu'une décision du client soit valable. Le client vous donne ce nombre par écrit ; il ne dépasse pas le nombre d'approbateurs." };
// EX-4.19 : budget journalier b_k de chaque clé de chaîne, en gaz.
const BUDGET = { nom: "budget_jour", libelle: "Budget d'écriture par jour", type: "montant", facultatif: true, exemple: "10800000", aide: "Ce que l'enregistreur du client pourra dépenser chaque jour pour écrire sur le registre public (unité technique : le « gaz »). Laissez vide : la valeur habituelle, 10 800 000, convient à un journal qui dépose une preuve de date par heure. N'écrivez une autre valeur que si l'équipe technique vous la donne." };
const TRESORERIE = { nom: "tresorerie", libelle: "Référence de notre compte de paiement", type: "reference_cle", facultatif: true, exemple: "alias:tresorerie", aide: "Le compte de notre société qui paiera le versement sur le compte technique du client. Laissez vide : c'est le compte habituel du service d'inscription. Ne remplissez ce champ que si l'équipe technique vous a donné une référence, qui commence par « fichier: » ou « alias: ». Une référence dit où une clé est rangée ; ce n'est jamais la clé secrète elle-même." };
const VERSEMENT = { titre: "Le versement sur le compte technique", replie: "Réglages avancés", texte: "Ce qui sera versé au compte technique de l'enregistreur pour payer ses écritures. Les valeurs habituelles s'appliquent quand ces champs restent vides ; le service d'inscription recalcule lui-même le montant du versement.", champs: [BUDGET, TRESORERIE] };
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
            { titre: "Le client", champs: [ORG, JOURNAUX] },
            {
              titre: "Ses approbateurs",
              texte: "Les approbateurs sont les personnes du client qui donnent leur accord en signant. Chacun est désigné par son adresse de signature, qui n'est pas un secret.",
              champs: [
                { nom: "approbateurs", libelle: "Adresses de signature des approbateurs", type: "liste_adresses", exemple: "0x1111111111111111111111111111111111111111", aide: "Le client vous donne par écrit l'adresse de signature de chacun de ses approbateurs : « 0x » suivi de 40 caractères. Une adresse par ligne ; copiez-les sans les retaper. Si une adresse est fausse, l'outil ne peut pas le voir, et une autre personne que prévu pourrait approuver à la place du client." },
                SEUIL,
                { nom: "admin_jeu", libelle: "Adresse de signature du responsable des approbateurs", type: "adresse", exemple: "0x2222222222222222222222222222222222222222", aide: "La personne du client qui pourra, plus tard, ajouter ou retirer un approbateur. Le client vous donne son adresse par écrit. C'est toujours une adresse du client, jamais une des nôtres : pour un vrai client, l'outil refuse une de nos adresses." },
              ],
            },
            {
              titre: "Son enregistreur",
              // CT-2 EX-11.13 : documents cle_enregistreur fournis par le démon de l'enregistreur.
              texte: "L'enregistreur est le logiciel qui note chaque action de l'agent logiciel du client au moment où elle a lieu.",
              champs: [{ nom: "cles_enregistreur", libelle: "Fiche de l'enregistreur du client", type: "liste_documents", exemple: "[ { tout le contenu de la fiche, tel quel } ]", aide: "À son installation, l'enregistreur du client produit une fiche : un petit fichier de texte qui le décrit, lui et son compte technique, sans aucun secret. Le client vous envoie ce fichier. Ouvrez-le, copiez tout son contenu sans rien y changer, et collez-le ici entre un crochet ouvrant « [ » et un crochet fermant « ] ». Pour plusieurs enregistreurs, séparez les fiches par une virgule." }],
            },
            VERSEMENT,
          ]}
          note={APRES}
          bouton="Préparer le dossier"
        />
      </section>
      {developpement ? (
        <details className="nt-detail" data-action="cles-essai">
          <summary>Préparer un client d'essai<span className="nt-detail-note">réservé aux essais de l'équipe technique</span></summary>
          <div className="nt-detail-corps">
            <p className="nt-attenue">Ne vous servez pas de ce formulaire pour un vrai client. En mode essai, les approbateurs et l'enregistreur peuvent venir d'un fichier de clés d'essai que l'équipe technique a déjà déposé auprès du service d'inscription.</p>
            <FormulaireTravail
              commande="inscrire-client-preparer"
              sections={[
                { titre: "Le client d'essai", champs: [ORG, JOURNAUX, SEUIL] },
                { titre: "Les clés d'essai", champs: [{ nom: "cles_essai", libelle: "Fichier des clés d'essai", type: "chemin", defaut: "cles-essai.json", aide: "Le nom du fichier que l'équipe technique a déposé. Gardez la valeur proposée, sauf consigne contraire." }] },
                VERSEMENT,
              ]}
              note={APRES}
              bouton="Préparer le dossier d'essai"
              principal={false}
            />
          </div>
        </details>
      ) : null}
      <Lexique />
    </main>
  );
}
