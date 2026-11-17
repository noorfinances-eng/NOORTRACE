// /clients/nouveau : pas 1, les options de `inscrire-client --preparer` (CT-4 §7.5) ; en développement, le choix des
// clés d'essai ou des références. Les clés de l'exploitant se désignent par référence (EX-7.3), jamais par valeur.
//
// Présentation (complément du 2026-11-17) : le formulaire se lit en quatre sections courtes ; chaque champ a un
// libellé en langage courant, une aide et, où il aide, un exemple fictif. Les renvois à la spécification (RG-1,
// RG-2, EX-4.19, CT-2 EX-11.13) restent ici, en commentaire, et dans INTERFACES.md.

import FormulaireTravail from "../../../composants/FormulaireTravail.js";
import Icone from "../../../composants/Icone.js";
import { exigerSession, nature } from "../../../lib/page.mjs";

export const dynamic = "force-dynamic";

// RG-1 : slug de l'organisation ; en production, « o- » et 32 chiffres hexadécimaux tirés au hasard.
const ORG = { nom: "org", libelle: "Nom court de l'organisation", type: "slug", exemple: "assureur-demo", aide: "Lettres minuscules, chiffres et tirets. En production : « o- » suivi de 32 chiffres hexadécimaux tirés au hasard." };
// RG-2 : noms des journaux.
const JOURNAUX = { nom: "journaux", libelle: "Noms des journaux", type: "liste_noms_journal", exemple: "journal-principal", aide: "Un nom par ligne : lettres minuscules, chiffres et tirets." };
const SEUIL = { nom: "seuil", libelle: "Seuil du jeu d'approbateurs", type: "seuil", exemple: "2", aide: "Le nombre d'approbations exigées pour chaque décision. Au plus le nombre d'approbateurs." };
// EX-4.19 : budget journalier b_k de chaque clé de chaîne, en gaz.
const BUDGET = { nom: "budget_jour", libelle: "Budget journalier de chaque clé, en gaz", type: "montant", facultatif: true, exemple: "10800000", aide: "Laissez vide pour le budget par défaut : 10 800 000." };
const TRESORERIE = { nom: "tresorerie", libelle: "Référence de la clé de la trésorerie", type: "reference_cle", facultatif: true, exemple: "fichier:/chemin/vers/tresorerie.cle", aide: "Une clé se désigne par sa référence, jamais par sa valeur. Laissez vide pour la trésorerie de l'agent." };
const FINANCEMENT = { titre: "Le financement", texte: "Ce qui sera versé à chaque clé de chaîne pour payer ses écritures. Les valeurs par défaut conviennent le plus souvent.", champs: [BUDGET, TRESORERIE] };

export default async function PageNouveau() {
  await exigerSession();
  const developpement = nature() === "developpement";
  return (
    <main className="nt-page nt-page-etroite">
      <a className="nt-fil" href="/clients"><Icone nom="retour" />Tous les clients</a>
      <header className="nt-entete">
        <div className="nt-entete-texte">
          <p className="nt-sur-titre">Étape 1</p>
          <h1>Nouveau client</h1>
          <p className="nt-sous-titre">Préparez le dossier d'inscription : l'organisation, ses approbateurs et ses clés d'enregistreur. Rien n'est envoyé au registre à cette étape.</p>
        </div>
      </header>
      <section className="nt-carte" aria-labelledby="dossier-titre">
        <h2 id="dossier-titre">Dossier d'inscription</h2>
        <FormulaireTravail
          commande="inscrire-client-preparer"
          sections={[
            { titre: "L'organisation", champs: [ORG, JOURNAUX] },
            {
              titre: "Les approbateurs",
              texte: "Les personnes du client qui approuveront ses décisions. Une adresse par personne.",
              champs: [
                { nom: "approbateurs", libelle: "Adresses des approbateurs", type: "liste_adresses", exemple: "0x1111111111111111111111111111111111111111", aide: "Une adresse par ligne : « 0x » suivi de 40 chiffres hexadécimaux." },
                SEUIL,
                { nom: "admin_jeu", libelle: "Adresse de la clé de gouvernance", type: "adresse", exemple: "0x2222222222222222222222222222222222222222", aide: "Elle administre le jeu d'approbateurs : c'est une clé du client, jamais un compte de l'exploitant." },
              ],
            },
            {
              titre: "Les clés d'enregistreur",
              // CT-2 EX-11.13 : documents cle_enregistreur fournis par le démon de l'enregistreur.
              champs: [{ nom: "cles_enregistreur", libelle: "Clés d'enregistreur", type: "liste_documents", exemple: "[ { … }, { … } ]", aide: "Tableau JSON, un document par clé, tel que l'enregistreur du client le fournit. Ce sont des clés publiques : aucune clé privée ne se saisit ici." }],
            },
            FINANCEMENT,
          ]}
          bouton="Préparer le dossier"
        />
      </section>
      {developpement ? (
        <details className="nt-detail" data-action="cles-essai">
          <summary>Préparer avec les clés d'essai<span className="nt-detail-note">réseau de développement seulement</span></summary>
          <div className="nt-detail-corps">
            <p className="nt-attenue">Sur le réseau de développement, les approbateurs et les clés d'enregistreur peuvent venir d'un fichier de clés d'essai déjà déposé dans les données de l'agent.</p>
            <FormulaireTravail
              commande="inscrire-client-preparer"
              sections={[
                { titre: "L'organisation", champs: [ORG, JOURNAUX, SEUIL] },
                { titre: "Les clés d'essai", champs: [{ nom: "cles_essai", libelle: "Fichier des clés d'essai", type: "chemin", defaut: "cles-essai.json", aide: "Chemin relatif au répertoire du client dans les données de l'agent." }] },
                FINANCEMENT,
              ]}
              bouton="Préparer le dossier avec les clés d'essai"
              principal={false}
            />
          </div>
        </details>
      ) : null}
    </main>
  );
}
