// /clients/nouveau : pas 1, les options de `inscrire-client --preparer` (CT-4 §7.5) ; en développement, le choix des
// clés d'essai ou des références. Les clés de l'exploitant se désignent par référence (EX-7.3), jamais par valeur.

import FormulaireTravail from "../../../composants/FormulaireTravail.js";
import { exigerSession, nature } from "../../../lib/page.mjs";

export const dynamic = "force-dynamic";

const COMMUNS = [
  { nom: "org", libelle: "Slug de l'organisation (RG-1 ; en production, o- et 32 chiffres hexadécimaux tirés au hasard)", type: "slug" },
  { nom: "journaux", libelle: "Noms des journaux (RG-2), un par ligne", type: "liste_noms_journal" },
  { nom: "seuil", libelle: "Seuil du jeu d'approbateurs", type: "seuil" },
];
const FIN = [
  { nom: "budget_jour", libelle: "Budget journalier de chaque clé de chaîne, en gaz (EX-4.19 ; défaut 10 800 000)", type: "montant", facultatif: true },
  { nom: "tresorerie", libelle: "Référence de la clé de la trésorerie (fichier:, env: ; défaut : celle de l'agent)", type: "reference_cle", facultatif: true, exemple: "fichier:/chemin/vers/tresorerie.cle" },
];

export default async function PageNouveau() {
  await exigerSession();
  const developpement = nature() === "developpement";
  return (
    <>
      <h1>Nouveau client (pas 1)</h1>
      <FormulaireTravail
        titre="Dossier d'inscription"
        commande="inscrire-client-preparer"
        champs={[
          ...COMMUNS,
          { nom: "approbateurs", libelle: "Adresses des approbateurs, une par ligne", type: "liste_adresses" },
          { nom: "admin_jeu", libelle: "Clé de gouvernance, administrateur du CuratorSet (adresse)", type: "adresse" },
          { nom: "cles_enregistreur", libelle: "Clés d'enregistreur : tableau JSON de documents cle_enregistreur (CT-2 EX-11.13)", type: "liste_documents" },
          ...FIN,
        ]}
        bouton="Préparer le dossier"
      />
      {developpement ? (
        <FormulaireTravail
          titre="Avec les clés d'essai (réseau de développement seulement)"
          commande="inscrire-client-preparer"
          champs={[...COMMUNS, { nom: "cles_essai", libelle: "cles-essai.json, chemin relatif au répertoire du client dans les données de l'agent", type: "chemin", defaut: "cles-essai.json" }, ...FIN]}
          bouton="Préparer le dossier avec les clés d'essai"
        />
      ) : null}
    </>
  );
}
