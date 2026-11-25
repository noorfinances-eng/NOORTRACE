// Fiche de contrôle des adresses des approbateurs (CT-4 EX-7.8 et EX-7.26, complément du 2026-11-25, décision du
// porteur sur l'outil d'inscription ; INTERFACES.md 2.7, 3.5) : produite depuis les seules données du dossier, dès
// que le dossier est préparé, pour que le client contrôle lui-même chaque adresse avant qu'elle parte vers le
// registre public (étape `jeu_approbateurs` du pas 2, la seule qui les envoie).
//
// Deux formes du même contenu : le fichier texte canonique (`texteFiche` : UTF-8, une ligne par élément, sauts de
// ligne `\n`, aucune date ni valeur variable, de sorte que le même dossier donne les mêmes octets) et la page
// imprimable de l'interface, qui met en forme les mêmes lignes (`lignesFiche`). L'empreinte de la fiche est le
// SHA-256 du fichier texte (`empreinteFiche`) ; la confirmation du client la cite (`objet.fiche_sha256`), et l'agent
// la recalcule depuis le dossier au moment d'exécuter l'étape : un dossier dont un approbateur ou une adresse a
// changé donne une autre empreinte, et une confirmation qui citait l'ancienne ne vaut plus.
//
// Le dossier ne porte pas le nom des approbateurs : il vient d'une note interne de l'application (`noms_approbateurs`,
// src/commun/notes.mjs), saisi par l'exploitant d'après ce que le client a écrit, par adresse ; la fiche le porte à
// côté de l'adresse, et, s'il manque, un trait et la consigne « le client complète le nom ». Il entre dans le fichier,
// donc dans l'empreinte : une fiche dont un nom change est une fiche nouvelle. Le nom interne du client (EX-7.23) n'y
// entre jamais : la fiche nomme l'organisation par son slug.
//
// Chaque version de la fiche produite est gardée par l'agent, dans ses données (`fiches-controle.ndjson` : organisation,
// numéro de version, empreinte, instant), hors du paquet ; `versionsFiche` les lit, la plus récente d'abord, et dit
// laquelle est la version courante.
//
// Module pur : l'interface (page, route de téléchargement, formulaire de confirmation, consigne de la fiche du
// client) et l'agent (admission et exécution du travail `inscrire-client`) calculent la même fiche.

import { sha256Hex, utf8 } from "@noortrace/noyau";

/** Opération de la confirmation hors bande qui porte la fiche renvoyée (EX-7.26) : le nom de l'étape qu'elle débloque. */
export const OPERATION_FICHE = "jeu_approbateurs";
/** Titre de la fiche, première ligne du fichier. */
export const TITRE_FICHE = "Fiche de contrôle des adresses des approbateurs";
/** Consigne au client, dernière ligne du fichier. */
export const CONSIGNE_FICHE = "Chaque approbateur compare sa ligne, en entier, à l'adresse que montre son propre portefeuille, et écrit son nom à côté. Renvoyez-nous ensuite cette fiche confirmée par écrit, par un autre moyen que l'outil d'inscription.";
/** Nom du fichier texte à télécharger. */
export const nomFichierFiche = (slug) => `fiche-controle-${slug}.txt`;
/** Registre des versions de la fiche dans les données de l'agent (INTERFACES.md 3.6). */
export const FICHIER_FICHES = "fiches-controle.ndjson";
/** Ce que porte la ligne d'un approbateur dont le nom manque. */
export const NOM_A_COMPLETER = "— (le client complète le nom)";

/** Un entier en chiffres, sans espace (la fiche ne groupe rien : elle se compare caractère à caractère). */
const entier = (n) => String(n);

/**
 * Les lignes de la fiche, dans l'ordre du fichier : `[{ cle, libelle, valeur, nom }]`. `cle` nomme la ligne
 * (`titre`, `organisation`, `approbations`, `approbateur`, `responsable`, `consigne`) ; `valeur` est le texte tel
 * quel (slug, adresse) ; sur une ligne d'approbateur, `nom` est le nom donné par le client (`noms`, par adresse) ou
 * null quand il manque.
 */
export function lignesFiche(dossier, noms = {}) {
  const membres = Array.isArray(dossier?.approvers?.members) ? dossier.approvers.members : [];
  const requises = dossier?.approvers?.threshold;
  const l = [
    { cle: "titre", libelle: TITRE_FICHE, valeur: null, nom: null },
    { cle: "organisation", libelle: "Organisation (nom court)", valeur: String(dossier?.organisation?.slug ?? ""), nom: null },
    { cle: "approbations", libelle: "Nombre d'approbations requises", valeur: `${entier(requises)}, sur ${entier(membres.length)} ${membres.length > 1 ? "approbateurs" : "approbateur"}`, nom: null },
  ];
  membres.forEach((adresse, k) => l.push({ cle: "approbateur", libelle: `Approbateur ${k + 1}`, valeur: String(adresse), nom: typeof noms?.[adresse] === "string" && noms[adresse] !== "" ? noms[adresse] : null }));
  l.push({ cle: "responsable", libelle: "Responsable des approbateurs", valeur: String(dossier?.approvers?.set_admin ?? ""), nom: null });
  l.push({ cle: "consigne", libelle: "Consigne", valeur: CONSIGNE_FICHE, nom: null });
  return l;
}

/** Le texte d'une ligne d'approbateur après l'adresse : le nom donné, ou le trait et la consigne. */
export const nomSurLaFiche = (nom) => `nom : ${nom ?? NOM_A_COMPLETER}`;

/** Le fichier texte canonique de la fiche : `titre\nlibellé : valeur\n…`, terminé par un saut de ligne. */
export function texteFiche(dossier, noms = {}) {
  return lignesFiche(dossier, noms).map((x) => (x.valeur === null ? x.libelle : `${x.libelle} : ${x.valeur}${x.cle === "approbateur" ? ` — ${nomSurLaFiche(x.nom)}` : ""}`)).join("\n") + "\n";
}

/** Octets UTF-8 du fichier texte. */
export const octetsFiche = (dossier, noms = {}) => utf8(texteFiche(dossier, noms));

/** Empreinte de la fiche : SHA-256 du fichier texte, en hexadécimal préfixé par `0x`. */
export const empreinteFiche = (dossier, noms = {}) => sha256Hex(octetsFiche(dossier, noms));

/**
 * Les versions de la fiche d'une organisation, d'après les lignes du registre de l'agent (`{ org_id, version,
 * fiche_sha256, produite_a }`) et l'empreinte de la fiche courante : `[{ version, fiche_sha256, produite_a, courante }]`,
 * la plus récente d'abord ; si la fiche courante n'est pas encore enregistrée (le dossier vient de changer), elle est en
 * tête, sans numéro (`version` null). Une ligne illisible ou d'une autre organisation est ignorée.
 */
export function versionsFiche(lignes, orgId, courante) {
  const l = [];
  for (const x of Array.isArray(lignes) ? lignes : []) {
    if (!x || typeof x !== "object" || x.org_id !== orgId || !Number.isSafeInteger(x.version) || typeof x.fiche_sha256 !== "string") continue;
    l.push({ version: x.version, fiche_sha256: x.fiche_sha256, produite_a: typeof x.produite_a === "string" ? x.produite_a : null, courante: x.fiche_sha256 === courante });
  }
  l.sort((a, b) => b.version - a.version);
  if (courante && !l.some((x) => x.courante)) l.unshift({ version: null, fiche_sha256: courante, produite_a: null, courante: true });
  return l;
}

/** La prochaine ligne à écrire au registre des versions pour une empreinte qui n'y est pas encore, ou null. */
export function nouvelleVersion(lignes, orgId, ficheSha256, instant) {
  const connues = versionsFiche(lignes, orgId, null);
  if (connues.some((x) => x.fiche_sha256 === ficheSha256)) return null;
  return { org_id: orgId, version: (connues[0]?.version ?? 0) + 1, fiche_sha256: ficheSha256, produite_a: instant };
}
