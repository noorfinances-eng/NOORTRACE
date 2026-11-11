# @noortrace/verification-web — page de vérification (CT-6 §18)

La page statique et publique qui exécute dans le navigateur, dans un
travailleur, le vérificateur `noortrace-verifier` compilé en WebAssembly,
sur un dossier que l'utilisateur choisit et qui ne quitte pas son poste ;
elle affiche le rapport du binaire, sans rien y ajouter (CT-6 §18). Le
paquet porte le script qui produit, de façon déterministe, les fichiers de
la page à partir de l'artefact WebAssembly.

**État : en construction, étape 6.** Le contrat est dans `INTERFACES.md`.

Fichiers repris de noorchain-core : aucun à ce jour.
