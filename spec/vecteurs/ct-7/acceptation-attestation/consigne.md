# Épreuve à l'aveugle de l'administrateur du client (CT-7, EX-9.4)

Vous recevez la section 7 de la spécification CT-7
(`spec/CT-7-securite-et-conformite.md`, version 0.1) et rien d'autre de la
spécification. Vous disposez aussi de :

- l'attestation de l'exemple :
  `spec/vecteurs/ct-7/attestations/exemple/attestation.json` et sa forme signée
  `attestation-signee.json` ;
- un dossier de preuve qui la porte :
  `spec/vecteurs/ct-1/dossiers/valide-seq-12-attestation-inscrite/` ;
- le rapport de ce dossier, `rapport.txt` dans ce répertoire, tel que l'imprime
  `node scripts/verify/dossier.mjs` sur ce dossier (les deux lignes qui nomment
  la machine et le répertoire sont omises).

Répondez seul et par écrit aux six questions. Un relecteur qui ne vous a pas
aidé compare ensuite vos réponses à une grille qui n'est pas dans ce
répertoire.

## Questions

Q1. Quelles pièces rassemblez-vous pour remplir l'attestation ?
Q2. Qui doit signer, et combien ?
Q3. Que vérifie un signataire avant de signer ?
Q4. Qu'est-ce qui ne doit jamais figurer dans l'attestation ?
Q5. Que prouve l'attestation vérifiée, et que ne prouve-t-elle pas ?
Q6. Le rapport du dossier fourni dit-il que le périmètre est prouvé ?
