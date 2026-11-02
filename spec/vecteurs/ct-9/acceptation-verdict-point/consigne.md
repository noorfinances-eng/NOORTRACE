# Épreuve de lecture de CT-6 §7 révisée : le verdict avec un point de contrôle

Consigne de l'épreuve TR-5 de CT-9 (section 12, protocole commun ;
table 12.2). Produite par `scripts/vecteurs/generer-ct9.mjs` ; ne pas
l'éditer à la main. Le participant reçoit ce fichier et le matériel nommé
ci-dessous, rien d'autre ; il répond par écrit, seul, sans interroger
personne ; la durée court de la remise du matériel à la remise de la
réponse. La grille du juge est un fichier à part qui ne lui est pas remis.

## Matériel remis

- `spec/CT-6-verificateur.md`, section 7 entière (7.1 à 7.10) ;
- le rapport de vérification d'un dossier des vecteurs qui porte la partie
  `points-de-controle.json` ; le dossier est :

  ```text
  spec/vecteurs/ct-6/dossiers/valide-point-de-controle-complet
  ```

  Son énoncé est le membre `statement` de son fichier `attendu.json` ; le
  rapport complet se produit, avec les fichiers d'ancres et d'en-têtes que ce
  même `attendu.json` nomme (`anchors`, `bitcoin_headers`), par :

  ```bash
  node scripts/verify/dossier.mjs <dossier> --ancres <ancres> \
    --entetes-bitcoin <chaîne> --json
  ```

- cette consigne.

Ne sont pas remis : les autres sections de CT-6, CT-5, CT-9, la grille
`acceptation-verdict-point-attendu.json`.

## Questions

1. Qu'engage exactement le point de contrôle que porte ce dossier, par
   rapport au journal et par rapport au manifeste de la période ?
2. Que prouve la clause du rapport qui porte sur le jeton du point, et que
   représente le membre `facts.checkpoint.rewrite_window_ms` du rapport :
   une preuve ou autre chose ?
3. Si l'enregistreur réécrivait cet événement après ce point, qu'est-ce qui
   changerait dans la vérification, et qui s'en apercevrait ?
4. Que ne prouve pas la signature du point par l'enregistreur, et que
   resterait-il du verdict si la vérification du jeton du point n'avait pas
   été exécutée ou avait échoué ?

## Forme de la réponse

Un texte par question, numéroté ; citez le passage de la section 7 qui
fonde chaque affirmation.
