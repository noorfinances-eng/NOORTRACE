# Épreuve d'acceptation de CT-5 : ancrage, cadence, fenêtre, coût, panne

Consigne de l'épreuve TR-4 de CT-9 (section 12, protocole commun ;
table 12.2). Produite par `scripts/vecteurs/generer-ct9.mjs` ; ne pas
l'éditer à la main. Le participant reçoit ce fichier et le matériel nommé
ci-dessous, rien d'autre ; il répond par écrit, seul, sans interroger
personne ; la durée court de la remise du matériel à la remise de la
réponse. La grille du juge est un fichier à part qui ne lui est pas remis.

## Matériel remis

- `spec/CT-5-ancrage.md` en entier ;
- `spec/CT-1-journal.md`, sections 9 à 11 ;
- cette consigne.

Ne sont pas remis : CT-6, CT-8, CT-9, le code du dépôt, la grille
`acceptation-ancrage-attendu.json`.

## Données de la question 4

Prix unitaires symboliques : `p_q` = 1 p par jeton d'une autorité qualifiée,
`p_s` = 0,2 p par jeton d'une autorité de second rang ; le registre et
OpenTimestamps ne sont pas facturés dans ce calcul. Cas à traiter : le cas
nommé `defaut-second-rang-a1` de la section de CT-5 sur le coût (points
contresignés par une autorité de second rang, `a` = 1), pour un journal sur
une année. Donnez le détail du calcul et le total.

## Questions

1. À quelle cadence l'enregistreur produit-il ses points de contrôle, à
   quelle cadence le composant d'ancrage les fait-il contresigner, et à
   quelle cadence les périodes sont-elles closes ? Nommez les paramètres.
2. Pour chacune des ancres qu'un point peut recevoir, dites ce que sa
   vérification réussie prouve et ce qu'elle ne prouve pas.
3. Quelle fenêtre de réécriture la conception laisse-t-elle à qui détient
   la clé de l'enregistreur, pour la date et pour l'ordre, avec les points
   en service ; et quelle fenêtre restait-il avec les seules ancres
   horaires ?
4. Avec les données ci-dessus, quel est le coût annuel d'ancrage d'un
   journal dans le cas nommé ?
5. Le prestataire d'horodatage principal ne répond plus pendant une heure.
   Que fait le composant d'ancrage, que fait l'enregistreur, qu'est-ce qui
   est alerté et quand, et que verra le réviseur d'un dossier exporté
   pendant cette heure ?

## Forme de la réponse

Un texte par question, numéroté ; citez la section de CT-5 ou de CT-1 qui
fonde chaque affirmation. Ne recopiez pas la spécification : dites ce
qu'elle établit.
