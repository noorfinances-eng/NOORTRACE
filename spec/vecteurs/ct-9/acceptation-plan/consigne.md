# Épreuves (a) et (c) de CT-9 : écrire un test, ajouter une entrée

Consigne de l'épreuve TR-13 et TR-15 de CT-9 (section 12, protocole commun ;
table 12.2). Produite par `scripts/vecteurs/generer-ct9.mjs` ; ne pas
l'éditer à la main. Le participant reçoit ce fichier et le matériel nommé
ci-dessous, rien d'autre ; il répond par écrit, seul, sans interroger
personne ; la durée court de la remise du matériel à la remise de la
réponse. Pour (a), la grille du juge est l'entrée du catalogue elle-même et
les exigences qu'elle cite (exception écrite d'EX-12.3) ; pour (c), le
verdict de l'outil de couverture.

## Épreuve (a), testeur (TR-13)

Matériel : `spec/CT-9-plan-de-tests.md` sans sa section 15 (extrait
`extraits/CT-9-sans-15.md`), le catalogue `catalogue.json`, les identifiants des
cinq entrées que le juge a tirées au sort parmi les entrées `a_ecrire` autres
que TR-13, TR-14 et TR-15 (le juge remet ces identifiants, non une règle de
tirage ; ils sont consignés) et, pour chacune, les spécifications qu'elle vise :
celles de son membre `specs` et, de toute autre spécification que ses
préconditions, ses pas, son oracle ou son bloc propre nomment, les sections
citées ; les lire n'est pas un écart. Ne sont pas remis : la section 15 de CT-9,
les fichiers `test/*.test.js` du dépôt.

Pour chaque entrée tirée, écrivez un fichier de test, en mocha ou en
pseudo-code structuré, qui reprend ses préconditions (ce qui doit être vrai
avant), ses étapes (dans l'ordre) et son oracle (ce qui est comparé à
quoi), avec pour chacun une contrepartie exécutable : une entrée concrète,
une comparaison, une valeur ou un fichier. Chaque assertion cite
l'identifiant de la règle qu'elle vérifie. Une réponse qui recopie le texte
de l'entrée sans entrée concrète ni comparaison exécutable échoue. Rendez
cinq fichiers, un par entrée, nommés par l'identifiant de l'entrée.

## Épreuve (c), développeur (TR-15)

Matériel : `spec/CT-9-plan-de-tests.md` sans sa section 15, le dépôt au commit
éprouvé, et une exigence EX- d'une des spécifications CT-1 à CT-8, désignée par
le juge et consignée. Aucun auteur de CT-9 ne peut être interrogé. Si l'exigence
désignée n'existe pas dans la spécification nommée, consignez-le et
arrêtez-vous, sans lui substituer une autre exigence.

Ajoutez au catalogue une entrée qui teste cette exigence, en suivant les
seules règles de CT-9 (sections 3 et 4 : niveau, famille d'identifiant,
membres d'une entrée, états) et la procédure d'EX-4.6 : l'entrée s'écrit
dans la source de données du générateur (`scripts/vecteurs/ct9/donnees/`),
le catalogue se régénère par `npm run vecteurs:ct9`, les tables du texte
se réimpriment par `node scripts/vecteurs/generer-ct9.mjs --tables
<fichier hors de spec/vecteurs/ct-9/>` et vous collez les blocs
`<!-- table X -->` régénérés dans `spec/CT-9-plan-de-tests.md` (vous
mettez aussi à jour les chiffres de la section 5.5 si votre entrée les
change, et, s'ils changent, ceux des sections 10.8 et 16, que l'outil ne
relit pas), puis vous lancez `node scripts/tests/couverture.mjs`, sans puis
avec `--strict`. Rendez le diff de votre ajout (source de données et
texte) et la sortie de l'outil. Si votre entrée est `executable`, écrivez
aussi le test qu'elle cite dans `test/*.test.js` : son diff fait alors
partie de votre réponse.

## Forme de la réponse

Les fichiers rendus et, pour (c), le diff et la sortie de l'outil ; aucune
autre explication n'est demandée.
