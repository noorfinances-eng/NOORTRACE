# Confrontation tierce de CT-9 : recomptage indépendant en Python

`recompter.py` (Python 3, `python3 -I`, bibliothèque standard seule) est
écrit depuis le seul texte de [CT-9](../../../CT-9-plan-de-tests.md)
(sections 0.1, 0.2, 3.3, 4.1, 4.2, 5.1, 5.2, 5.5, 10.4, 10.7, 10.8, 11.5,
12.2, annexes A.6 et A.11, EX-A.18), sans reprendre une ligne du code
JavaScript ni du code Go du dépôt. Ses expressions régulières sont les
siennes ; il relit les mêmes entrées que l'outil de couverture et compare
chaque compte à `couverture.json`, au catalogue, à
`index-ta-par-menace.json`, à `menaces.json` et aux chiffres écrits dans le
texte de CT-9 (tables de 5.2 et 5.5, phrases de 0.2, 5.5, 10.8 et EX-A.11).

Ce qu'il recompte, dans l'ordre de sa sortie :

1. les identifiants définis par `spec/CT-1-*.md` à `CT-8-*.md` (5.2), par
   spécification et par famille : `**EX-s.k**` ou `**EX-s.k (` en gras,
   première cellule `| XX-k |` d'une ligne de table (gras retiré), hors
   blocs de code, préfixes `CT-` et `EIP-` exclus ; pour CT-8, les lignes
   `DM-n` en début de ligne (elles sont dans le bloc de code du modèle de
   dimensionnement), `**IR-n**`, `**IC-n**` et RB-1 à RB-8 des titres
   `### 10.12` à `### 10.19` ;
2. la règle (a) de 5.1 : chaque identifiant couvert par `covers` d'une
   entrée (sections `§` ignorées), par `threats` d'un TA- (menaces) ou par
   `covers` d'une justification NC-, et les identifiants cités inconnus
   (EX-5.5) ;
3. les occurrences de « CT-9 » dans ces fichiers et `spec/README.md`, la
   clé de section de chacune (dernier titre de niveau 2 à 4 hors bloc de
   code ; `§` suivi du premier mot quand il est numérique ou de la forme
   `A.11`, le titre entre guillemets sinon, « en-tête » avant le premier
   titre), comparées aux lignes TC- du catalogue et à la table TC du texte ;
4. les menaces de `menaces.json` : un TA-n par MN-n, avec `threats`,
   `component`, `covers` = `response.refs`, `threat_test_text` = `test`,
   `accepted_risk` ; les cinq scénarios (composition, union des `covers` et
   des `threats`) ; les 82 risques acceptés (nom, borne, porteur, menace,
   test, état) ; `index-ta-par-menace.json` (test, état, scénarios) ;
5. les titres `describe`/`it` de `test/*.test.js` et les étapes `- name:`
   de `.github/workflows/ci.yml` cités par les entrées exécutables (règle
   (d), EX-4.2) : le titre est le texte source entre ses délimiteurs,
   échappements compris ; `describe(` et `it(` sont reconnus comme mots
   entiers après neutralisation des commentaires, des expressions
   rationnelles littérales et de l'intérieur des chaînes ; un `it` doit
   être dans le bloc d'accolades du `describe` cité (imbrication comprise) ;
6. les `it` de `test/adversarial.test.js` : nombre (EX-A.11, 10.8), forme
   du titre « TA-n (MN-n » (EX-10.7), fin « (tué) » ou « (tués) »,
   identifiants TA- distincts cités et leur entrée au catalogue ;
7. les lignes TM- et TR- des tables 11.5 et 12.2 (identifiants dans
   l'ordre du catalogue, colonne « État » conforme à `status`, colonne
   « Mesure » vide et `measured` nul, identifiants de leurs `covers`
   connus) et la table des chiffres par niveau de 5.5.

## Commande

Depuis la racine du dépôt :

```bash
python3 -I spec/vecteurs/ct-9/confrontation/recompter.py . \
    > spec/vecteurs/ct-9/confrontation/sorties/recompte.txt
```

Codes : 0 sans discordance ; 1 avec au moins une discordance ; 2 pour un
usage incorrect ou un fichier illisible. La sortie ne porte ni chemin local,
ni date, ni version d'outil ; deux exécutions donnent les mêmes octets, et
le même résultat quel que soit le répertoire courant (la racine est
l'argument). Versions de la sortie publiée : Python 3.13.16, sur le dépôt
au commit éprouvé de CT-9 0.1 (2026-11-01).

## Règle de comparaison

Chaque compte recalculé est comparé à la valeur publiée (`couverture.json`,
catalogue, index, `menaces.json`) ou écrite dans le texte de CT-9 ; toute
différence est une discordance, imprimée `[DISCORDANCE]` dans le bilan et
rendue par le code 1. Un écart voulu au sens d'EX-A.18 est imprimé
`[DECLARE]`, ne compte pas comme discordance et doit être déclaré ici avec
sa raison. `test/plan-de-tests.test.js` et le job de confrontation de
l'intégration continue rejouent le programme et exigent le code 0 et une
sortie égale, octet pour octet, à `sorties/recompte.txt` ;
`test/confrontation.test.js` n'est pas modifié.

## Bilan

Sortie publiée `sorties/recompte.txt` : **0 discordance**, 0 écart déclaré.

Tous les comptes égalent `couverture.json` et le catalogue : 2332
identifiants (CT-1 44, CT-2 335, CT-3 259, CT-4 181, CT-5 174, CT-6 262,
CT-7 580, CT-8 497), mêmes familles ; 2193 couverts par une entrée, 139 par
un NC-, 0 non couvert, 0 cité inconnu ; 117 occurrences de « CT-9 » sur 110
lignes, 117 lignes TC-, mêmes clés de section ; 98 menaces, 98 TA-, 82
risques acceptés, index égal ; 162 `describe` et 906 `it` dans 26 fichiers,
41 étapes de CI, 189 entrées exécutables citant 359 titres ou étapes tous
trouvés ; 58 `it` dans `test/adversarial.test.js`, 63 identifiants TA-
distincts cités, 63 entrées citant le fichier (TA-17 partage les `it`
« TA-17 et TA-61 … » et « TA-17 et TA-69 … », EX-10.7) ; 43 lignes TM- et
15 lignes TR- égales au catalogue ; table des chiffres par niveau égale.

Formes admises comptées sans écart : les deux `it` d'EX-10.4 (TA-23, TA-72),
dont l'oracle porte sur un vecteur et dont le mutant est la régénération
observée par l'intégration continue, portent « oracle sur le vecteur » à la
place de « (tué) », comme EX-10.7 l'admet ; le programme les compte à part
(ligne « EX-10.4 et EX-10.7 » de la section 6) sans les déclarer en écart.

## Ce que le programme ne fait pas

Il ne valide aucun fichier contre un schéma, ne compare pas les autres
tables du texte cellule par cellule (rôle de l'outil de couverture et du
vérificateur Go) et n'exécute aucun test. Il n'écrit rien : la sortie
publiée est une redirection de sa sortie standard.
