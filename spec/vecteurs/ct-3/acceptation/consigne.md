# Épreuve d'acceptation de CT-3 : trois relecteurs, une politique, dix cas

Ce répertoire, avec la partie A de la spécification CT-3, est tout ce que
reçoit un relecteur. Il sert le critère d'acceptation du lot CT-3 : trois
relecteurs, dans les rôles d'approbateur, d'auditeur et de développeur,
lisent la même politique à l'aveugle et en tirent la même décision sur dix
cas (CT-3, annexe A.5, EX-A.4 et EX-A.5).

## Ce que vous recevez

- `politique.json` : une politique d'approbation (document
  `politique-approbation-v0`), ses règles sur un même outil et sa règle
  par défaut ;
- `cas/cas-01.json` à `cas/cas-10.json` : dix demandes, chacune la
  requête `evaluer` que le noyau de l'enregistreur envoie au service
  d'approbation (`tool_announced` est le nom de l'outil, `arguments` ses
  arguments, `delegation.launched_by` le demandeur) ;
- `gabarit-reponse.json` : le fichier à remplir et à rendre ;
- la partie A de la spécification CT-3 (sections 0 à 6), à part.

Pour lire la politique, chaque relecteur lit, dans la partie A : la
section 5 pour les niveaux ; 4.2 pour la forme d'une règle (`description`
est sans effet sur la décision) ; 4.4 à 4.11 pour la sélection de l'outil,
les pointeurs, les types (un montant est numérique s'il est une chaîne
décimale ou un nombre JSON entier, EX-4.5), les comparaisons, les
combinaisons `all`, `any`, `none`, la valeur INDETERMINE d'un argument
absent ou d'un autre type, et la règle par défaut ; 6.2 à 6.4 pour l'issue de
chaque règle et le rang qui l'emporte. Le rôle de développeur lit en plus le
reste des sections 4 et 6.

## Ce que vous faites

1. Travaillez seul. Ne consultez ni les réponses des autres relecteurs, ni
   aucun fichier de décisions attendues : il n'est pas dans ce répertoire et
   vous ne devez pas le demander avant d'avoir rendu votre réponse.
2. Pour chaque cas, décidez ce que la politique rend : `autorise`,
   `a_approuver` ou `refuse`. Aucune fenêtre n'est ouverte et aucun ticket
   n'existe : seule la politique décide.
3. Les rôles d'approbateur et d'auditeur n'exécutent aucun code. Le rôle de
   développeur peut écrire son propre code, sans reprendre
   `scripts/lib/approbation.mjs` ni le vérificateur Go du dépôt.
4. Copiez `gabarit-reponse.json`, inscrivez votre rôle (`approbateur`,
   `auditeur` ou `developpeur`), votre nom ou un pseudonyme, et une
   décision par cas, puis rendez le fichier.

## Résultat

L'épreuve est réussie si les trois réponses sont égales entre elles et
égales, cas par cas, aux décisions attendues que tient l'organisateur
(`acceptation-attendu.json`, hors de ce répertoire). L'implémentation de
référence et le vérificateur Go indépendant doivent, eux, rendre exactement
ces décisions attendues. Les réponses des relecteurs ne sont pas des
vecteurs et ne sont pas publiées par le générateur.
