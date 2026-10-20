# NOORTRACE — architecture cible

Version 0.1, 20 octobre 2026. Document de conception, pas d'implémentation.

## Principe

Un journal n'a de valeur probatoire que si trois acteurs ne peuvent pas le réécrire :
l'agent, l'opérateur de l'agent, et le fournisseur du journal. NOORTRACE sépare donc
trois rôles.

| Rôle | Qui | Ce qu'il peut faire | Ce qu'il ne peut pas faire |
|---|---|---|---|
| Enregistreur | Composant déployé chez le client | Capturer, chaîner, signer les événements | Être lu ou modifié par l'agent |
| Registre et approbations | NOORTRACE, sur NOORCHAIN | Enregistrer les lots d'empreintes et les décisions humaines | Modifier un événement déjà chaîné |
| Ancre de confiance | Prestataire qualifié et registre public | Horodater les racines de lots | Rien d'autre : il ne voit que des empreintes |

## Flux

1. **Capture.** L'enregistreur s'insère entre l'agent et ses outils, comme proxy MCP
   ou comme SDK dans le runtime. Chaque appel d'outil, chaque lecture ou écriture de
   données, chaque sortie produit un événement.
2. **Chaînage.** Chaque événement porte l'empreinte du précédent et une signature
   de l'enregistreur. Le journal est en ajout seul, sur un volume séparé de celui
   de l'agent, conformément aux recommandations du PFPDT sur la journalisation.
3. **Approbation.** Les actions marquées sensibles par la politique du client sont
   suspendues jusqu'à décision d'un approbateur humain. La décision, son auteur, son
   instant et son motif deviennent des événements du même journal. Les jeux
   d'approbateurs, repris des contrats de curateurs de NOORCHAIN, fournissent ce
   mécanisme : bornés, tracés, contestables.
4. **Ancrage.** Toutes les heures, la racine de Merkle des événements de la période
   est horodatée par un prestataire de confiance qualifié ZertES et eIDAS, puis
   ancrée sur un registre public gratuit. Seule la racine quitte le client.
5. **Dossier de preuve.** À la demande, pour un incident, une revue ou une requête
   du régulateur, le client exporte les événements concernés, les preuves d'inclusion
   et les jetons d'horodatage.
6. **Vérification.** Un vérificateur en ligne de commande, publié en source ouverte,
   recalcule la chaîne, contrôle les preuves d'inclusion, valide les jetons
   d'horodatage contre le certificat du prestataire et la preuve d'ancrage public.
   Il fonctionne hors ligne et sans accès à NOORTRACE.

## Modèle d'événement

Huit champs, alignés sur le schéma proposé par le papier Agent Flight Recorder
([arXiv 2609.01931](https://arxiv.org/pdf/2609.01931)) :

| Champ | Contenu |
|---|---|
| Intention | Ce que l'agent déclare vouloir faire et pourquoi |
| Évaluation de politique | Règle appliquée, résultat : autorisé, à approuver, refusé |
| Approbation humaine | Décision, approbateur, instant, motif, le cas échéant |
| Exécution | Outil appelé, paramètres, réponse, durée |
| Effets | Ressources lues, écrites, supprimées, envoyées |
| Provenance du contexte | Documents, données et mémoire utilisés |
| Provenance du code | Version du modèle, du prompt système, de la politique, de l'enregistreur |
| Provenance de la délégation | Qui a lancé l'agent, pour le compte de qui, avec quels droits |

Format d'export : spans OpenTelemetry GenAI pour l'interopérabilité, reçus SCITT
(RFC 9943) pour les preuves d'inclusion, compatibilité visée avec le projet IETF
« agent audit trail ». Aucun format propriétaire.

## Ancrage et droit de la preuve

- L'horodatage électronique qualifié porte la présomption légale d'exactitude de la
  date et d'intégrité (art. 41(2) eIDAS). En Suisse, la ZertES définit l'horodatage
  qualifié par un prestataire reconnu. Swisscom Trust Services est le seul prestataire
  identifié sous les deux régimes.
- L'ancrage sur un registre public est complémentaire : il permet la vérification sans
  intermédiaire mais ne porte pas de présomption légale.
- NOORCHAIN, opérée par le fournisseur, ne peut pas servir d'ancre de confiance. Elle
  tient le registre des lots et des approbations, et doit rester substituable.
- La procédure est documentée pour satisfaire l'art. 9 GeBüV : signatures, horodatage,
  conservation des journaux et des logs du système.

## Instance dédiée

Décision du 20 octobre 2026 : NOORTRACE tourne sur une instance dédiée de noorcore,
distincte de la chaîne 2123 du PoSS.

- Identifiant de chaîne propre, validateurs propres, aucun contrat de jeton ni de
  récompense déployé.
- Un seul registre pour tous les clients ; chaque client est une organisation avec
  son jeu d'approbateurs. Aucune donnée métier sur la chaîne, seulement des racines.
- Les validateurs sont ouverts aux partenaires : un intégrateur ou un cabinet d'audit
  qui opère un validateur rend le registre moins dépendant du fournisseur.
- Un incident ou une mise à jour du PoSS ne touche pas les clients NOORTRACE, et la
  description du périmètre pour l'inventaire des externalisations reste simple.
- Pour le pilote, une instance de développement suffit ; la chaîne de production est
  arrêtée après le pilote.

Terminologie : « approbateur » désigne le rôle que les contrats de NOORCHAIN nomment
curateur. Le mécanisme est repris, le mot et la fonction sociale ne le sont pas.

## Déploiement

- Enregistreur et journal chez le client : sur site, dans son tenant cloud ou chez un
  hébergeur suisse. Seules les racines de lots sortent.
- Registre et console NOORTRACE : hébergés en Suisse. Rétention probatoire visée :
  10 ans, alignée sur l'art. 958f CO et l'art. 18 du Règlement IA.
- Vérificateur : binaire autonome, sans réseau, publié avec son code et ses vecteurs
  de test.

## Modèle de menace

| Menace | Réponse |
|---|---|
| L'agent efface ou falsifie ses traces | Journal en ajout seul, hors de son contexte d'exécution, chaîné et signé |
| L'opérateur réécrit l'historique après coup | Racines horodatées par un tiers qualifié : toute réécriture casse les preuves d'inclusion |
| Le fournisseur NOORTRACE triche ou disparaît | Vérification possible sans lui ; registre substituable ; format ouvert |
| Manipulation de l'horloge | Temps issu du jeton d'horodatage qualifié, pas de l'hôte |
| Fuite de données via les empreintes | Seules des racines de Merkle sortent du périmètre du client |

## Ce qui est réutilisé de noorchain-core

| Dépôt noorchain-core | Usage |
|---|---|
| `contracts/poss/AttestationRegistry.sol` | Registre des racines de lots et des approbations |
| `contracts/poss/CuratorSet.sol`, `CuratorSetRegistry.sol` | Jeux d'approbateurs par client, seuil, administration reprise par le client |
| `dapps/curators-hub` | Base de la console d'approbation et de revue |
| `docs/runbooks`, `ops/observability` | Exploitation du service |
| `core/` | Nœud du registre d'exploitation, inchangé |

## Décisions ouvertes

1. Granularité des événements et taille des lots : coût de l'horodatage contre finesse de la preuve.
2. Gestion des clés de l'enregistreur chez le client : HSM, TPM ou logiciel.
3. Politique de rédaction des paramètres sensibles avant journalisation.
4. Version 0 du format d'export, à figer après les trois premiers entretiens avec des réviseurs.
5. Identifiant de la chaîne de production et premiers validateurs partenaires, après le pilote.
