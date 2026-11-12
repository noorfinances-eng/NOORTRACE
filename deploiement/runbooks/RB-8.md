<!-- Copie dérivée de CT-8 §10.19 (RB-8), spec/CT-8-deploiement-et-exploitation.md, tirée par scripts/deploiement/extraire-runbooks.mjs. Le texte normatif est celui de CT-8 : ne pas modifier ce fichier à la main. -->

### 10.19 RB-8 Suspicion de compromission de clé

**EX-10.23** Une clé ou un secret de l'inventaire de CT-7 §4.2 est soupçonné
compromis : par une alerte (`noortrace_relais_refuse`,
`noortrace_remise_refusee`, `noortrace_ancrage_volume`,
`noortrace_acces_non_declare`, une version WORM inattendue, un gel levé hors
de l'outil), ou par un signalement.

- **Détection.** Les règles ci-dessus ; un écart de la relecture d'EX-10.9 ;
  un accès au coffre ou aux copies par un principal non déclaré (11.10). Avant
  d'ouvrir ce runbook sur `noortrace_ancrage_volume`, ventiler
  `noortrace_anchoring_attempts_total` par prestataire et par issue : des
  succès en excès hors de toute panne relèvent de ce runbook ; des échecs
  vers un prestataire en panne suivis de succès de rattrapage relèvent de
  RB-4.
- **Impact sur la preuve.** Selon la clé : CT-7 EX-4.8 liste, clé par clé,
  ce qui peut être invalide (événements signés entre l'instant présumé et la
  rotation pour CLE-1 ; décisions signées pour CLE-3 ; jetons émis pour
  CLE-10).
- **Invariants.** La conduite est celle de CT-7 §4.6, dans son ordre ; CT-8
  n'en change aucun pas ; ne jamais restaurer une clé d'usage `enregistreur`,
  `chaine` ou `validateur` depuis une sauvegarde (CT-7 EX-4.4).
- **Pas.**
  1. Nommer la clé (CLE-n) et l'instant présumé ; porte : la ligne de la
     table de CT-7 EX-4.8 est choisie.
  2. Exécuter les pas de cette ligne ; pour CLE-1 : `noortrace-ctl cle
     rotation-urgence` (CT-2 EX-11.16) tant que la clé est
     utilisable ; porte : événement `noortrace.journal.rotation-cle` scellé et
     nouvelle clé inscrite au registre.
  3. Pour un secret CLE-11 à CLE-25 : révocation chez l'émetteur, nouveau
     secret écrit en place dans `secrets/<nom>` (même fichier, EX-11.12),
     puis `noortrace-ctl reload` ou redémarrage (CT-7 EX-4.8) ; porte : ligne
     `config_reloaded` avec le nouveau SHA-256 du document, ou, pour un
     secret qu'un rechargement ne relit pas, redémarrage par `$DC up -d
     --force-recreate <service>` et `/readyz` à `200`.
  4. Extraire du journal des consultations (11.10) et des journaux de
     l'émetteur les accès depuis l'instant présumé ; porte : liste jointe au
     paquet d'incident.
- **Vérification de sortie.** Les vérifications de CT-7 (procès-verbal de
  cérémonie de la nouvelle clé, CR-) passent ; le registre montre la
  révocation.
- **Événements journalisés.** `noortrace.journal.rotation-cle` dans la
  chaîne ; `config_reloaded` ; procès-verbal de cérémonie (CT-7 §5).
- **Après l'incident.** Exercice annuel de rotation d'urgence de CT-7 EX-3.12
  mis à jour ; information des réviseurs prévue par CT-7 EX-4.8.
