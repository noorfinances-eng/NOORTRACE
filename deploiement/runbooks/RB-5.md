<!-- Copie dérivée de CT-8 §10.16 (RB-5), spec/CT-8-deploiement-et-exploitation.md, tirée par scripts/deploiement/extraire-runbooks.mjs. Le texte normatif est celui de CT-8 : ne pas modifier ce fichier à la main. -->

### 10.16 RB-5 Perte d'une copie WORM

**EX-10.20** Une copie manque, diffère de l'original, n'est pas verrouillée
comme la configuration le dit, a une version inattendue, ou un gel n'est pas
posé. Ce runbook couvre une copie manquante, différente, mal verrouillée ou
non gelée ; la perte d'un support entier n'est couverte par aucun runbook en
version 0.1 (section 15).

- **Détection.** `noortrace_copie_worm_en_retard`,
  `noortrace_verrou_worm_non_conforme`,
  `noortrace_retention_support_non_conforme`, `noortrace_versions_inattendues`,
  `noortrace_gel_non_pose`, `noortrace_registre_gels_invalide`,
  `noortrace_releve_en_retard`, `noortrace_gel_pose_en_retard` ; lignes
  `worm_copy_failed`, `worm_lock_check`, `worm_lock_audit`,
  `worm_versions_unexpected`, `worm_legal_hold_observed`.
- **Impact sur la preuve.** L'original local reste la référence (CT-2
  EX-12.17) ; tant que la copie manque, la perte du volume local perd les
  segments non copiés ; une copie non verrouillée peut être supprimée ; la
  chaîne, ses signatures et ses ancres ne changent pas : tout dossier se
  revérifie (CT-6).
- **Invariants.** Ne jamais supprimer une version, même inattendue (elle
  est une pièce de l'incident) ; ne jamais employer un rôle de contournement
  de la rétention ; ne jamais lever un gel hors de la procédure d'EX-11.16.
- **Pas.**
  1. `noortrace-ctl worm releve` ; porte : ligne `worm_lock_audit` avec
     les clés en cause.
  2. Copie manquante : laisser la supervision la réessayer (CT-2 EX-12.16) ;
     porte : version inscrite au registre des copies avec le bon SHA-256.
  3. Copie différente de l'original : comparer les deux SHA-256 avec
     `verifier-journal.mjs` sur l'original et sur la version restaurée par
     `noortrace-ctl worm restaurer` ; porte :
     l'exemplaire qui vérifie est connu ; l'autre est une pièce de
     l'incident.
  4. Verrou ou rétention non conforme : corriger la configuration par
     défaut du support avec le rôle Administrateur du compte (CT-2 EX-18.9),
     jamais par l'écrivain ; porte : ligne `worm_lock_config_check`
     conforme.
  5. Gel non posé : reposer le gel par le gardien de pose (`noortrace-ctl
     worm gel poser`) ; porte : relecture d'EX-10.9 `registre_gels` à 1.
- **Vérification de sortie.** `noortrace_worm_copy_pending`,
  `noortrace_worm_lock_nonconforming` et `noortrace_worm_versions_unexpected`
  valent 0 au relevé suivant.
- **Événements journalisés.** `worm_copy_failed`, `worm_lock_check`,
  `worm_lock_audit`, `worm_versions_unexpected`, lignes de l'outil de gel ;
  aucun événement de la chaîne (CT-2 §9.1).
- **Après l'incident.** Une version inattendue ou un gel levé hors de
  l'outil est un incident de sécurité (RB-8) ; procès-verbal `restauration`
  si une copie a été réécrite à partir de l'original.
