<!-- Copie dérivée de CT-8 §10.12 (RB-1), spec/CT-8-deploiement-et-exploitation.md, tirée par scripts/deploiement/extraire-runbooks.mjs. Le texte normatif est celui de CT-8 : ne pas modifier ce fichier à la main. -->

### 10.12 RB-1 Écrivain arrêté

**EX-10.16** Le démon n'écrit plus : stockage indisponible, disque plein,
segment corrompu, démon arrêté.

- **Détection.** `noortrace_mode_degrade_majeur` (raison `stockage` ou
  `attente`), `noortrace_disque_*`, `noortrace_attente_*`,
  `noortrace_controle_integrite`, `noortrace_pieces_attente_perdues`,
  `noortrace_export_lecture_impossible` ; lignes
  `storage_unavailable`, `segment_corrupted`, `segment_truncated`, `disk_low`,
  `pending_limit_reached`, `pending_pieces_lost`, `dossier_export_refused` de
  raison `lecture_impossible` (CT-2 EX-15.12) ; `noortrace-ctl etat`
  muet (code 4, CT-2 EX-15.17).
- **Impact sur la preuve.** Aucun appel d'écriture n'est relayé sans
  événement durable (CT-2 EX-14.2) ; les lectures passantes ont des
  événements en attente, scellés plus tard avec leur `ts` de capture (CT-2
  EX-14.10) ; au-delà des bornes de CT-2 EX-14.9, les lectures sont bloquées
  aussi. En mode observation (section 12), rien n'est bloqué et les
  événements au-delà des bornes sont perdus et comptés (CT-2 EX-14.16). Si
  le démon s'est arrêté pendant le mode dégradé avant d'écrire les pièces
  qu'il gardait en mémoire, chaque événement relu dont une pièce manque est
  scellé au redémarrage en erreur, références gardées, et son dossier déclare
  ces pièces absentes comme des pièces purgées : leur contenu ne pourra jamais
  être produit (CT-2 EX-14.18).
- **Invariants.** Ne jamais modifier, tronquer ni supprimer à la main une
  ligne d'un segment ; ne jamais copier un segment de la copie WORM
  par-dessus l'original ; ne jamais lancer un second démon sur le même
  répertoire.
- **Pas.**
  1. `noortrace-ctl etat` ; porte : la raison est connue (`stockage`,
     `attente`) ou le démon ne répond pas.
  2. Si `disk_low` : libérer ou agrandir le volume, jamais en supprimant un
     fichier sous `storage.root` ; porte : espace libre ≥ 2 ×
     `min_free_bytes`.
  3. Si `segment_corrupted` (CT-2 EX-12.11) : arrêter le démon, placer le
     répertoire du journal hors service (renommage), puis appliquer la reprise
     de 11.4 chemin B (désigné ici, sans passer d'abord par le chemin A :
     l'archive quotidienne du chemin A est prise sur l'original local, dont un
     segment est corrompu, et peut porter la corruption, alors que chaque
     version WORM a été copiée à la fermeture de son segment et inscrite au
     registre des copies avec son SHA-256, CT-2 EX-12.16 et EX-12.29, ce qui se
     contrôle fichier par fichier, RB-5 pas 2) ; les intentions, l'attente, les
     approbations et les pièces sans `copy_pieces`, qui n'ont pas de copie WORM,
     sont alors perdues et listées au procès-verbal `restauration` ; porte :
     `verifier-journal.mjs` rend `valide` sur le répertoire reconstruit.
  4. Redémarrer ; porte : `noortrace-ctl etat` rend `ok`, la ligne
     `pending_flushed` est consignée si des événements attendaient ; si la
     ligne `pending_pieces_lost` l'est aussi, ses `seq` et son nombre de
     pièces absentes vont au paquet d'incident (EX-10.15).
  5. Exporter, une fois sa période close (sinon `periode_non_close`, CT-2
     EX-15.11), et vérifier le dossier du premier événement scellé après la
     reprise : `noortrace-ctl dossier exporter --seq <n> --vers
     /var/lib/noortrace-exports/<incident>-<n>` (CT-2 EX-15.9) ; porte : code
     0 de l'export, et `dossier.mjs` rend le code 0.
- **Vérification de sortie.** `noortrace_degraded` vaut 0 pour toutes les
  raisons, `noortrace_pending_events` vaut 0, `verifier-journal.mjs` rend
  `valide`.
- **Événements journalisés.** `degraded_enter`, `degraded_exit`,
  `storage_unavailable`, `segment_truncated` ou `segment_corrupted`,
  `pending_flushed`, `pending_pieces_lost` ; dans la chaîne : événements de reprise et événements
  en attente (CT-2 EX-9.8), jamais un événement « panne » (CT-2 EX-14.7).
- **Après l'incident.** Procès-verbal `restauration` si le chemin B a servi
  (11.9) ; cause du disque plein rapprochée du dimensionnement (section 9).
