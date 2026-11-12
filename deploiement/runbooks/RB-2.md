<!-- Copie dérivée de CT-8 §10.13 (RB-2), spec/CT-8-deploiement-et-exploitation.md, tirée par scripts/deploiement/extraire-runbooks.mjs. Le texte normatif est celui de CT-8 : ne pas modifier ce fichier à la main. -->

### 10.13 RB-2 Bail perdu

**EX-10.17** L'instance active perd son bail, ou deux instances se disputent
un journal.

- **Détection.** `noortrace_bail_non_detenu`, `noortrace_bail_renouvellement`,
  `noortrace_fourche`, `noortrace_cle_mac_relais` ; lignes `lease_lost`,
  `lease_lost_after_write`, `lease_standby`, `journal_fork`,
  `relay_mac_key_mismatch`.
- **Impact sur la preuve.** Pendant au plus `lease.ttl_ms`, aucun écrivain ;
  les appels en vol deviennent des événements de reprise ; le segment ouvert
  d'un volume perdu est perdu s'il n'a pas été copié (CT-2 §13.5) ; une
  fourche donne deux événements signés de même `seq`, que la relecture
  suivante arrête (CT-2 EX-13.10).
- **Invariants.** Ne jamais rendre le bail à une instance qui n'a pas relu
  le journal ; ne jamais monter le volume sur deux hôtes (CT-2 EX-13.2).
- **Pas.**
  1. Identifier l'instance qui détient l'époque la plus haute :
     `noortrace_lease_epoch` par instance ; porte : une seule instance a une
     époque non nulle.
  2. Rendre le stockage de l'ancienne active inaccessible en écriture par le
     moyen de `lease.fencing` (détachement ou réservation, CT-2 EX-13.10)
     si la bascule ne l'a pas fait ; porte : l'ancien hôte ne voit plus le
     volume.
  3. Basculer l'adresse de service (moyen de la topologie, EX-3.11) vers
     la nouvelle active ; porte : `noortrace-ctl etat` rend `ok` sur le
     nouvel hôte, et `curl -fsS -m 3 -o /dev/null <adresse de service>/readyz`
     rend 0 depuis un hôte qui la joint (`etat` ne lit que le démon local, et
     `noortrace-ctl sonde` n'admet que la boucle locale).
  4. Si `journal_fork` : ne rien redémarrer avant d'avoir consigné la taille
     finale des fichiers d'époque inférieure et relu le journal ; porte :
     `verifier-journal.mjs` nomme le `seq` de la fourche.
  5. Si `relay_mac_key_mismatch` : corriger la référence du secret CLE-16
     sur la passive (même clé pour toutes les instances, CT-7 §4.2) puis
     redémarrer la passive ; porte : la passive est `standby` sans la ligne.
- **Vérification de sortie.** Une seule instance active, `role="active"`
  porte l'époque la plus haute, `verifier-journal.mjs` rend `valide`.
- **Événements journalisés.** `lease_acquired`, `lease_lost`,
  `lease_standby`, `journal_fork` ; dans la chaîne : événements de reprise
  des intentions (CT-2 12.5) ; un événement de politique au démarrage si
  l'ensemble a changé (CT-2 EX-9.2).
- **Après l'incident.** Une fourche est un incident de sécurité : paquet
  d'incident remis au client et aux réviseurs des journaux concernés ;
  procès-verbal `restauration` si le chemin B a servi.
