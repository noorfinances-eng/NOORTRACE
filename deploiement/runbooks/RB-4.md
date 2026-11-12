<!-- Copie dérivée de CT-8 §10.15 (RB-4), spec/CT-8-deploiement-et-exploitation.md, tirée par scripts/deploiement/extraire-runbooks.mjs. Le texte normatif est celui de CT-8 : ne pas modifier ce fichier à la main. -->

### 10.15 RB-4 Prestataire d'horodatage injoignable

**EX-10.19** Le prestataire RFC 3161 principal, le secours ou tous les
calendriers OpenTimestamps ne répondent pas, ou un jeton est révoqué.

- **Détection.** `noortrace_ancrage_prestataire_injoignable`,
  `noortrace_ancrage_prestataires_epuises_*`, `noortrace_ancrage_revoque`,
  `noortrace_ancrage_reponse_tardive_promue`,
  `noortrace_ancrage_point_en_retard_*` ; enregistrements d'acquisition.
- **Impact sur la preuve.** La borne « au plus tard » de la période ou du
  point attend (`W_date`, CT-5 3.3) ; la relève au secours la rétablit
  (CT-5 EX-8.8) ; un jeton de période n'est jamais abandonné (CT-5 EX-4.5).
  Sans relève (`provider_role` `second_rang` ou `interne`, qui n'en ont
  pas, ou relève épuisée), une demande de jeton de point en erreur
  transitoire reste `a_reprendre` et passe `remplacee` dès qu'une échéance
  postérieure est satisfaite ; en erreur permanente, elle passe `refusee`
  et rend ses échéances (CT-5 EX-5.7, EX-8.8, §8.3). Après une longue
  panne, les événements de la panne sont couverts par le premier point
  contresigné au retour, qui les engage par préfixe (CT-5 P-3) : leur borne
  « au plus tard » est d'autant plus tardive. Défauts de CT-5 :
  `rfc3161.manifest.fallback_after_s` = 300,
  `rfc3161.checkpoints.fallback_after_s` = 120, `rfc3161.retry.max_ms` =
  300 000.
- **Invariants.** Ne jamais retirer une réponse conservée ; ne jamais
  promouvoir à la main un jeton.
- **Pas.**
  1. Vérifier la sortie réseau déclarée vers le prestataire (section 5) ;
     porte : connexion TLS établie depuis l'hôte du composant.
  2. Si le principal est seul en cause : laisser la relève jouer (CT-5
     EX-8.8) ; porte : `obtenue` chez le secours dans `fallback_after_s`.
  3. Si tous les prestataires d'une période échouent : changer de
     prestataire par la configuration `ancrage-v0` (réécriture en place,
     EX-11.12, puis redémarrage du composant, CT-5 EX-4.8) ; porte :
     `noortrace_anchoring_last_success_age_s` du nouveau prestataire baisse.
     Sans second contrat ni statut qualifié établi (le secours n'est que
     recommandé, EX-8.2), ce pas ne s'applique pas : attendre le retour du
     prestataire ; aucun jeton de période n'est abandonné (CT-5 EX-4.5), et la
     durée de l'attente est consignée au paquet d'incident.
  4. Si `revoque` : la demande repart au secours (CT-5 révision 0.2) ;
     informer les réviseurs des journaux concernés (CT-7 §4.6, ligne
     CLE-10 pour le serveur interne) ; porte : nouveau jeton promu.
- **Vérification de sortie.** Aucune demande `jeton_*` en `a_reprendre`
  depuis plus de `retry.max_ms`.
- **Événements journalisés.** `anchor_retry`, `anchor_fallback`,
  `anchor_response_rejected`, `period_timestamped`.
- **Après l'incident.** Réexport des dossiers ; si le prestataire est
  qualifié et que le statut a changé, réétablissement de `qualified`
  (EX-11.24). La relève et le rattrapage font dépasser à
  `noortrace_anchoring_attempts_total` deux fois le volume nominal : une
  alerte `noortrace_ancrage_volume` pendant ou juste après l'incident relève
  de ce runbook, non de RB-8, quand la ventilation par prestataire et par
  issue montre des échecs vers le prestataire en panne suivis de succès de
  rattrapage (10.5).
