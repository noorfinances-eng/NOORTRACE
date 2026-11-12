<!-- Copie dérivée de CT-8 §10.17 (RB-6), spec/CT-8-deploiement-et-exploitation.md, tirée par scripts/deploiement/extraire-runbooks.mjs. Le texte normatif est celui de CT-8 : ne pas modifier ce fichier à la main. -->

### 10.17 RB-6 Saut d'horloge

**EX-10.21** L'horloge de l'hôte recule au-delà de `clock.max_backstep_ms` ou
avance brutalement au-delà de `clock.max_forward_ms`, ou un prestataire
signale une horloge suspecte.

- **Détection.** `noortrace_mode_degrade_critique` (raison `horloge`),
  `noortrace_horloge_ecart`, `noortrace_ancrage_horloge_suspecte`,
  `noortrace_ancrage_jeton_anterieur` ; lignes `clock_backstep`,
  `clock_forward_jump`, `clock_skew`.
- **Impact sur la preuve.** Tout est bloqué (CT-2 §14.2) sauf en mode
  observation, où rien ne l'est mais où aucun `ts` n'est posé dans le futur
  (CT-2 EX-14.14) ; `ts` reste non décroissant ; les ancres extérieures
  bornent l'écart (CT-5 3.3).
- **Invariants.** Ne jamais régler l'horloge à la main vers l'arrière ; ne
  jamais employer `noortrace-ctl clock --accept` sans avoir établi l'heure
  par une source extérieure.
- **Pas.**
  1. Lire l'état de synchronisation de l'hôte (`chronyc -c tracking` ou
     `timedatectl`, R9-F41, R9-F44 ; à défaut l'appel `adjtimex(2)`, dont la
     valeur 5 signifie « clock not synchronized », R9-F46) ; porte : la
     source de temps est synchronisée.
  2. Comparer à une seconde source (horloge du magasin de bail, CT-2
     EX-7.13 ; `genTime` du dernier jeton) ; porte : l'écart est expliqué.
  3. Attendre le retour dans la tolérance, ou confirmer par
     `noortrace-ctl clock --accept` (consigné) ; porte : sortie du mode
     dégradé « horloge ».
- **Vérification de sortie.** `noortrace_degraded{reason="horloge"}` vaut 0 et
  `abs(noortrace_clock_skew_ms)` est sous `warn_skew_ms`.
- **Événements journalisés.** `clock_backstep`, `clock_forward_jump`,
  `clock_skew`, la confirmation ; aucun événement de la chaîne (CT-7 JS-8).
- **Après l'incident.** Rapprocher l'intervalle des jetons RFC 3161 de la
  période ; si l'horloge a été falsifiée, RB-8.
