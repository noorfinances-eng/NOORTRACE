<!-- Copie dérivée de CT-8 §10.14 (RB-3), spec/CT-8-deploiement-et-exploitation.md, tirée par scripts/deploiement/extraire-runbooks.mjs. Le texte normatif est celui de CT-8 : ne pas modifier ce fichier à la main. -->

### 10.14 RB-3 Ancrage dégradé

**EX-10.18** Les ancres d'une période ou d'un point n'arrivent pas, ou la file
du composant d'ancrage est perdue.

- **Détection.** `noortrace_ancre_en_retard`, `noortrace_ancrage_en_attente`,
  `noortrace_ancrage_file`, `noortrace_ancrage_ots_abandon` ; lignes
  `anchor_pending`, `registry_pending`, `anchoring_queue_rebuilt`,
  `anchor_queue_*`.
- **Impact sur la preuve.** Rien ne bloque la capture (CT-2 §14.2, CT-5
  EX-4.8) ; les dossiers des périodes concernées n'ont pas encore leurs
  ancres ; sans l'ancre au registre, ils ne passent pas le contrôle 8 (CT-4
  EX-8.3, CT-6 EX-11.10) ; une file perdue ne fait perdre que du temps
  (CT-5 EX-8.12).
- **Invariants.** Ne jamais supprimer ni réécrire un fichier de la file
  (CT-5 EX-8.5) ; ne jamais créer à la main une demande.
- **Pas.**
  1. Lire `noortrace_anchoring_queue_entries` par sorte et état ; porte :
     la sorte en retard est connue.
  2. Si un prestataire est en cause : RB-4 ; si le registre : RB-7 ;
     porte : la cause est dans un autre runbook ou levée.
  3. Si la file est perdue ou tronquée : redémarrer le composant, qui
     confronte le stockage aux demandes et recrée celles qui manquent (CT-5
     EX-8.12) ; porte : ligne `anchoring_queue_rebuilt`. La clôture
     anticipée (`noortrace-ctl close-period --now`) n'est admise qu'en
     développement (CT-2 EX-19.4) : elle n'est jamais un pas de ce runbook.
- **Vérification de sortie.** `noortrace_anchor_pending` vaut 0 pour les
  trois ancres ; `noortrace_anchoring_window_s` revient sous `c_T`.
- **Événements journalisés.** `anchoring_started`, `anchoring_queue_rebuilt`,
  `anchor_retry`, `anchor_fallback`, `period_timestamped`, `ots_complete`.
- **Après l'incident.** Réexporter les dossiers des périodes concernées
  quand leurs ancres sont là (CT-5 EX-6.7), par `noortrace-ctl dossier
  exporter` vers des destinations neuves : un dossier exporté n'est jamais
  remplacé (CT-2 EX-15.13, point 4).
