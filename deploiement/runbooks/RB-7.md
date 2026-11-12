<!-- Copie dérivée de CT-8 §10.18 (RB-7), spec/CT-8-deploiement-et-exploitation.md, tirée par scripts/deploiement/extraire-runbooks.mjs. Le texte normatif est celui de CT-8 : ne pas modifier ce fichier à la main. -->

### 10.18 RB-7 RPC du registre injoignable

**EX-10.22** Le point RPC du registre (validateur joignable ou relais) ne
répond plus, la chaîne n'avance plus, ou une double signature est vue.

- **Détection.** `noortrace_registre_cible_muette`, `noortrace_registre_sonde`,
  `noortrace_registre_hauteur_figee`, `noortrace_registre_equivocation`,
  `noortrace_registre_cloture_non_soumise`,
  `noortrace_registre_capture_en_retard`, `noortrace_registre_mempool`,
  `noortrace_registre_sous_tarif`, `noortrace_registre_marge_retention`,
  `noortrace_ancrage_empreinte_squattee` ; ligne `registry_pending`.
- **Impact sur la preuve.** Le registre ne bloque jamais l'enregistreur
  (CT-4 EX-8.1) ; le contrôle 8 des dossiers des périodes non soumises
  attend (CT-4 EX-8.3) ; une capture faite trop tard perd le certificat
  hors de la fenêtre de rétention du validateur (CT-4 EX-9.4, EX-9.6).
- **Invariants.** Ne jamais restaurer le répertoire de données ni l'état de
  consensus d'un validateur depuis une sauvegarde (CT-4 EX-10.9) ; ne jamais
  soumettre une ancre ni capturer par un relais (CT-4 EX-10.5) ;
  `-bft-recovery-reset` n'existe qu'en profil de développement (CT-4 §13).
- **Pas.**
  1. Sonder `eth_blockNumber` à travers chaque point déclaré (sonde
     d'EX-10.7, à produire, section 15) ; porte : le point en cause est
     connu.
  2. Relais : redémarrer le conteneur du relais (image et Compose de
     `chain/docker`, EX-3.6) ; porte : `noortrace_registre_sonde_ok` à 1.
  3. Validateur du client injoignable : la soumission continue vers les
     autres validateurs de `--rpc`, qui reçoivent les mêmes octets (au moins
     deux validateurs d'opérateurs distincts en production, CT-4 EX-8.15) ;
     porte : `registry_pending` cesse.
  4. Hauteur figée sur tous les points : prévenir l'exploitant du registre
     (CT-4 §10) ; porte : accusé de réception.
  5. Équivocation : incident du registre ; conserver les preuves et les
     transmettre (CT-4 EX-10.8, §14) ; porte : paquet d'incident transmis.
  6. Empreinte prise au registre : suivre CT-4 §8.3 ; porte : décision
     consignée.
- **Vérification de sortie.** Hauteur qui avance, `registry_pending` absent
  depuis une période, captures faites dans l'heure.
- **Événements journalisés.** `registry_pending`, lignes de l'outil du
  registre (sorties `operations-registre-v0`).
- **Après l'incident.** Capturer les blocs encore dans la fenêtre de
  rétention ; consigner ceux qui en sont sortis (le certificat n'est plus
  récupérable auprès de ce nœud, CT-4 §9.5).
