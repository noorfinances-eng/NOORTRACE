# Vecteurs CT-8 — déploiement et exploitation

Produit par `scripts/vecteurs/generer-ct8.mjs` (`npm run vecteurs:ct8`) ; ne pas
l'éditer à la main. Spécification :
[`spec/CT-8-deploiement-et-exploitation.md`](../../CT-8-deploiement-et-exploitation.md),
annexe A.

Le générateur lit les vecteurs de CT-1, CT-3, CT-4, CT-6 et CT-7 et les
fichiers de référence de `deploiement/` sans jamais les réécrire (EX-A.2). Il
n'écrit ni n'efface `confrontation/` ni `verificateur-independant/`. Deux
exécutions donnent des fichiers identiques (EX-A.1).

Familles de cette génération :
`conteneurs/`,
`controle-prealable/`,
`dimensionnement/`,
`observation/`,
`journaux/`,
`proces-verbaux/`,
`consultations/`,
`acceptation-exploitation/`, `acceptation-observation/`,
`paquets/`.

```bash
npm run vecteurs:ct8
npm run deploiement:conteneurs   # code 0
node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/valide.tar   # code 0
node scripts/deploiement/verifier-journal.mjs spec/vecteurs/ct-8/journaux/valide --cles spec/vecteurs/ct-8/journaux/valide/cles.json   # code 0
```

## conteneurs

Fichiers Compose de CT-8 §4 confrontés à la description des images, annexe
A.3. `images.json` est la copie de `deploiement/images/images.json` ; chaque
cas a son fichier `<cas>.yaml` et `<cas>.attendu.json` (schéma
`conteneurs-v0#/$defs/cas`), dont `attendu` est le rapport exact de
`scripts/deploiement/verifier-conteneurs.mjs`, SHA-256 du fichier compris.
Chaque cas invalide est un fichier de référence dont une seule chaîne est
remplacée, et qui échoue à une seule vérification.

Commande de chaque cas, depuis la racine du dépôt (code 0 pour un fichier
conforme, 1 sinon) :

```bash
node scripts/deploiement/verifier-conteneurs.mjs spec/vecteurs/ct-8/conteneurs/<cas>.yaml \
  --images spec/vecteurs/ct-8/conteneurs/images.json --json
```

| Cas | Ce qui change | Code | Verdict | Vérification en échec |
|---|---|---|---|---|
| `valide-rapide` | Fichier de référence deploiement/compose/rapide.yaml, sans changement : conforme. | 0 | `conforme` | — |
| `valide-production` | Fichier de référence deploiement/compose/production.yaml, sans changement : conforme. | 0 | `conforme` | — |
| `valide-production-condenses` | production.yaml dont chaque image noortrace/* est complétée par @sha256: suivi de 32 fois « ab » (condensé fictif, jamais celui d'une image) : conforme, toutes les images par condensé. | 0 | `conforme` | — |
| `yaml-cle-dupliquee` | Clé user répétée dans le service enregistreur : le YAML ne s'analyse pas sans ambiguïté (CO-1, yaml_invalide). | 1 | `non_conforme` | CO-1 (— : `yaml_invalide`) |
| `service-non-decrit` | Service verificateur renommé inconnu, absent de images.json (CO-1, service_non_decrit). | 1 | `non_conforme` | CO-1 (inconnu : `service_non_decrit`) |
| `image-latest` | Image noortrace/enregistreur:latest, étiquette mutable (CO-2). | 1 | `non_conforme` | CO-2 (enregistreur : `image_non_epinglee`) |
| `image-sans-etiquette` | Image noortrace/enregistreur sans étiquette ni condensé (CO-2). | 1 | `non_conforme` | CO-2 (enregistreur : `image_non_epinglee`) |
| `construction-presente` | Clé build: . ajoutée au service enregistreur (CO-3). | 1 | `non_conforme` | CO-3 (enregistreur : `construction_presente`) |
| `utilisateur-root` | Service enregistreur sous le compte 0:0 (CO-4, utilisateur_non_conforme). | 1 | `non_conforme` | CO-4 (enregistreur : `utilisateur_non_conforme`) |
| `utilisateur-absent` | Clé user retirée du service enregistreur : le compte serait celui de l'image (CO-4, utilisateur_absent). | 1 | `non_conforme` | CO-4 (enregistreur : `utilisateur_absent`) |
| `racine-inscriptible` | read_only: false pour le service enregistreur : racine inscriptible (CO-5). | 1 | `non_conforme` | CO-5 (enregistreur : `racine_inscriptible`) |
| `capacite-ajoutee` | cap_add: [NET_ADMIN] pour le service enregistreur, capacité absente de sa description (CO-6). | 1 | `non_conforme` | CO-6 (enregistreur : `capacite_ajoutee`) |
| `sans-no-new-privileges` | security_opt retiré du service enregistreur : no-new-privileges absent (CO-7). | 1 | `non_conforme` | CO-7 (enregistreur : `privileges_non_bloques`) |
| `privilegie` | privileged: true pour le service enregistreur (CO-8). | 1 | `non_conforme` | CO-8 (enregistreur : `cle_interdite_privileged`) |
| `reseau-hote` | network_mode: host pour le service approbation (CO-8, reseau_hote). | 1 | `non_conforme` | CO-8 (approbation : `reseau_hote`) |
| `secret-en-environnement` | Variable NOORTRACE_TOKEN_HOTE posée dans l'environnement du service enregistreur : un secret en clair (CO-9). | 1 | `non_conforme` | CO-9 (enregistreur : `variable_non_decrite`, enregistreur : `secret_en_environnement`) |
| `secret-hors-repertoire` | Secret de premier niveau cle-mac-relais lu dans /etc/noortrace, hors de ./secrets/ (CO-9, secret_hors_repertoire). | 1 | `non_conforme` | CO-9 (— : `secret_hors_repertoire`) |
| `port-toutes-interfaces` | Port 8300 publié sans adresse, donc sur toutes les interfaces de l'hôte (CO-10). | 1 | `non_conforme` | CO-10 (enregistreur : `port_toutes_interfaces`) |
| `port-non-decrit` | Port 9999 publié, absent de la description du service enregistreur (CO-10, port_non_decrit). | 1 | `non_conforme` | CO-10 (enregistreur : `port_non_decrit`) |
| `socket-du-moteur` | Montage lié de la prise du moteur /var/run/docker.sock dans le service enregistreur (CO-11, montage_interdit). | 1 | `non_conforme` | CO-11 (enregistreur : `montage_interdit`) |
| `configuration-inscriptible` | read_only retiré du montage de la configuration, décrite en lecture seule (CO-11, volume_inscriptible). | 1 | `non_conforme` | CO-11 (enregistreur : `volume_inscriptible`) |
| `sonde-par-interpreteur` | Sonde du service enregistreur en CMD-SHELL, qui passe par /bin/sh (CO-12, sonde_non_conforme). | 1 | `non_conforme` | CO-12 (enregistreur : `sonde_non_conforme`) |
| `dependance-sans-condition` | depends_on de l'enregistreur de production.yaml en forme courte (- approbation), sans condition d'état sain (CO-12, dependance_sans_condition). | 1 | `non_conforme` | CO-12 (enregistreur : `dependance_sans_condition`) |
| `outil-redemarre` | restart: unless-stopped pour l'outil verificateur, qui redémarrerait en boucle (CO-13). | 1 | `non_conforme` | CO-13 (verificateur : `redemarrage_non_conforme`) |
| `verificateur-en-reseau` | Réseau sortie donné au verificateur, qui n'a pas de réseau (CO-14, reseau_attendu_aucun). | 1 | `non_conforme` | CO-14 (verificateur : `reseau_attendu_aucun`) |
| `reseau-outils-non-interne` | Réseau outils de production.yaml déclaré outils: {}, non interne (CO-14, reseau_non_interne). | 1 | `non_conforme` | CO-14 (— : `reseau_non_interne`) |
| `services-vides` | Clé services vide : aucun service à vérifier (CO-1, services_absents) ; CO-2 à CO-14 non exécutées (prerequis_en_echec). | 1 | `non_conforme` | CO-1 (— : `services_absents`) |
| `inclusion-refusee` | Clé include de premier niveau, qui chargerait un fichier non examiné (CO-1, cle_premier_niveau_non_admise) ; CO-2 à CO-14 non exécutées (prerequis_en_echec). | 1 | `non_conforme` | CO-1 (— : `cle_premier_niveau_non_admise`) |
| `groupe-absent` | group_add retiré de l'enregistreur : le compte n'aurait pas le groupe 10010 du répertoire des prises (CO-4, groupe_non_conforme). | 1 | `non_conforme` | CO-4 (enregistreur : `groupe_non_conforme`) |
| `confinement-retire` | seccomp:unconfined ajouté au security_opt de l'enregistreur : filtre des appels système retiré (CO-7, confinement_desactive). | 1 | `non_conforme` | CO-7 (enregistreur : `confinement_desactive`) |
| `extension-de-service` | Clé extends dans l'enregistreur, qui importerait les clés d'un service non examiné (CO-8, cle_interdite_extends). | 1 | `non_conforme` | CO-8 (enregistreur : `cle_interdite_extends`) |
| `variable-non-decrite` | Variable LANG posée dans l'environnement de l'enregistreur, hors de la liste fermée de sa description (CO-9, variable_non_decrite). | 1 | `non_conforme` | CO-9 (enregistreur : `variable_non_decrite`) |
| `secret-en-ligne-de-commande` | Option --jeton suivie d'une valeur en clair, et non d'un chemin /run/secrets/, sur la ligne de commande du service approbation (CO-9, secret_en_ligne_de_commande). | 1 | `non_conforme` | CO-9 (approbation : `secret_en_ligne_de_commande`) |
| `secret-partage-entre-comptes` | La console (compte 10003) reçoit le fichier jeton-console-vers-service-approbation du service (compte 10002) : un fichier n'a qu'un propriétaire, l'un des deux ne pourrait pas le lire (CO-9, secret_partage_entre_comptes et secret_non_decrit). | 1 | `non_conforme` | CO-9 (console : `secret_non_decrit`, console : `secret_partage_entre_comptes`) |
| `montage-remontee` | Source de montage lié ./config/../../../../var/run/docker.sock : un préfixe admis suivi de « .. » mène à la prise du moteur (CO-11, montage_interdit). | 1 | `non_conforme` | CO-11 (enregistreur : `montage_interdit`) |
| `volume-lie-hote` | Volume nommé journal défini par driver_opts (type none, o bind, device /) : un montage de la racine de l'hôte sous un nom de volume (CO-11, volume_lie_hote). | 1 | `non_conforme` | CO-11 (— : `volume_lie_hote`) |

## controle-prealable

Évaluation du contrôle préalable de CT-8 §6, annexe A.4. Chaque
`<cas>.json` (schéma `controle-prealable-v0#/$defs/cas`) porte le profil,
les observations d'un hôte (celles de 6.3, ou leur variante de production :
8 processeurs, 16 Gio, 1 200 Gio libres, ports publiés sur `192.0.2.40`, images
par condensé, cache déclaré), le seuil d'espace (`storage_free_min_bytes`)
ou la liste `only` quand le cas les fixe, et le rapport attendu. Chaque cas
change un relevé.

Commande de chaque cas (`--observations` admet un fichier de cas : ses
observations, son seuil et sa liste `only` sont repris) ; la sortie `--json`
égale `attendu`, et le code de sortie est `attendu.exit_code` :

```bash
node scripts/deploiement/controle-prealable.mjs --profil <profil> \
  --observations spec/vecteurs/ct-8/controle-prealable/<cas>.json --json
```

| Cas | Profil | Ce qui change | Code | Verdict | Vérifications non réussies |
|---|---|---|---|---|---|
| `pret-rapide` | `rapide` | Observations de 6.3, sans changement : prêt avec avertissement, IP-13 non exécutée faute de déclaration du cache, non bloquante en rapide. | 0 | `pret_avec_avertissements` | IP-13 `non_execute` (`declaration_absente`), non bloquante |
| `pret-production` | `production` | Variante de production, seuil d'espace égal à local_bytes de l'exemple de 9.5 : prêt. | 0 | `pret` | — |
| `architecture-non-prise-en-charge` | `rapide` | Architecture ia32 au lieu de x64 : IP-1 échoue. | 1 | `non_pret` | IP-1 `echoue` (`architecture_non_prise_en_charge`) ; IP-13 `non_execute` (`declaration_absente`), non bloquante |
| `memoire-insuffisante` | `rapide` | 2 Gio de mémoire, sous la cible de 4 Gio : IP-2 échoue. | 1 | `non_pret` | IP-2 `echoue` (`memoire_insuffisante`) ; IP-13 `non_execute` (`declaration_absente`), non bloquante |
| `espace-insuffisant` | `production` | Seuil d'espace de 2 000 Gio, au-delà des 1 200 Gio libres : IP-3 échoue. | 1 | `non_pret` | IP-3 `echoue` (`espace_insuffisant`) |
| `production-sans-dimensionnement` | `production` | Production sans dimensionnement : IP-3 non exécutée (dimensionnement_absent), bloquante. | 1 | `non_pret` | IP-3 `non_execute` (`dimensionnement_absent`) |
| `stockage-nfs` | `rapide` | Stockage sur nfs4, système de fichiers refusé : IP-4 échoue. | 1 | `non_pret` | IP-4 `echoue` (`systeme_de_fichiers_refuse`) ; IP-13 `non_execute` (`declaration_absente`), non bloquante |
| `systeme-de-fichiers-non-eprouve` | `rapide` | Stockage sur zfs, ni admis ni refusé : IP-4 en avertissement. | 0 | `pret_avec_avertissements` | IP-4 `avertissement` (`systeme_de_fichiers_non_eprouve`) ; IP-13 `non_execute` (`declaration_absente`), non bloquante |
| `horloge-non-synchronisee-rapide` | `rapide` | Horloge non synchronisée en rapide : IP-5 échoue, non bloquante. | 0 | `pret_avec_avertissements` | IP-5 `echoue` (`horloge_non_synchronisee`), non bloquante ; IP-13 `non_execute` (`declaration_absente`), non bloquante |
| `horloge-non-synchronisee-production` | `production` | Horloge non synchronisée en production (timedatectl) : IP-5 échoue, bloquante. | 1 | `non_pret` | IP-5 `echoue` (`horloge_non_synchronisee`) |
| `horloge-ecart-trop-grand` | `production` | Borne d'erreur de l'horloge de 2 500 ms, au-delà de clock.warn_skew_ms (1 000) : IP-5 échoue (ecart_trop_grand). | 1 | `non_pret` | IP-5 `echoue` (`ecart_trop_grand`) |
| `horloge-sans-outil-production` | `production` | Aucun outil de synchronisation trouvé en production : IP-5 non exécutée, bloquante. | 1 | `non_pret` | IP-5 `non_execute` (`outil_absent`) |
| `horloge-borne-inconnue-production` | `production` | Horloge synchronisée selon timedatectl, sans borne d'erreur connue : IP-5 en avertissement (borne_inconnue), qui n'est pas un échec. | 0 | `pret_avec_avertissements` | IP-5 `avertissement` (`borne_inconnue`) |
| `horloge-non-relevee` | `production` | Horloge non relevée (clock null) : IP-5 non exécutée (mesure_absente), bloquante en production. | 1 | `non_pret` | IP-5 `non_execute` (`mesure_absente`) |
| `port-occupe` | `rapide` | Port 8500 de 127.0.0.1 déjà occupé : IP-6 échoue. | 1 | `non_pret` | IP-6 `echoue` (`port_occupe`) ; IP-13 `non_execute` (`declaration_absente`), non bloquante |
| `adresse-toutes-interfaces` | `production` | NOORTRACE_IP_INTERNE vaut 0.0.0.0 : les ports de production seraient publiés sur toutes les interfaces (IP-6, adresse_toutes_interfaces). | 1 | `non_pret` | IP-6 `echoue` (`adresse_toutes_interfaces`) |
| `adresse-hors-hote` | `production` | NOORTRACE_IP_INTERNE n'est l'adresse d'aucune interface de l'hôte (IP-6, adresse_hors_hote). | 1 | `non_pret` | IP-6 `echoue` (`adresse_hors_hote`) |
| `nom-non-resolu` | `rapide` | Serveur d'outils outils.interne.example non résolu : IP-7 échoue, et IP-8 (dns). | 1 | `non_pret` | IP-7 `echoue` (`nom_non_resolu`) ; IP-8 `echoue` (`dns`) ; IP-13 `non_execute` (`declaration_absente`), non bloquante |
| `sortie-bloquee` | `rapide` | Calendrier a.pool.opentimestamps.org en délai : IP-8 échoue (delai). | 1 | `non_pret` | IP-8 `echoue` (`delai`) ; IP-13 `non_execute` (`declaration_absente`), non bloquante |
| `tls-refuse` | `production` | Poignée de main TLS refusée vers api.anthropic.com : IP-8 échoue (tls). | 1 | `non_pret` | IP-8 `echoue` (`tls`) |
| `mandataire-non-declare` | `production` | HTTPS_PROXY posé sans --mandataire : IP-9 en avertissement, qui n'est pas un échec. | 0 | `pret_avec_avertissements` | IP-9 `avertissement` (`mandataire_incoherent`) |
| `secret-lisible-par-le-groupe` | `rapide` | Secret cle-enregistreur en 0440, lisible par le groupe : IP-10 échoue (secrets_lisibles). | 1 | `non_pret` | IP-10 `echoue` (`secrets_lisibles`) ; IP-13 `non_execute` (`declaration_absente`), non bloquante |
| `configuration-lisible-par-autrui` | `rapide` | Configuration en 0444 : IP-10 échoue (configuration_lisible_par_autrui). | 1 | `non_pret` | IP-10 `echoue` (`configuration_lisible_par_autrui`) ; IP-13 `non_execute` (`declaration_absente`), non bloquante |
| `secret-mauvais-proprietaire` | `rapide` | Secret cle-mac-relais propriété du compte 1000 au lieu de 10001 : IP-10 échoue (secret_proprietaire_incorrect). | 1 | `non_pret` | IP-10 `echoue` (`secret_proprietaire_incorrect`) ; IP-13 `non_execute` (`declaration_absente`), non bloquante |
| `secret-mode-non-conforme` | `rapide` | Secret jeton-hote en 0700 : ni 0400 ni 0600, même sans droit de groupe ni d'autrui (IP-10, secret_mode_non_conforme). | 1 | `non_pret` | IP-10 `echoue` (`secret_mode_non_conforme`) ; IP-13 `non_execute` (`declaration_absente`), non bloquante |
| `secret-partage-entre-comptes` | `production` | Fichier de secret jeton-console-vers-service qu'admettent des services de comptes différents : un fichier n'a qu'un propriétaire (IP-10, secret_partage_entre_comptes). | 1 | `non_pret` | IP-10 `echoue` (`secret_partage_entre_comptes`) |
| `configuration-mauvais-proprietaire` | `rapide` | Configuration en 0400 propriété du compte 0 au lieu de 10001 (IP-10, configuration_proprietaire_incorrect). | 1 | `non_pret` | IP-10 `echoue` (`configuration_proprietaire_incorrect`) ; IP-13 `non_execute` (`declaration_absente`), non bloquante |
| `execute-par-root-admis` | `rapide` | Outil lancé sous le compte 0 (sudo, pas IR-4) : admis, prêt avec le seul avertissement d'IP-13. | 0 | `pret_avec_avertissements` | IP-13 `non_execute` (`declaration_absente`), non bloquante |
| `compose-absent` | `rapide` | docker compose version en échec : IP-11 échoue (compose_absent). | 1 | `non_pret` | IP-11 `echoue` (`compose_absent`) ; IP-13 `non_execute` (`declaration_absente`), non bloquante |
| `conteneurs-non-conformes` | `rapide` | Fichier Compose dont CO-5 échoue : IP-12 échoue. | 1 | `non_pret` | IP-12 `echoue` (`conteneurs_non_conformes`) ; IP-13 `non_execute` (`declaration_absente`), non bloquante |
| `images-sans-condense-production` | `production` | Une image sans condensé en production : IP-12 échoue (condense_requis). | 1 | `non_pret` | IP-12 `echoue` (`condense_requis`) |
| `cache-non-declare-production` | `production` | Aucune déclaration du cache d'écriture en production : IP-13 échoue. | 1 | `non_pret` | IP-13 `echoue` (`declaration_absente`) |
| `systeme-seulement-production` | `production` | Production, --seulement IP-1,IP-2,IP-4,IP-5,IP-6,IP-11,IP-13 (pas IC-5) : les six autres non demandées, non bloquantes ; prêt avec avertissements. | 0 | `pret_avec_avertissements` | IP-3 `non_execute` (`non_demandee`), non bloquante ; IP-7 `non_execute` (`non_demandee`), non bloquante ; IP-8 `non_execute` (`non_demandee`), non bloquante ; IP-9 `non_execute` (`non_demandee`), non bloquante ; IP-10 `non_execute` (`non_demandee`), non bloquante ; IP-12 `non_execute` (`non_demandee`), non bloquante |

## dimensionnement

Calculateur de CT-8 §9, annexe A.5 : les seize cas de 9.6, qui font varier
l'exemple de 9.5 un paramètre à la fois. Chaque `<cas>.json` (schéma
`dimensionnement-v0#/$defs/cas`) porte les entrées et la sortie exacte
(`attendu`).

Commande de chaque cas (`--entrees` admet un fichier de cas : ses `entrees`
sont reprises) ; la sortie `--json` égale `attendu`, code 0, ou 1 pour un
refus d'EX-9.3 :

```bash
node scripts/deploiement/dimensionner.mjs --entrees spec/vecteurs/ct-8/dimensionnement/<cas>.json --json
```

| Cas | Ce qui change | Code | `local_bytes` (Gio) | `worm_bytes` (Gio) | Jetons qualifiés / autres par an | Transactions par heure ; part |
|---|---|---|---|---|---|---|
| `reference` | Exemple de 9.5, sans changement. | 0 | 967,655 | 806,888 | 8 760 / 96 360 | 63 ; 0,000249 |
| `sans-worm` | Aucun support WORM (storage.worm = null). | 0 | 967,655 | 0 | 8 760 / 96 360 | 63 ; 0,000249 |
| `deux-copies-worm-et-pieces` | Deux copies WORM sur des supports distincts, pièces copiées. | 0 | 967,655 | 2 055,207 | 8 760 / 96 360 | 63 ; 0,000249 |
| `points-chez-principal` | Points contresignés par le prestataire principal (provider_role = principal). | 0 | 967,655 | 806,888 | 105 120 / 0 | 63 ; 0,000249 |
| `contresignature-a-la-minute` | Contresignature à la minute (c_T = 60) par le prestataire principal. | 0 | 1 007,066 | 850,273 | 525 600 / 0 | 63 ; 0,000249 |
| `ots-mi-periode` | Preuve OpenTimestamps d'un point à mi-période. | 0 | 967,674 | 806,909 | 8 760 / 96 360 | 63 ; 0,000249 |
| `sans-ancre-des-points` | Aucune ancre des points au registre (registry.checkpoints = aucun), c_T = 3 600. | 0 | 342,712 | 118,938 | 8 760 / 0 | 2 ; 0,000008 |
| `pieces-purgees` | Pièces conservées localement 365 jours (D_lp = 365). | 0 | 766,989 | 806,888 | 8 760 / 96 360 | 63 ; 0,000249 |
| `debit-au-dela-de-la-cible` | 50 agents, 10 000 événements par heure, actifs 8 760 heures : pointe au-delà de la cible de 500 événements par seconde. | 0 | 391 505,042 | 115 670,826 | 8 760 / 96 360 | 63 ; 0,000249 |
| `cent-journaux` | Cent journaux de ce type (J = 100). | 0 | 96 765,467 | 80 688,823 | 876 000 / 9 636 000 | 6 300 ; 0,024858 |
| `deux-types-de-journaux` | Plus trois journaux souscription de deux agents à 30 événements par heure. | 0 | 2 979,481 | 2 965,453 | 35 040 / 385 440 | 252 ; 0,000994 |
| `journal-inactif` | Journal sans activité (e = 0, a = 0) : le maximum d'ancres est gardé (DM-7 est une borne). | 0 | 645,943 | 704,981 | 8 760 / 0 | 63 ; 0,000249 |
| `points-toutes-les-dix-secondes` | Un point toutes les dix secondes (c_K = 10). | 0 | 4 015,100 | 4 159,730 | 8 760 / 96 360 | 363 ; 0,001432 |
| `refus-cadence-non-diviseur` | c_K = 70, qui ne divise pas 3 600 : refus (EX-9.3). | 1 | refus : `checkpoint_interval_s_non_diviseur`, `rfc3161_interval_s_invalide` | | | |
| `refus-retention-ancres` | Rétention des pièces d'horodatage de 5 ans, sous 10 : refus (EX-9.3). | 1 | refus : `retention_years_inferieure_a_10` | | | |
| `refus-depassement-capacite` | Un million d'agents à 100 000 événements par heure, mille journaux : une sortie entière dépasserait 2^53 − 1 : refus (EX-9.3, depassement_capacite). | 1 | refus : `depassement_capacite` | | | |

## observation

Mode observation de CT-8 §12, annexe A.8 : vérifications OB-1 à OB-6. Le
journal d'exemple de 12.4 (sept événements scellés par `rec-test-01`,
ensemble `2026-11-05-observation`) est sous `journal/` ; empreinte :

- `0x3d0e81832bce1e5b653040304a65dfdc0e3912ba24e10ae44b2b78431516da36` ;

son segment fait 10086 octets, de SHA-256 :

- `0x0670cb8b7f374a6728082a73e43a7cf7a42f8202d9710cde72a3d27a641febb5` ;

SHA-256 du rapport attendu en JCS :

- `0x2df5ab6987cc8345b9a6f8bee1002b97b708901ee996faa44506bd9fb4254794`.

Les pièces des deux ensembles de politique (observation et erreur) sont sous
`politiques/`, nommées par leur `policy_sha256` sans `0x`, octets JCS exacts
sans saut de ligne final.

```bash
node scripts/deploiement/rapport-observation.mjs spec/vecteurs/ct-8/observation/evenements.ndjson --json   # égal à rapport-attendu.json, code 0
node scripts/deploiement/rapport-observation.mjs spec/vecteurs/ct-8/observation/invalides/<cas>.ndjson \
  [--politiques spec/vecteurs/ct-8/observation/politiques] --json   # anomalies attendues, code 1
```

| Fichier | Cas | Vérifications | Contenu |
|---|---|---|---|
| `marques.json` | 13 | OB-1 | chaînes `policy.rule` et analyse attendue |
| `correspondance.json` | 26 | OB-6 | cas de `ct-3/evaluation/assureur.json` rejoués en observation, et deux cas sans service |
| `reponses.json` | 10 | OB-6 | réponses du service et ce que le noyau en scelle (noms réservés, longueur, marque forgée) |
| `evenements.ndjson`, `rapport-attendu.json` | 1 | OB-5 | les sept événements et leur rapport |
| `invalides/` | 6 | OB-1 à OB-4 | suites re-scellées et anomalies attendues |

| Cas invalide | Ce qui change | Pièces | Anomalies attendues |
|---|---|---|---|
| `marque-absente-en-observation` | L'appel seq 3 n'a pas de marque sous une version en mode observation (OB-3). | oui | seq 3 OB-3 `marque_absente` |
| `marque-hors-observation` | Après l'annonce de la version 2026-11-05-erreur (seq 8), un appel marqué sous cette version (seq 9, OB-3). | oui | seq 9 OB-3 `marque_hors_observation` |
| `retenue-en-observation` | Un appel retenu (status retenue, ticket) sous une version en mode observation (OB-4 ; OB-3, sans marque). | oui | seq 3 OB-3 `marque_absente` ; seq 3 OB-4 `approbation_en_observation` |
| `marque-avec-decision-a-approuver` | Appel marqué dont policy.decision vaut a_approuver avec un ticket (OB-2). | non | seq 3 OB-2 `incoherence_marque` |
| `marque-sur-outil-reserve` | Événement noortrace.journal.politique qui porte une marque (OB-2). | non | seq 1 OB-2 `incoherence_marque` |
| `marque-en-double` | Appel seq 2 dont policy.rule porte deux marques d'observation (OB-1, marque_en_double). | non | seq 2 OB-1 `marque_en_double` |

## journaux

Vérification d'un répertoire de journal (CT-8 EX-11.7), annexe A.9. Chaque
cas est un répertoire de la disposition de CT-2 EX-12.1 (`journal.json`,
`segments/`, `manifestes/`), avec son `cles.json` et `attendu.json` (sa
description et le rapport `verification-journal-v0` attendu).

```bash
node scripts/deploiement/verifier-journal.mjs spec/vecteurs/ct-8/journaux/<cas> \
  --cles spec/vecteurs/ct-8/journaux/<cas>/cles.json --json   # code 0 valide, 1 invalide
```

| Cas | Ce qui change | Code | Verdict | Erreurs |
|---|---|---|---|---|
| `valide` | Le journal d'exemple de 12.4 : un segment, sept événements. | 0 | `valide` | — |
| `valide-deux-segments` | Le même journal en deux segments (seq 1 à 4 à l'époque 1, seq 5 à 7 à l'époque 2), en-tête du second chaîné au hash de seq 4. | 0 | `valide` | — |
| `valide-manifeste` | Le journal d'exemple et le manifeste signé de sa période, recalculé et vérifié. | 0 | `valide` | — |
| `ligne-modifiee` | Montant de l'événement seq 3 changé dans le segment sans re-scellement : hash et signature faux (E-7, E-8), lien rompu (C-2). | 1 | `invalide` | `E-7`, `E-8`, `C-2` |
| `ligne-tronquee` | Dernière ligne du segment coupée avant son \n (écriture interrompue) : ligne_incomplete. | 1 | `invalide` | `E-2`, `ligne_incomplete` |
| `entete-invalide` | En-tête de segment de version de format 1 au lieu de 0 : entete_invalide. | 1 | `invalide` | `entete_invalide` |
| `entete-discontinu` | Second segment dont l'en-tête porte un prev_hash qui n'est pas le hash de seq 4 : prev_hash_entete. | 1 | `invalide` | `prev_hash_entete` |
| `epoque-decroissante` | Second segment ouvert à l'époque 1 après un premier à l'époque 2 : epoque_decroissante. | 1 | `invalide` | `epoque_decroissante` |
| `segment-manquant` | Trois segments (1-2, 3-4, 5-7) dont celui de seq 3 et 4 manque : first_seq_discontinu (et C-1). | 1 | `invalide` | `C-1`, `C-2`, `first_seq_discontinu`, `prev_hash_entete` |
| `cle-inconnue` | Fichier de clés qui ne nomme que rec-test-02 : la clé des événements est inconnue (cle_inconnue). | 1 | `invalide` | `cle_inconnue` |
| `journal-json-invalide` | journal.json sans le membre recorder : journal_json_invalide. | 1 | `invalide` | `journal_json_invalide` |
| `manifeste-altere` | Manifeste dont count et last_seq omettent seq 7 (signature recalculée) : manifeste_invalide. | 1 | `invalide` | `manifeste_invalide` |
| `signature-manifeste-fausse` | Signature du manifeste remplacée par 64 octets nuls : signature_manifeste. | 1 | `invalide` | `signature_manifeste` |

## proces-verbaux

Procès-verbaux d'exploitation (CT-8 11.9, schéma
`proces-verbal-exploitation-v0`), vérifications PV-1 à PV-10, annexe A.9.
`racine/` est une copie du journal d'exemple (fichiers copiés, aucun lien) ;
`attendu.json` donne, cas par cas, le résultat de la vérification.

```bash
node scripts/deploiement/proces-verbal.mjs verifier spec/vecteurs/ct-8/proces-verbaux/<fichier> \
  [--racine spec/vecteurs/ct-8/proces-verbaux/racine --cles spec/vecteurs/ct-8/proces-verbaux/cles.json] --json
```

| Fichier | Racine | Ce qui change | Code | Verdict | Vérifications en échec |
|---|---|---|---|---|---|
| `valides/migration-support.json` | oui | Procès-verbal migration_support valide. | 0 | `valide` | — |
| `valides/passage-mode.json` | non | Procès-verbal passage_mode valide. | 0 | `valide` | — |
| `valides/sauvegarde.json` | oui | Procès-verbal sauvegarde valide. | 0 | `valide` | — |
| `valides/fin-de-retention.json` | non | Procès-verbal fin_de_retention valide. | 0 | `valide` | — |
| `invalides/pv-1-cle-en-double.json` | non | Clé kind répétée dans le document : JSON strict refusé (PV-1). | 1 | `invalide` | PV-1 |
| `invalides/pv-2-non-trie.json` | non | files dans l'ordre inverse des chemins (PV-2). | 1 | `invalide` | PV-2 |
| `invalides/pv-3-totaux-faux.json` | non | totals.bytes d'un octet de trop (PV-3). | 1 | `invalide` | PV-3 |
| `invalides/pv-4-condense-different.json` | non | sha256_destination du segment différent de sha256_source (PV-4). | 1 | `invalide` | PV-4 |
| `invalides/pv-5-sans-temoin.json` | non | Migration de support signée par le seul exécutant (PV-5). | 1 | `invalide` | PV-5 |
| `invalides/pv-6-destination-nulle.json` | non | Migration de support sans support d'arrivée (PV-6). | 1 | `invalide` | PV-6 |
| `invalides/pv-7-fichier-different.json` | oui | Longueur et SHA-256 annoncés pour journal.json qui ne sont pas ceux du fichier de la racine (PV-7). | 1 | `invalide` | PV-7 |
| `invalides/pv-8-continuite-fausse.json` | oui | continuity.last_seq 6 alors que le journal de la racine finit à seq 7 (PV-8). | 1 | `invalide` | PV-8 |
| `invalides/pv-9-echeance-fausse.json` | non | Fin de rétention dont retain_until précède d'un jour la fin de l'exercice plus dix ans (PV-9). | 1 | `invalide` | PV-9 |
| `invalides/pv-10-secret-dans-sauvegarde.json` | non | Sauvegarde qui liste le fichier secrets/cle-chaine : une clé hors de sa garde (PV-10). | 1 | `invalide` | PV-10 |

## consultations

Journal des consultations et des accès (CT-8 11.10, schéma `consultation-v0`),
vérifications CA-1 à CA-6, annexe A.9. Chaque cas est un répertoire qui
contient un fichier `consultations-2026-11-05.ndjson` (le nom entre dans CA-3).

```bash
node scripts/deploiement/consultations.mjs verifier spec/vecteurs/ct-8/consultations/<cas>/consultations-2026-11-05.ndjson --json
```

| Cas | Ce qui change | Code | Verdict | Vérifications en échec |
|---|---|---|---|---|
| `valide` | Les deux lignes chaînées de 11.10 (export d'un dossier par un réviseur, lecture d'un segment par le rôle Lecteur). | 0 | `valide` | — |
| `rang-saute` | Seconde ligne de rang 3 au lieu de 2 (CA-2). | 1 | `invalide` | CA-2 (ligne 2) |
| `chainage-rompu` | prev_sha256 de la seconde ligne qui n'est pas le SHA-256 de la première (CA-3). | 1 | `invalide` | CA-3 (ligne 2) |
| `collecte-decroissante` | Seconde ligne collectée avant la première (CA-4). | 1 | `invalide` | CA-4 (ligne 2) |
| `role-inconnu` | Principal sans rôle déclaré (role inconnu) : CA-6, règle noortrace_acces_non_declare. | 1 | `invalide` | CA-6 (ligne 2) |
| `non-jcs` | Première ligne écrite avec des espaces, hors JCS v0 (CA-1) ; la seconde reste chaînée à ses octets. | 1 | `invalide` | CA-1 (ligne 1) |

## acceptation-exploitation, acceptation-observation

Matériel des épreuves à l'aveugle de CT-8 §14 (EX-14.1, EX-14.11) : consignes
remises aux participants et grilles qu'ils ne reçoivent pas, tirées du texte
de la section 14 par le générateur.

| Fichier | Contenu |
|---|---|
| `acceptation-exploitation/consigne.md` | consigne de l'épreuve (a), avec les trois scénarios d'incident |
| `acceptation-exploitation/entrees-dimensionnement.json` | cas de dimensionnement d'EX-14.1 |
| `acceptation-exploitation-attendu.json` | grille : 4 éléments d'EX-14.2, totaux attendus, 3 scénarios d'EX-14.3 |
| `acceptation-observation/consigne.md`, `evenement-seq-3.json`, `rapport-observation.json` | consigne et matériel de l'épreuve (c) |
| `acceptation-observation-attendu.json` | grille : 5 questions d'EX-14.11 |

```bash
node scripts/deploiement/dimensionner.mjs --entrees spec/vecteurs/ct-8/acceptation-exploitation/entrees-dimensionnement.json --json   # totaux égaux à la grille, code 0
```

## paquets

Paquets réviseurs de CT-8 §13, annexe A.10. `description.json` est la
description de `valide.tar` (13.5), chemins relatifs à `paquets/` ;
`valide.tar` est construit par `scripts/paquet-reviseur/construire.mjs`
(paquet allégé, sans vérificateur joint) ; chaque archive de variante n'en
diffère que d'une chose. `observation.tar` est construit de même depuis
`description-observation.json` (dossiers de `observation/dossiers/`, EX-A.15).
`cas.json` (schéma `paquet-reviseur-v0#/$defs/fichier_cas`)
donne, pour chaque cas, ses options et le résultat attendu de l'outil de
vérification, que le générateur a obtenu en l'exécutant (EX-A.14).

13 archives, 3 624 960 octets en tout ; SHA-256 de `cas.json` :
`0x0e44622a66a79180a61f72ad90490c427c1c8bbab9c628ee650630337e3cb746`.

| Cas | Archive | SHA-256 | Options | Code | Paquet | PR- en échec | Avertissements | Codes des dossiers | Ce qui change |
|---|---|---|---|---|---|---|---|---|---|
| `valide` | `valide.tar` (296960 octets) | `0x8b977c10452e6a2c0b61319360834e3c06aa5e2a2b6208c9580c96b4dac33982` | — | 0 | `intact` | — | AV-PR-3 | 0, 0, 0 | Paquet construit par l'outil de référence : trois dossiers valides de ct-6, le fichier d'ancres de test, deux fichiers d'en-têtes, l'attestation de ct-7 ; sans vérificateur joint. |
| `valide-empreinte` | `valide.tar` (296960 octets) | `0x8b977c10452e6a2c0b61319360834e3c06aa5e2a2b6208c9580c96b4dac33982` | `--empreinte 0x8b977c10452e6a2c0b61319360834e3c06aa5e2a2b6208c9580c96b4dac33982` | 0 | `intact` | — | AV-PR-3 | 0, 0, 0 | Le même paquet, vérifié avec l'empreinte attendue reçue à part : PR-2 réussit. |
| `empreinte-fausse` | `valide.tar` (296960 octets) | `0x8b977c10452e6a2c0b61319360834e3c06aa5e2a2b6208c9580c96b4dac33982` | `--empreinte 0xb41b49dbe9b529f90b4de5b1c73986406951af163e0f9ed2a8381481227e7d29` | 4 | `non_conforme` | PR-2 | — | — | Le même paquet, vérifié avec l'empreinte d'un autre paquet : PR-2 échoue, rien d'autre n'est lu. |
| `fichier-altere` | `fichier-altere.tar` (296960 octets) | `0xb41b49dbe9b529f90b4de5b1c73986406951af163e0f9ed2a8381481227e7d29` | — | 4 | `non_conforme` | PR-8 | — | — | Un octet de dossiers/valide-seq-7-complet/evenement.json changé (seq 7 devenu 9), manifeste inchangé : PR-8. |
| `fichier-manquant` | `fichier-manquant.tar` (296960 octets) | `0x92dd0e6f2d3f76d8281925c73ae0d31fe8bfc80f6112b506e6cd39f794c8acbe` | — | 4 | `non_conforme` | PR-8 | — | — | dossiers/valide-seq-7-complet/voisins.json retiré de l'archive, toujours déclaré : PR-8. |
| `fichier-en-trop` | `fichier-en-trop.tar` (296960 octets) | `0x40558d06651fd5f539942952a9d6ea0f2a1322f0262ec41d06e8b0e00fa4730d` | — | 4 | `non_conforme` | PR-8 | — | — | dossiers/valide-seq-7-complet/note.txt ajouté à sa place dans l'ordre, absent du manifeste : PR-8. |
| `manifeste-altere` | `manifeste-altere.tar` (296960 octets) | `0x32ba2c02676d40d5d25f42e90a235763c53c78cd8348f18e34ae82e51473b122` | — | 4 | `non_conforme` | PR-8 | — | — | Le manifeste déclare pour evenement.json le SHA-256 d'une autre version ; le fichier est intact : PR-8. |
| `contrefacon-coherente` | `contrefacon-coherente.tar` (296960 octets) | `0xd806d8e7af25c118d9f241ead0c8b51892e10e778a8f1a0238f831334e822344` | — | 1 | `intact` | — | AV-PR-3 | 1, 0, 0 | evenement.json changé et le manifeste recalculé : le paquet est intact (PR-1 à PR-10), et le vérificateur de CT-6 rend le dossier invalide (D-2) : code 1. |
| `chemin-hors-archive` | `chemin-hors-archive.tar` (296960 octets) | `0xfc6446e02c04c10aea067a848c0fdc263d8f5a4a8242bec113475340dc678253` | — | 4 | `non_conforme` | PR-5 | — | — | Entrée paquet-reviseur/../../evasion.txt, qui sortirait du répertoire d'extraction : PR-5. |
| `chemin-absolu` | `chemin-absolu.tar` (296960 octets) | `0x6f07e6e4cb1dc1e6ebeac41a546ab140be71dd974d08a54cbbd084a5b1251fe2` | — | 4 | `non_conforme` | PR-5 | — | — | Entrée /paquet-reviseur/evasion.txt, nom absolu : PR-5. |
| `lien-symbolique` | `lien-symbolique.tar` (296960 octets) | `0xf036a91c971e6fbd3c75da67ddc90f5e3f6522e8a7a3c250f7178bf644c25071` | — | 4 | `non_conforme` | PR-4 | — | — | Entrée paquet-reviseur/ancres/raccourci, lien symbolique vers ../../../evasion, hors du répertoire d'extraction : PR-4. |
| `lien-physique` | `lien-physique.tar` (296960 octets) | `0xe8c92cba21f5c6ada90b7e17a595923888056f51345fbfacd35402437c186735` | — | 4 | `non_conforme` | PR-4 | — | — | Entrée paquet-reviseur/ancres/double, lien physique vers un fichier de l'archive : PR-4, plus strict que GNU tar et que le filtre data de Python. |
| `nom-en-double` | `nom-en-double.tar` (296960 octets) | `0xcfbc9d58c6e0174c3fdb86d10155ad642741166434522a94ca82b495398d2697` | — | 4 | `non_conforme` | PR-5 | — | — | Seconde entrée paquet-reviseur/LISEZMOI.md, d'un autre contenu : PR-5. |
| `metadonnees-non-fixees` | `metadonnees-non-fixees.tar` (296960 octets) | `0x275277ac3f74b02b8902301de1c5441b71803d2aace807511b87421af26410a3` | — | 4 | `non_conforme` | PR-6 | — | — | paquet-reviseur/README.md au mode 0600 : PR-6. |
| `ancres-du-reviseur-discordantes` | `valide.tar` (296960 octets) | `0x8b977c10452e6a2c0b61319360834e3c06aa5e2a2b6208c9580c96b4dac33982` | `--ancres spec/vecteurs/ct-6/ancres/ancres-cle-enregistreur-autre.json` | 1 | `intact` | — | — | 1, 1, 1 | Le paquet valide, vérifié avec un fichier d'ancres du réviseur qui attribue à rec-test-01 la clé de rec-test-02 : paquet intact, N-3 échoue dans chaque dossier, code 1. |
| `ancres-non-conformes` | `valide.tar` (296960 octets) | `0x8b977c10452e6a2c0b61319360834e3c06aa5e2a2b6208c9580c96b4dac33982` | `--ancres spec/vecteurs/ct-6/ots/entetes/chaine.json` | 2 | `intact` | — | — | 2, 2, 2 | Le paquet valide, vérifié avec --ancres désignant un fichier qui n'est pas un fichier d'ancres : chaque dossier rend le code 2 (N-1), code 2. |
| `observation` | `observation.tar` (61440 octets) | `0x127b257aebef28bb8436f7b07fe7a3c6d4e805ce7ca9c3f3e991c53b543f9ba5` | — | 0 | `intact` | — | AV-PR-4 | 0, 0 | Paquet des dossiers de seq 1 (annonce de l'ensemble, policy.rule nulle) et de seq 3 (appel marqué) du journal d'exemple de 12.4, avec la pièce de l'ensemble : les deux dossiers sont déclarés en mode observation (policy_version en -observation), seq 3 avec la marque a_approuver (EX-12.9, EX-A.15). |

Commande de chaque cas, depuis la racine du dépôt (code de sortie attendu en
commentaire) :

```bash
# valide : code 0
node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/valide.tar
# valide-empreinte : code 0
node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/valide.tar --empreinte 0x8b977c10452e6a2c0b61319360834e3c06aa5e2a2b6208c9580c96b4dac33982
# empreinte-fausse : code 4
node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/valide.tar --empreinte 0xb41b49dbe9b529f90b4de5b1c73986406951af163e0f9ed2a8381481227e7d29
# fichier-altere : code 4
node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/fichier-altere.tar
# fichier-manquant : code 4
node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/fichier-manquant.tar
# fichier-en-trop : code 4
node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/fichier-en-trop.tar
# manifeste-altere : code 4
node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/manifeste-altere.tar
# contrefacon-coherente : code 1
node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/contrefacon-coherente.tar
# chemin-hors-archive : code 4
node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/chemin-hors-archive.tar
# chemin-absolu : code 4
node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/chemin-absolu.tar
# lien-symbolique : code 4
node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/lien-symbolique.tar
# lien-physique : code 4
node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/lien-physique.tar
# nom-en-double : code 4
node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/nom-en-double.tar
# metadonnees-non-fixees : code 4
node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/metadonnees-non-fixees.tar
# ancres-du-reviseur-discordantes : code 1
node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/valide.tar --ancres spec/vecteurs/ct-6/ancres/ancres-cle-enregistreur-autre.json
# ancres-non-conformes : code 2
node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/valide.tar --ancres spec/vecteurs/ct-6/ots/entetes/chaine.json
# observation : code 0
node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/observation.tar
```

Reconstruction de `valide.tar` depuis sa description (l'archive écrite est
identique, octet pour octet) :

```bash
node scripts/paquet-reviseur/construire.mjs --description spec/vecteurs/ct-8/paquets/description.json --sortie <nouveau fichier>.tar
```
