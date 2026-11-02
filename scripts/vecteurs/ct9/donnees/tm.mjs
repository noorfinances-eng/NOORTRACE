// Source de données du catalogue CT-9 : entrées TM- (section 11), telles
// qu'elles sont imprimées dans spec/vecteurs/ct-9/catalogue.json.

export const TM = [
  {
    "id": "TM-1",
    "level": "TM",
    "title": "Latence ajoutée par appel relayé (CT-2 §16.1) : p50 ≤ 5 ms, p99 ≤ 50 ms",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 §16.1",
      "CT-2 EX-16.1",
      "CT-2 EX-16.2",
      "CT-2 EX-16.3"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Harnais `scripts/mesures/ct-2-perf.mjs` (CT-2 EX-16.2, phase 2) et configuration `spec/vecteurs/ct-2/mesures/configuration-mesure.json` (classe D, bail `file`, politique `pii-v1`).",
      "Serveur d'outils nul et hôte de test sur la même machine que l'enregistreur (EX-16.1) ; arguments ≤ 4 KiB, résultat ≤ 16 KiB ; signataire de classe D."
    ],
    "steps": [
      "Échauffement de 2 000 appels, puis N = 20 000 appels avec 1 connexion d'hôte, instants `t_recu_hote` et `t_reponse_hote` sur l'horloge monotone de l'hôte.",
      "Lire dans le journal d'exploitation `t_recu`, `t_envoi`, `t_reponse` par `id` JSON-RPC ; latence ajoutée = `(t_reponse_hote − t_recu) − (t_reponse − t_envoi)`.",
      "Percentiles au plus proche rang sur N ; rapport de mesure (11.3), ligne `latence_appel_relaye`."
    ],
    "oracle": "`p50 ≤ 5` et `p99 ≤ 50` (ms) sur le système de référence, `counts_for_targets` vrai ; sinon la ligne porte `met` faux et la porte 2 le dit.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 4,
      "blocking": "Enregistreur et harnais de mesure non construits (CT-2 EX-16.2 : phase 2)."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "latence ajoutée par appel relayé",
      "unit": "ms",
      "target": {
        "p50": 5,
        "p99": 50
      },
      "comparison": "p50_et_p99_au_plus",
      "source": "CT-2 §16.1",
      "failure_threshold": "p50 > 5 ms ou p99 > 50 ms, `fsync` actif, sur le système de référence",
      "method": "harnais",
      "percentiles": [
        "p50",
        "p95",
        "p99",
        "max"
      ],
      "warmup": 2000,
      "repetitions": 20000,
      "result_name": "latence_appel_relaye",
      "conditions": [
        "fdatasync sur disque local NVMe ou SSD",
        "signataire de classe D ou C",
        "arguments ≤ 4 KiB, résultat ≤ 16 KiB",
        "politique pii-v1",
        "une connexion d'hôte"
      ]
    }
  },
  {
    "id": "TM-2",
    "level": "TM",
    "title": "Latence ajoutée au premier octet d'un flux SSE (CT-2 §16.1) : ≤ 10 ms pour chaque octet",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 §16.1",
      "CT-2 EX-5.11",
      "CT-2 EX-16.2"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Harnais `scripts/mesures/ct-2-perf.mjs` (CT-2 EX-16.2, phase 2) et configuration `spec/vecteurs/ct-2/mesures/configuration-mesure.json` (classe D, bail `file`, politique `pii-v1`).",
      "Fournisseur de modèle simulé émettant un événement toutes les 50 ms, même machine, même horloge."
    ],
    "steps": [
      "Horodater chaque octet émis par le fournisseur simulé et chaque octet reçu par l'hôte de test (EX-16.2, pas 5).",
      "Latence = réception par l'hôte − émission par le fournisseur, pour chaque octet du flux ; N = 20 000 appels après 2 000 d'échauffement.",
      "Rapport : ligne `latence_premier_octet_sse`, `max` sur tous les octets."
    ],
    "oracle": "`max ≤ 10` ms sur tous les octets (aucun tampon, EX-5.11) ; sinon `met` faux.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 4,
      "blocking": "Passerelle du modèle et harnais non construits."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "latence ajoutée à chaque octet d'un flux SSE",
      "unit": "ms",
      "target": 10,
      "comparison": "au_plus",
      "source": "CT-2 §16.1",
      "failure_threshold": "max > 10 ms sur le système de référence",
      "method": "harnais",
      "percentiles": [
        "p50",
        "p99",
        "max"
      ],
      "warmup": 2000,
      "repetitions": 20000,
      "result_name": "latence_premier_octet_sse",
      "conditions": [
        "fournisseur simulé, un événement toutes les 50 ms",
        "même machine, même horloge"
      ]
    }
  },
  {
    "id": "TM-3",
    "level": "TM",
    "title": "Débit : événements rendus durables par seconde et par instance (CT-2 §16.1) : ≥ 500",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 §16.1",
      "CT-2 EX-16.2"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Harnais `scripts/mesures/ct-2-perf.mjs` (CT-2 EX-16.2, phase 2) et configuration `spec/vecteurs/ct-2/mesures/configuration-mesure.json` (classe D, bail `file`, politique `pii-v1`).",
      "Validation groupée `group_max_events: 64`, `group_max_wait_ms: 5` ; 16 connexions d'hôte concurrentes ; mêmes tailles que TM-1."
    ],
    "steps": [
      "Échauffement de 2 000 appels, puis N = 20 000 appels avec 16 connexions, émis à cadence fixe par l'hôte de test (11.2, omission coordonnée).",
      "Débit = `N / (t_dernier_fdatasync − t_premier_recu)` (EX-16.2, pas 6).",
      "Rapport : ligne `debit`, `connections` 16."
    ],
    "oracle": "`value ≥ 500` événements/s ; sinon `met` faux.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 4,
      "blocking": "Enregistreur et harnais non construits."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "débit d'événements durables",
      "unit": "evenements_par_s",
      "target": 500,
      "comparison": "au_moins",
      "source": "CT-2 §16.1",
      "failure_threshold": "moins de 500 événements/s avec 16 connexions sur le système de référence",
      "method": "harnais",
      "percentiles": [],
      "warmup": 2000,
      "repetitions": 20000,
      "result_name": "debit",
      "conditions": [
        "validation groupée 64 / 5 ms",
        "16 connexions d'hôte"
      ]
    }
  },
  {
    "id": "TM-4",
    "level": "TM",
    "title": "Latence ajoutée par échange de modèle hors flux (CT-2 §16.1) : p50 ≤ 5 ms, p99 ≤ 50 ms",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 §16.1",
      "CT-2 EX-16.2"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Harnais `scripts/mesures/ct-2-perf.mjs` (CT-2 EX-16.2, phase 2) et configuration `spec/vecteurs/ct-2/mesures/configuration-mesure.json` (classe D, bail `file`, politique `pii-v1`).",
      "Fournisseur simulé de l'API Messages hors flux ; corps de requête ≤ 32 KiB, réponse ≤ 16 KiB."
    ],
    "steps": [
      "Même procédé que TM-1 sur `/v1/messages` sans `stream`, N = 20 000 après 2 000 d'échauffement, 1 connexion.",
      "Rapport : ligne `latence_echange_modele`."
    ],
    "oracle": "`p50 ≤ 5` et `p99 ≤ 50` (ms) ; sinon `met` faux.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 4,
      "blocking": "Passerelle du modèle et harnais non construits."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "latence ajoutée par échange de modèle hors flux",
      "unit": "ms",
      "target": {
        "p50": 5,
        "p99": 50
      },
      "comparison": "p50_et_p99_au_plus",
      "source": "CT-2 §16.1",
      "failure_threshold": "p50 > 5 ms ou p99 > 50 ms sur le système de référence",
      "method": "harnais",
      "percentiles": [
        "p50",
        "p95",
        "p99",
        "max"
      ],
      "warmup": 2000,
      "repetitions": 20000,
      "result_name": "latence_echange_modele",
      "conditions": [
        "corps ≤ 32 KiB, réponse ≤ 16 KiB"
      ]
    }
  },
  {
    "id": "TM-5",
    "level": "TM",
    "title": "Durée d'un appel `sign` du signataire, publiée par classe de backend (CT-2 §16.1), sans cible",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 §16.1",
      "CT-2 EX-16.3"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Harnais `scripts/mesures/ct-2-perf.mjs` (CT-2 EX-16.2, phase 2) et configuration `spec/vecteurs/ct-2/mesures/configuration-mesure.json` (classe D, bail `file`, politique `pii-v1`).",
      "Un backend par classe disponible en test : A (SoftHSM2), B (Vault ou OpenBao en conteneur), C, D."
    ],
    "steps": [
      "Pendant TM-1, relever la durée de chaque appel `sign` par classe (EX-16.3 : la latence du signataire est séparée).",
      "Rapport : une ligne `signature` par classe, membre `backend` dans `conditions`."
    ],
    "oracle": "Une ligne par classe mesurée, `met` null (aucune cible) ; la latence de la classe B est ajoutée à TM-1 comme CT-2 §16.1 le demande.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 4,
      "blocking": "Signataires et harnais non construits."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "durée d'un appel sign par classe de backend",
      "unit": "ms",
      "target": null,
      "comparison": "aucune_cible",
      "source": "CT-2 §16.1",
      "failure_threshold": "aucun : mesure publiée ; une classe absente du rapport est une lacune nommée",
      "method": "harnais",
      "percentiles": [
        "p50",
        "p99"
      ],
      "warmup": 2000,
      "repetitions": 20000,
      "result_name": "signature",
      "conditions": [
        "une ligne par classe A, B, C, D"
      ]
    }
  },
  {
    "id": "TM-6",
    "level": "TM",
    "title": "Octets par événement sur les vecteurs publiés (CT-2 §16.1 : attendu de 2 à 3 KiB ; la ligne de l'annexe A fait 2 465 octets)",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 §16.1"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; aucun réseau, aucun conteneur, aucun binaire noorcore.",
      "Vecteurs `spec/vecteurs/ct-2/evenements/journal-demo/segment.ndjson` (9 lignes) et l'événement de l'annexe A de CT-2."
    ],
    "steps": [
      "Compter les octets de chaque ligne du segment de la démonstration, saut de ligne compris ; moyenne, minimum, maximum.",
      "Resceller `seq` 2, 3 et 4 de l'annexe A et compter la ligne de segment (2 465 octets).",
      "Rapport sur les vecteurs : ligne `octets_par_evenement`, `excluded_reason` `vecteurs_seulement`."
    ],
    "oracle": "La ligne de l'annexe A fait exactement 2 465 octets (test cité) ; la moyenne du segment de la démonstration est celle du rapport publié (1 588,11 octets sur 9 lignes, 2026-11-01) ; aucune cible.",
    "status": {
      "state": "executable",
      "command": "npx hardhat --config hardhat.config.mjs test test/enregistreur.test.js",
      "tests": [
        {
          "file": "test/enregistreur.test.js",
          "describe": "CT-2 : annexe A recalculée (relais de tools/call, pièces, événements)",
          "it": "seq 2, 3 et 4 rescellés par l'écrivain sont identiques, octet pour octet, aux événements imprimés ; ligne de segment de 2465 octets"
        }
      ]
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "octets par événement dans le segment, sur les vecteurs",
      "unit": "octets",
      "target": null,
      "comparison": "aucune_cible",
      "source": "CT-2 §16.1",
      "failure_threshold": "aucun : mesure publiée ; la ligne de l'annexe A doit faire 2 465 octets",
      "method": "comparaison_octets",
      "percentiles": [
        "mean",
        "min",
        "max"
      ],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "octets_par_evenement",
      "conditions": [
        "vecteurs publiés, pas l'enregistreur"
      ]
    }
  },
  {
    "id": "TM-7",
    "level": "TM",
    "title": "Octets par événement et octets de pièces par appel en charge (CT-2 §16.1), sans cible",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 §16.1"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Harnais `scripts/mesures/ct-2-perf.mjs` (CT-2 EX-16.2, phase 2) et configuration `spec/vecteurs/ct-2/mesures/configuration-mesure.json` (classe D, bail `file`, politique `pii-v1`)."
    ],
    "steps": [
      "Pendant TM-3, mesurer la taille du segment et des pièces écrites, divisée par le nombre d'événements et d'appels.",
      "Rapport : lignes `octets_par_evenement` et `octets_pieces_par_appel`."
    ],
    "oracle": "Lignes présentes, `met` null ; un écart de plus d'un facteur 2 avec TM-6 est signalé dans `notes`.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 4,
      "blocking": "Enregistreur non construit."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "octets par événement et par appel en charge",
      "unit": "octets",
      "target": null,
      "comparison": "aucune_cible",
      "source": "CT-2 §16.1",
      "failure_threshold": "aucun : mesure publiée",
      "method": "harnais",
      "percentiles": [
        "mean",
        "max"
      ],
      "warmup": 2000,
      "repetitions": 20000,
      "result_name": "octets_pieces_par_appel",
      "conditions": [
        "charge de TM-3"
      ]
    }
  },
  {
    "id": "TM-8",
    "level": "TM",
    "title": "Reprise : relecture du dernier segment et du journal d'intention au démarrage (CT-2 EX-12.10) : ≤ 2 s pour 256 MiB",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 §16.1",
      "CT-2 EX-12.10"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Un segment de 268 435 456 octets et son journal d'intention produits par l'enregistreur sur le disque local."
    ],
    "steps": [
      "Arrêter puis redémarrer le démon ; mesurer, sur l'horloge monotone, du début de la relecture (EX-12.10) à la ligne `startup` qui la clôt.",
      "Trois échauffements puis dix répétitions ; rapport : ligne `reprise`, `segment_bytes` 268435456 dans `conditions`."
    ],
    "oracle": "`p99 ≤ 2000` ms ; sinon `met` faux.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 4,
      "blocking": "Écrivain et reprise du démon non construits."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "durée de reprise au démarrage pour un segment de 256 MiB",
      "unit": "ms",
      "target": 2000,
      "comparison": "p99_au_plus",
      "source": "CT-2 §16.1",
      "failure_threshold": "p99 > 2 000 ms sur disque local",
      "method": "harnais",
      "percentiles": [
        "p50",
        "p99",
        "max"
      ],
      "warmup": 3,
      "repetitions": 10,
      "result_name": "reprise",
      "conditions": [
        "segment de 268 435 456 octets",
        "disque local"
      ]
    }
  },
  {
    "id": "TM-9",
    "level": "TM",
    "title": "Mémoire résidente à vide et sous charge ; `m_0` et `M_tamp` du dimensionnement (CT-2 §16.1 ; CT-8 §9.2, §9.3)",
    "specs": [
      "CT-2",
      "CT-8"
    ],
    "covers": [
      "CT-2 §16.1",
      "CT-8 EX-9.1",
      "CT-8 DM-19",
      "CT-8 §9.3"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Harnais `scripts/mesures/ct-2-perf.mjs` (CT-2 EX-16.2, phase 2) et configuration `spec/vecteurs/ct-2/mesures/configuration-mesure.json` (classe D, bail `file`, politique `pii-v1`).",
      "Calculateur `scripts/deploiement/dimensionner.mjs` avec les entrées de la configuration mesurée."
    ],
    "steps": [
      "Relever la mémoire résidente du démon (`/proc/<pid>/status`, `VmRSS`) à vide après `startup`, puis au maximum pendant TM-3.",
      "Comparer le maximum à `M_tamp` (`memory_buffers_max_bytes`) rendu par le calculateur ; publier `m_0` = résidente à vide.",
      "Rapport : lignes `memoire_vide`, `memoire_charge` ; `m_0` reporté dans les entrées du calculateur (membre `coefficients`)."
    ],
    "oracle": "Lignes présentes, `met` null (aucune cible en version 0) ; `memoire_charge − memoire_vide ≤ M_tamp` sinon `notes` le dit et DM-19 est à revoir.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 4,
      "blocking": "Enregistreur non construit ; `m_0` nul dans le calculateur jusqu'à cette mesure (CT-8 IC-1)."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "mémoire résidente à vide (m_0) et sous charge",
      "unit": "octets",
      "target": null,
      "comparison": "aucune_cible",
      "source": "CT-2 §16.1",
      "failure_threshold": "aucun : mesure publiée ; `memoire_charge − memoire_vide > M_tamp` est une lacune de DM-19 à tracer",
      "method": "releve",
      "percentiles": [
        "max"
      ],
      "warmup": 2000,
      "repetitions": 20000,
      "result_name": "memoire_charge",
      "conditions": [
        "charge de TM-3",
        "VmRSS"
      ]
    }
  },
  {
    "id": "TM-10",
    "level": "TM",
    "title": "P-1 sur les vecteurs : cadence des points d'une série publiée, `checkpoint_ts − ts ≤ c_K + 1 s` (CT-5 §3.6, AN-2)",
    "specs": [
      "CT-5"
    ],
    "covers": [
      "CT-5 P-1",
      "CT-5 AN-2",
      "CT-5 §3.6",
      "CT-5 §4.1"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; aucun réseau, aucun conteneur, aucun binaire noorcore.",
      "Série des points de `spec/vecteurs/ct-1/points-de-controle/` et `constaterCadence` de `scripts/lib/ancrage.mjs`."
    ],
    "steps": [
      "Appliquer `constaterCadence` à la série publiée : aucun écart ; à la série creuse (09:00, 09:59, clôture) : écart de 3 540 s.",
      "Pour chaque événement de seq `i` de `ct-1/journal-valide/evenements.json` : `checkpoint_ts` du premier point de `ct-1/points-de-controle/periode-*.json` dont `last_seq ≥ i` et `checkpoint_ts ≥ ts(i)`, moins `ts(i)` ; les douze délais et leur maximum sont recalculés à la génération et publiés dans le rapport sur les vecteurs, ligne `p1_cadence_vecteurs` (`samples`, `max`)."
    ],
    "oracle": "Aucun écart sur la série publiée ; maximum des délais ≤ 61 s ; l'écart de 3 540 s est constaté sur la série creuse (test cité).",
    "status": {
      "state": "executable",
      "command": "npx hardhat --config hardhat.config.mjs test test/ancrage.test.js",
      "tests": [
        {
          "file": "test/ancrage.test.js",
          "describe": "CT-5 : série des points, échéances, admission et complétude au registre (AN-2, AN-3, AN-61)",
          "it": "constaterCadence (AN-2, alerte point_manquant) : la série publiée est conforme ; une série creuse (09:00, 09:59, clôture) porte un écart de 3540 s"
        }
      ]
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "délai entre un événement et le premier point qui l'engage, sur les vecteurs",
      "unit": "s",
      "target": 61,
      "comparison": "au_plus",
      "source": "CT-5 P-1",
      "failure_threshold": "un écart de cadence sur la série publiée, ou un délai > 61 s",
      "method": "comptage",
      "percentiles": [
        "max"
      ],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "p1_cadence_vecteurs",
      "conditions": [
        "vecteurs publiés, c_K = 60 s"
      ]
    }
  },
  {
    "id": "TM-11",
    "level": "TM",
    "title": "P-1 sur le réseau de développement : série réelle produite par l'enregistreur, `checkpoint_ts − ts ≤ 61 s`",
    "specs": [
      "CT-5",
      "CT-2"
    ],
    "covers": [
      "CT-5 P-1",
      "CT-5 EX-3.3",
      "CT-2 EX-12.24"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Enregistreur produisant les points (`checkpoint_interval_s` 60) pendant une heure de charge de TM-3 ; composant d'ancrage en service."
    ],
    "steps": [
      "Lire la série `points/periode-<ps>.ndjson` et les événements de la période ; pour chaque événement, délai jusqu'au premier point de `tree_size` supérieur.",
      "`constaterCadence` sur la série ; rapport : ligne `p1_cadence`, `p99` et `max`."
    ],
    "oracle": "`max ≤ 61` s et aucun écart de cadence ; sinon `met` faux.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 5,
      "blocking": "Enregistreur (étape 4) et composant d'ancrage (étape 5) non construits."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "délai entre un événement et le premier point signé qui l'engage",
      "unit": "s",
      "target": 61,
      "comparison": "au_plus",
      "source": "CT-5 P-1",
      "failure_threshold": "max > 61 s ou un écart de cadence sur une heure",
      "method": "releve",
      "percentiles": [
        "p50",
        "p99",
        "max"
      ],
      "warmup": 0,
      "repetitions": 3600,
      "result_name": "p1_cadence",
      "conditions": [
        "c_K = 60 s",
        "une période complète sous la charge de TM-3"
      ]
    }
  },
  {
    "id": "TM-12",
    "level": "TM",
    "title": "P-2 : inclusion de l'ancre du point au registre, reçu reçu au plus `inclusion_alert_s` (60 s) après `checkpoint_ts`",
    "specs": [
      "CT-5",
      "CT-4"
    ],
    "covers": [
      "CT-5 P-2",
      "CT-5 §4.3",
      "CT-5 §3.3",
      "CT-4 §4.4"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Réseau de développement lancé par `chain/scripts/dev-net.sh start` ; composant d'ancrage avec `registry.checkpoints` `nouveaux_evenements`."
    ],
    "steps": [
      "Pour chaque ancre de point d'une période : instant de réception du reçu d'inclusion sur l'horloge de l'enregistreur moins `checkpoint_ts` (jamais l'horodatage du bloc).",
      "Rapport : ligne `p2_inclusion`, `p50`, `p99`, `max` ; `d_registre` publié."
    ],
    "oracle": "`max ≤ 60` s ; sinon `met` faux et l'alerte `inclusion_alert_s` doit s'être levée (sinon TA- de la supervision).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 5,
      "blocking": "Composant d'ancrage non construit ; le réseau de développement existe."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "délai d'inclusion de l'ancre d'un point au registre (d_registre)",
      "unit": "s",
      "target": 60,
      "comparison": "au_plus",
      "source": "CT-5 P-2",
      "failure_threshold": "max > 60 s en fonctionnement nominal sur le réseau de développement",
      "method": "releve",
      "percentiles": [
        "p50",
        "p99",
        "max"
      ],
      "warmup": 0,
      "repetitions": 60,
      "result_name": "p2_inclusion",
      "conditions": [
        "réseau de développement, 1,10 bloc/s mesuré le 2026-10-25",
        "horloge de l'enregistreur"
      ]
    }
  },
  {
    "id": "TM-13",
    "level": "TM",
    "title": "P-3 : contresignature RFC 3161 au plus `c_T + d_jeton` après l'événement, `d_jeton` rapporté avec ses quatre composantes (CT-5 EX-3.5)",
    "specs": [
      "CT-5"
    ],
    "covers": [
      "CT-5 P-3",
      "CT-5 EX-3.5",
      "CT-5 EX-4.3",
      "CT-5 §8.9"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Composant d'ancrage avec un prestataire RFC 3161 joignable (serveur interne de référence admis pour la mesure, CT-5 EX-7.4) ; `c_T` 300 s."
    ],
    "steps": [
      "Pour chaque échéance `D_k` satisfaite : `genTime + précision − D_k = d_jeton`, lu sur la ligne `checkpoint_countersigned` avec `d_point`, `d_attente`, `d_releve`, `d_tsa`.",
      "Vérifier qu'aucune échéance n'est non satisfaite avant la suivante en fonctionnement nominal.",
      "Rapport : lignes `p3_d_jeton`, `p3_d_point`, `p3_d_attente`, `p3_d_releve`, `p3_d_tsa`."
    ],
    "oracle": "`d_point ≤ 1` s, `d_attente ≤ squat_wait_s`, `d_releve ≤ fallback_after_s` (120 s), `d_tsa` publié ; zéro échéance manquée sur une période ; sinon `met` faux.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 5,
      "blocking": "Composant d'ancrage non construit."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "d_jeton : délai entre l'échéance de contresignature et genTime + précision",
      "unit": "s",
      "target": "c_T (300 s) + d_jeton ; d_point ≤ 1 s, d_attente ≤ squat_wait_s, d_releve ≤ fallback_after_s (120 s), d_tsa publié",
      "comparison": "au_plus",
      "source": "CT-5 P-3",
      "failure_threshold": "une échéance non satisfaite avant la suivante, ou une composante au-delà de sa borne",
      "method": "releve",
      "percentiles": [
        "p50",
        "p99",
        "max"
      ],
      "warmup": 0,
      "repetitions": 12,
      "result_name": "p3_d_jeton",
      "conditions": [
        "c_T = 300 s",
        "prestataire joignable",
        "une période complète"
      ]
    }
  },
  {
    "id": "TM-14",
    "level": "TM",
    "title": "P-4 : clôture horaire contresignée par un prestataire qualifié et horodatée par OpenTimestamps auprès d'au moins deux calendriers",
    "specs": [
      "CT-5",
      "CT-6"
    ],
    "covers": [
      "CT-5 P-4",
      "CT-6 EX-13.4",
      "CT-6 EX-13.5",
      "CT-6 T-11"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Un prestataire qualifié réel désigné `principal` pour la clôture (aucun prix dans le dépôt) ; deux calendriers OpenTimestamps joignables ; fichier d'ancres du réviseur."
    ],
    "steps": [
      "Exporter le dossier d'un événement d'une période close ; compter les parties `jeton-rfc3161.der` et `preuve.ots` et les calendriers de la preuve.",
      "Vérifier le dossier avec le fichier d'ancres : T-11 `reussi`.",
      "Rapport : ligne `p4_cloture`, `text_value` « jeton qualifié ; 2 calendriers ; T-11 reussi »."
    ],
    "oracle": "Les deux parties présentes, au moins deux calendriers, T-11 `reussi` ; sinon `met` faux.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 5,
      "blocking": "Composant d'ancrage non construit ; prestataire qualifié à contracter (porte 2)."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "clôture horaire qualifiée et attestée par deux calendriers",
      "unit": "texte",
      "target": "jeton qualifié ; au moins 2 calendriers ; T-11 reussi",
      "comparison": "egalite",
      "source": "CT-5 P-4",
      "failure_threshold": "partie absente, un seul calendrier, ou T-11 non reussi",
      "method": "lecture_api",
      "percentiles": [],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "p4_cloture",
      "conditions": [
        "prestataire qualifié réel",
        "fichier d'ancres du réviseur"
      ]
    }
  },
  {
    "id": "TM-15",
    "level": "TM",
    "title": "P-5 : un dossier se vérifie hors ligne, sans réseau ni concours du fournisseur, points de contrôle compris",
    "specs": [
      "CT-5",
      "CT-6"
    ],
    "covers": [
      "CT-5 P-5",
      "CT-6 EX-3.3",
      "CT-6 V-8",
      "CT-6 EX-8.7"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; aucun réseau, aucun conteneur, aucun binaire noorcore.",
      "Dossiers des vecteurs `ct-5` et `ct-6` ; `unshare -n` disponible (intégration continue)."
    ],
    "steps": [
      "Exécuter le vérificateur de référence sur chaque dossier deux fois : mêmes octets (V-8).",
      "Exécuter la copie jointe d'un paquet complet sous `unshare -n env -i` : code 0 (étape de CI citée)."
    ],
    "oracle": "Code 0 et rapport identique avec et sans réseau sur tous les dossiers ; sinon échec.",
    "status": {
      "state": "executable",
      "command": "npx hardhat --config hardhat.config.mjs test test/verificateur.test.js",
      "tests": [
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : dossiers complets de spec/vecteurs/ct-6 par la ligne de commande",
          "it": "deux exécutions rendent le même rapport JSON, octet pour octet (V-8)"
        }
      ],
      "ci_steps": [
        "paquet réviseur complet, construit deux fois, vérifié par le dépôt puis par sa copie jointe hors réseau"
      ]
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "vérification hors ligne d'un dossier avec points de contrôle",
      "unit": "texte",
      "target": "code 0 sans reseau ; rapport identique",
      "comparison": "egalite",
      "source": "CT-5 P-5",
      "failure_threshold": "un code différent ou un rapport différent sans réseau",
      "method": "comparaison_octets",
      "percentiles": [],
      "warmup": 0,
      "repetitions": 2,
      "result_name": "p5_hors_ligne",
      "conditions": [
        "unshare -n env -i"
      ]
    }
  },
  {
    "id": "TM-16",
    "level": "TM",
    "title": "P-6 : copie à verrou d'objet des points, ancres et manifestes, SHA-256 égal, mode et rétention lus par l'API du support",
    "specs": [
      "CT-5",
      "CT-2"
    ],
    "covers": [
      "CT-5 P-6",
      "CT-5 §5.5",
      "CT-2 EX-12.16",
      "CT-2 EX-12.17"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Support WORM réel ou son émulateur de test configuré dans `storage.seal.worm` ; une période close avec points, ancres et manifeste."
    ],
    "steps": [
      "Pour chaque fichier de `points/`, `ancres/periode-*/` et du manifeste : lire la version copiée par l'API du support, comparer son SHA-256 à l'original.",
      "Lire le mode de verrou et la date de rétention rendus par l'API ; comparer à la rétention des événements.",
      "Rapport : ligne `p6_copie_worm`, `value` = nombre de fichiers sans copie conforme."
    ],
    "oracle": "`value = 0` fichier manquant ; mode sans contournement ; rétention ≥ celle des événements ; sinon `met` faux.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 4,
      "blocking": "Copie WORM de l'enregistreur non construite (étape 4, stockage) ; support réel à la porte 2."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "fichiers de points, d'ancres et de manifestes sans copie WORM conforme",
      "unit": "nombre",
      "target": 0,
      "comparison": "egalite",
      "source": "CT-5 P-6",
      "failure_threshold": "au moins un fichier sans version au même SHA-256, ou une rétention plus courte",
      "method": "lecture_api",
      "percentiles": [],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "p6_copie_worm",
      "conditions": [
        "API du support (S3, Azure ou GCS)"
      ]
    }
  },
  {
    "id": "TM-17",
    "level": "TM",
    "title": "Mesures en charge du planificateur d'ancrage : débit de points, journaux par instance, taille de la file en régime de panne (CT-5 §15)",
    "specs": [
      "CT-5"
    ],
    "covers": [
      "CT-5 §15",
      "CT-5 §8.5",
      "CT-5 §12.4"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Composant d'ancrage avec `J` journaux (1 puis 10, maxima de CT-5 §4.6) ; prestataire simulé injoignable pendant une heure pour le régime de panne."
    ],
    "steps": [
      "Relever le nombre de points produits et ancrés par seconde pour J = 1 et J = 10.",
      "Couper le prestataire simulé une heure ; relever la taille maximale de la file durable et la mémoire du composant.",
      "Rapport : lignes `planificateur_debit_points`, `planificateur_journaux`, `planificateur_file_panne`."
    ],
    "oracle": "Lignes présentes, `met` null ; la file reste bornée (`queue` de CT-5 §8.5) sinon `notes` le dit.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 5,
      "blocking": "Composant d'ancrage non construit."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "débit de points, journaux par instance et taille de la file en panne",
      "unit": "nombre",
      "target": null,
      "comparison": "aucune_cible",
      "source": "CT-5 §15",
      "failure_threshold": "aucun : mesure publiée ; une file non bornée est une lacune à tracer",
      "method": "releve",
      "percentiles": [
        "max"
      ],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "planificateur_file_panne",
      "conditions": [
        "J = 1 puis J = 10",
        "panne du prestataire d'une heure"
      ]
    }
  },
  {
    "id": "TM-18",
    "level": "TM",
    "title": "AN-26 : numéros de série du serveur RFC 3161 interne strictement croissants à travers un redémarrage",
    "specs": [
      "CT-5"
    ],
    "covers": [
      "CT-5 AN-26",
      "CT-5 §7.2"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Serveur interne de référence (CT-5 EX-7.4) en service ; client de la section 5."
    ],
    "steps": [
      "Émettre dix jetons, redémarrer le serveur, émettre dix jetons ; lire `serialNumber` de chaque jeton (T-1).",
      "Rapport : ligne `an26_serie_croissante`, `value` = nombre de paires consécutives non croissantes."
    ],
    "oracle": "`value = 0` ; sinon `met` faux.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 5,
      "blocking": "Serveur interne non déployé comme service (CT-8 §15) ; l'autorité de test des vecteurs ne tourne pas."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "paires de jetons successifs à numéros de série non croissants, redémarrage compris",
      "unit": "nombre",
      "target": 0,
      "comparison": "egalite",
      "source": "CT-5 AN-26",
      "failure_threshold": "une paire non croissante",
      "method": "comptage",
      "percentiles": [],
      "warmup": 0,
      "repetitions": 20,
      "result_name": "an26_serie_croissante",
      "conditions": [
        "un redémarrage du serveur entre deux séries de dix jetons"
      ]
    }
  },
  {
    "id": "TM-19",
    "level": "TM",
    "title": "AN-24 : précision déclarée (`accuracy`) d'au plus 1 s dans chaque jeton émis par le serveur interne ; écart d'horloge journalisé",
    "specs": [
      "CT-5"
    ],
    "covers": [
      "CT-5 AN-24",
      "CT-5 §7.2"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Serveur interne de référence en service ; journal d'exploitation `tsa_clock_offset`."
    ],
    "steps": [
      "Sur chaque jeton émis pendant TM-13, lire `accuracy` (T-1) ; relever `tsa_clock_offset` dans le journal.",
      "Rapport : lignes `an24_accuracy` (`max`) et `an24_clock_offset` (`max`)."
    ],
    "oracle": "`accuracy` présent et ≤ 1 s sur tous les jetons ; `tsa_clock_offset` présent ; sinon `met` faux.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 5,
      "blocking": "Serveur interne non déployé comme service."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "précision déclarée des jetons du serveur interne",
      "unit": "s",
      "target": 1,
      "comparison": "au_plus",
      "source": "CT-5 AN-24",
      "failure_threshold": "accuracy absent ou > 1 s sur un jeton",
      "method": "releve",
      "percentiles": [
        "max"
      ],
      "warmup": 0,
      "repetitions": 12,
      "result_name": "an24_accuracy",
      "conditions": [
        "jetons de TM-13"
      ]
    }
  },
  {
    "id": "TM-20",
    "level": "TM",
    "title": "EX-7.18 de CT-7 : les six exigences de parité de l'attestation de périmètre, constatées sur tous les vecteurs",
    "specs": [
      "CT-7",
      "CT-6"
    ],
    "covers": [
      "CT-7 EX-7.18",
      "CT-6 V-10",
      "CT-6 EX-7.3"
    ],
    "preconditions": [
      "Dépôt au commit éprouvé, `npm ci` fait ; aucun réseau, aucun conteneur, aucun binaire noorcore.",
      "Vecteurs `ct-1`, `ct-6` (dossiers avec la partie) et `ct-7/attestations/` ; Go pour le vérificateur indépendant (sinon étape de CI)."
    ],
    "steps": [
      "Point 1 : vérifier sans réseau un dossier avec attestation (V-8). Point 2 : lire `facts.perimeter` du rapport. Point 3 : aucun « prouvé », « vérifié », « conforme » appliqué au périmètre (test cité).",
      "Point 4 : attestation non retenue : mêmes statuts, verdict, code, AV-AT-1 (test cité « FP de l'exemple… »). Point 5 : dossier sans attestation : rapport égal à la révision 0.2 aux membres près (test cité « --exiger… »). Point 2 : `facts.perimeter` lu dans le rapport (même test). Point 6 : statuts AT- égaux entre JavaScript et Go (étape de CI citée)."
    ],
    "oracle": "Les six points tenus sur tous les vecteurs, chacun par le test ou l'étape cités ; un point non tenu fait échouer son test.",
    "status": {
      "state": "executable",
      "command": "npx hardhat --config hardhat.config.mjs test test/verificateur.test.js",
      "tests": [
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 révision 0.3 : attestation de périmètre (section 5.5, EX-6.19 à EX-6.21, V-10)",
          "it": "EX-7.3 de CT-6, EX-7.18 point 3 de CT-7 : aucun texte des rapports n'applique « prouvé », « vérifié » ou « conforme » au périmètre ; le seul verbe est « déclaré »"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 : dossiers complets de spec/vecteurs/ct-6 par la ligne de commande",
          "it": "deux exécutions rendent le même rapport JSON, octet pour octet (V-8)"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 révision 0.3 : attestation de périmètre (section 5.5, EX-6.19 à EX-6.21, V-10)",
          "it": "FP de l'exemple d'EX-6.19 (français et anglais) et ligne lisible « Périmètre » (EX-8.10) ; AT- en échec « (sans effet sur le verdict) »"
        },
        {
          "file": "test/verificateur.test.js",
          "describe": "CT-6 révision 0.3 : attestation de périmètre (section 5.5, EX-6.19 à EX-6.21, V-10)",
          "it": "--exiger ne nomme que les huit contrôles : une attestation non retenue ne rend pas un dossier incomplet ; le rapport de la révision 0.2 d'un dossier sans la partie ne diffère que par verifier.schemas et facts.perimeter (EX-6.21)"
        }
      ],
      "ci_steps": [
        "vérificateur Go indépendant contre les vecteurs CT-7"
      ]
    },
    "threats": [
      "MN-78"
    ],
    "measure": {
      "measured": null,
      "quantity": "points de parité de CT-7 EX-7.18 non tenus sur les vecteurs",
      "unit": "nombre",
      "target": 0,
      "comparison": "egalite",
      "source": "CT-7 EX-7.18",
      "failure_threshold": "un point non tenu",
      "method": "comptage",
      "percentiles": [],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "ex718_parite",
      "conditions": [
        "tous les dossiers avec la partie attestation-perimetre.json"
      ]
    }
  },
  {
    "id": "TM-21",
    "level": "TM",
    "title": "EX-7.1 de CT-8 : installation rapide IR-1 à IR-8 en 900 s au plus, pas par pas, par une personne extérieure",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 EX-7.1",
      "CT-8 EX-7.2",
      "CT-8 IR-1",
      "CT-8 IR-2",
      "CT-8 IR-3",
      "CT-8 IR-4",
      "CT-8 IR-5",
      "CT-8 IR-6",
      "CT-8 IR-7",
      "CT-8 IR-8"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Hôte dans l'état de départ d'EX-7.2 (moteur de conteneurs, Compose, Node.js 22, curl, openssl) ; images `noortrace/*` publiées ; participant extérieur de TR-12 (partie phase 2 du rejeu complet, `participant.external` vrai dans la consignation) ; une exécution par l'ingénieur du lot est publiée mais ne compte pas pour la porte 2."
    ],
    "steps": [
      "Chronométrer chaque pas IR-1 à IR-8 sur l'horloge murale : début à la première commande du pas, fin à la vérification du pas rendue.",
      "Publier chaque durée, atteinte ou non, et la somme ; relever à part la durée du téléchargement des images d'IR-6 (TM-24).",
      "Rapport : lignes `ir_1` à `ir_8` (`value` en s, `target` = budget) et `ir_total`."
    ],
    "oracle": "`ir_total ≤ 900` s ; chaque pas comparé à son budget (60, 90, 90, 90, 60, 150, 180, 180 s), un dépassement de pas publié sans faire échouer le total.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Enregistreur, service d'approbation et images non construits (CT-8 §15 : installations non exécutées)."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "durée de l'installation rapide, IR-1 à IR-8",
      "unit": "s",
      "target": 900,
      "comparison": "somme_au_plus",
      "source": "CT-8 EX-7.1",
      "failure_threshold": "somme des huit pas > 900 s pour un participant extérieur (critère du plan : 15 minutes)",
      "method": "chronometre",
      "percentiles": [],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "ir_total",
      "conditions": [
        "état de départ d'EX-7.2",
        "une exécution par participant, horloge murale"
      ]
    }
  },
  {
    "id": "TM-22",
    "level": "TM",
    "title": "EX-8.1 de CT-8 : installation complète IC-1 à IC-18, durée totale sous 480 min (cible 450 min), pas par pas, attente de clôture relevée à part",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 EX-8.1",
      "CT-8 EX-8.3",
      "CT-8 IC-1",
      "CT-8 IC-2",
      "CT-8 IC-3",
      "CT-8 IC-4",
      "CT-8 IC-5",
      "CT-8 IC-6",
      "CT-8 IC-7",
      "CT-8 IC-8",
      "CT-8 IC-9",
      "CT-8 IC-10",
      "CT-8 IC-11",
      "CT-8 IC-12",
      "CT-8 IC-13",
      "CT-8 IC-14",
      "CT-8 IC-15",
      "CT-8 IC-16",
      "CT-8 IC-17",
      "CT-8 IC-18"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Machine vierge (CT-8 §2) ; préalables d'EX-8.2 réunis ; ingénieur d'exploitation qui n'a que CT-8 et les documents qu'il désigne (participant de TR-9 ou ingénieur du lot pour la répétition)."
    ],
    "steps": [
      "Chronométrer chaque pas IC-1 à IC-18 sur l'horloge murale depuis le procès-verbal (heures de début et de fin consignées, IC-18).",
      "Relever à part l'attente de clôture et d'inclusion d'IC-15 (jusqu'à une heure), qui entre dans la durée totale mais pas dans la durée du pas.",
      "Rapport : lignes `ic_1` à `ic_18` (`value` en min, `target` = budget), `ic_attente_cloture`, `ic_total`."
    ],
    "oracle": "`ic_total ≤ 480` min (cible 450 min, réserve 30 min) ; chaque pas comparé à son budget, un dépassement publié ; les durées sont celles du procès-verbal d'IC-18.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Enregistreur, service d'approbation, composant d'ancrage et images non construits ; script de préparation de l'hôte (IC-2) à écrire."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "durée de l'installation complète, IC-1 à IC-18",
      "unit": "min",
      "target": 450,
      "comparison": "somme_au_plus",
      "source": "CT-8 EX-8.1",
      "failure_threshold": "durée totale, attente comprise, > 480 min (journée de 8 heures)",
      "method": "chronometre",
      "percentiles": [],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "ic_total",
      "conditions": [
        "machine vierge, préalables d'EX-8.2 réunis",
        "une exécution par participant, horloge murale"
      ]
    }
  },
  {
    "id": "TM-23",
    "level": "TM",
    "title": "EX-8.1 de CT-8 : nombre d'informations absentes de CT-8 dont l'ingénieur a eu besoin (cible : zéro)",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 EX-8.1",
      "CT-8 §15"
    ],
    "preconditions": [
      "Pendant TM-22, le participant consigne chaque information qu'il a dû chercher hors de CT-8 et des documents qu'il désigne (y compris la documentation de la distribution pour IC-2, admise en 0.1)."
    ],
    "steps": [
      "Compter les demandes consignées ; distinguer celles admises par CT-8 §15 (IC-2) des autres.",
      "Rapport : ligne `ic_informations_manquantes`, `value` = nombre hors IC-2."
    ],
    "oracle": "`value = 0` ; chaque information manquante est une lacune de CT-8 à tracer (proposition PD-).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Installation complète non exécutée."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "informations absentes de CT-8 nécessaires à l'installation complète",
      "unit": "nombre",
      "target": 0,
      "comparison": "egalite",
      "source": "CT-8 EX-8.1",
      "failure_threshold": "au moins une information manquante hors IC-2",
      "method": "comptage",
      "percentiles": [],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "ic_informations_manquantes",
      "conditions": [
        "participant extérieur de TR-9"
      ]
    }
  },
  {
    "id": "TM-24",
    "level": "TM",
    "title": "Taille des images téléchargées à l'installation rapide (CT-8 §7.2, IR-6), sans cible",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 IR-6",
      "CT-8 EX-3.14"
    ],
    "preconditions": [
      "Images `noortrace/*` construites et publiées par condensé (EX-3.13, EX-3.14)."
    ],
    "steps": [
      "Relever la taille de chaque image (`docker image inspect`, `Size`) et la durée du téléchargement pendant IR-6.",
      "Rapport : lignes `image_<nom>_octets` et `ir6_telechargement_s`."
    ],
    "oracle": "Lignes présentes, `met` null ; la durée de téléchargement est relevée à part du budget d'IR-6 (150 s).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Aucune image construite (CT-8 EX-3.13)."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "taille des images et durée de leur téléchargement",
      "unit": "octets",
      "target": null,
      "comparison": "aucune_cible",
      "source": "CT-8 IR-6",
      "failure_threshold": "aucun : mesure publiée",
      "method": "releve",
      "percentiles": [],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "image_octets",
      "conditions": [
        "images épinglées par condensé"
      ]
    }
  },
  {
    "id": "TM-25",
    "level": "TM",
    "title": "EX-13.1 point 7 de CT-8 : temps d'un réviseur extérieur, de la réception du paquet au résultat, moins de 30 minutes la première fois",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 EX-13.1",
      "CT-8 EX-14.9"
    ],
    "preconditions": [
      "Épreuve TR-10 (CT-8 §14, épreuve (b)) en cours : réviseur extérieur, section 13 seule, paquet sous un nom neutre, poste sans réseau avec Node.js 22 et GNU tar."
    ],
    "steps": [
      "Chronométrer, sur l'horloge murale, de la remise du matériel à la remise du rapport écrit (EX-14.9) ; lecture des instructions comprise.",
      "Rapport : ligne `reviseur_temps`, une valeur par participant ; consignation TR-10 (`duration_s`)."
    ],
    "oracle": "`value < 1800` s pour chaque participant ; sinon `met` faux.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Épreuve humaine conduite à la porte 2 ; le matériel existe (paquets des vecteurs, outil de vérification, paquet complet construit par la CI)."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "temps du réviseur, réception à résultat",
      "unit": "s",
      "target": 1800,
      "comparison": "strictement_inferieur",
      "source": "CT-8 EX-13.1",
      "failure_threshold": "1 800 s ou plus (1 800,0 s exactement est un échec) pour un réviseur extérieur à sa première vérification",
      "method": "chronometre",
      "percentiles": [
        "max"
      ],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "reviseur_temps",
      "conditions": [
        "réviseur extérieur, première vérification",
        "poste sans réseau"
      ]
    }
  },
  {
    "id": "TM-26",
    "level": "TM",
    "title": "EX-3.9 de CT-8 : le compagnon pose les attributs `a` et `i` toutes les 60 secondes au plus",
    "specs": [
      "CT-8",
      "CT-2"
    ],
    "covers": [
      "CT-8 EX-3.9",
      "CT-2 EX-12.18"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Images construites ; `storage.seal.append_only_attribute` vrai ; service `attributs` en service sous le compte 0 avec ses trois capacités."
    ],
    "steps": [
      "Fermer un segment et écrire un manifeste ; relever l'instant de fermeture et l'instant où `lsattr` montre l'attribut `i` ; même relevé pour `a` sur le segment courant.",
      "Répéter sur dix segments ; rapport : ligne `compagnon_pose_attribut`, `max`."
    ],
    "oracle": "`max ≤ 60` s ; sinon `met` faux.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Image du compagnon non construite."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "délai de pose des attributs par le compagnon",
      "unit": "s",
      "target": 60,
      "comparison": "au_plus",
      "source": "CT-8 EX-3.9",
      "failure_threshold": "max > 60 s sur dix segments",
      "method": "releve",
      "percentiles": [
        "p50",
        "max"
      ],
      "warmup": 0,
      "repetitions": 10,
      "result_name": "compagnon_pose_attribut",
      "conditions": [
        "lsattr sur l'hôte"
      ]
    }
  },
  {
    "id": "TM-27",
    "level": "TM",
    "title": "CT-8 §3.5 : durée de vie DNS du nom du répartiteur d'au plus 30 secondes",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 §3.5",
      "CT-8 EX-3.11"
    ],
    "preconditions": [
      "Topologie à deux instances avec répartiteur et nom DNS (CT-8 §3.5)."
    ],
    "steps": [
      "Interroger le nom avec `dig` et lire le TTL rendu ; provoquer une bascule (EX-3.11) et mesurer le délai de reconnexion d'un hôte.",
      "Rapport : lignes `repartiteur_ttl_dns` et `repartiteur_reconnexion`."
    ],
    "oracle": "`repartiteur_ttl_dns ≤ 30` s ; `repartiteur_reconnexion` publié sans cible.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Topologie à deux instances non déployée."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "durée de vie DNS du nom du répartiteur",
      "unit": "s",
      "target": 30,
      "comparison": "au_plus",
      "source": "CT-8 §3.5",
      "failure_threshold": "TTL > 30 s",
      "method": "lecture_api",
      "percentiles": [],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "repartiteur_ttl_dns",
      "conditions": [
        "dig sur le nom du répartiteur"
      ]
    }
  },
  {
    "id": "TM-28",
    "level": "TM",
    "title": "EX-3.13 de CT-8 : égalité des condensés de deux constructions indépendantes de chaque image, du binaire du vérificateur et de la console",
    "specs": [
      "CT-8",
      "CT-3"
    ],
    "covers": [
      "CT-8 EX-3.13",
      "CT-8 §3.6",
      "CT-3 EX-13.4"
    ],
    "preconditions": [
      "Deux constructeurs indépendants (deux machines, même commit, `SOURCE_DATE_EPOCH` à la date du commit, images de base épinglées)."
    ],
    "steps": [
      "Construire chaque image `noortrace/*`, le binaire `noortrace-verifier` et la page de la console deux fois ; comparer les condensés.",
      "Rapport : ligne `construction_reproductible`, `value` = nombre d'artefacts aux condensés différents."
    ],
    "oracle": "`value = 0` ; un artefact non reproductible n'est pas publié (EX-3.13).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Aucune image construite ; binaire Go du vérificateur à construire (CT-6 §14, étape 2)."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "artefacts dont deux constructions indépendantes diffèrent",
      "unit": "nombre",
      "target": 0,
      "comparison": "egalite",
      "source": "CT-8 EX-3.13",
      "failure_threshold": "un condensé différent",
      "method": "comparaison_octets",
      "percentiles": [],
      "warmup": 0,
      "repetitions": 2,
      "result_name": "construction_reproductible",
      "conditions": [
        "deux constructeurs indépendants",
        "SOURCE_DATE_EPOCH fixé"
      ]
    }
  },
  {
    "id": "TM-29",
    "level": "TM",
    "title": "EX-6.2 de CT-8 : seuils « cible » du contrôle préalable (IP-2 processeurs et mémoire, IP-3 espace libre) confrontés à la consommation observée",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 EX-6.2",
      "CT-8 IP-2",
      "CT-8 IP-3"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Installation rapide puis production sur le système de référence ; charge de TM-3."
    ],
    "steps": [
      "Relever le nombre de processeurs occupés (moyenne de charge), la mémoire résidente totale des services et l'espace disque consommé après une heure de charge.",
      "Comparer aux planchers : 2 processeurs et 4 Gio (rapide), 4 et 8 Gio (production), 10 Gio d'espace (rapide).",
      "Rapport : lignes `ip2_processeurs`, `ip2_memoire`, `ip3_espace`."
    ],
    "oracle": "Chaque consommation observée sous son plancher ; un dépassement rend `met` faux et le seuil d'IP-2 ou IP-3 est à relever (proposition PD- à CT-8).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Composants non construits."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "consommation observée de processeurs, de mémoire et d'espace sous charge",
      "unit": "octets",
      "target": "2 processeurs et 4 Gio (rapide) ; 4 et 8 Gio (production) ; 10 Gio d'espace (rapide)",
      "comparison": "au_plus",
      "source": "CT-8 EX-6.2",
      "failure_threshold": "une consommation observée au-dessus du plancher du profil",
      "method": "releve",
      "percentiles": [
        "max"
      ],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "ip2_memoire",
      "conditions": [
        "charge de TM-3 pendant une heure"
      ]
    }
  },
  {
    "id": "TM-30",
    "level": "TM",
    "title": "Coefficient `b_ots` de CT-8 §9.2 : octets d'une preuve OpenTimestamps mise à niveau (défaut 233 en attente)",
    "specs": [
      "CT-8",
      "CT-5"
    ],
    "covers": [
      "CT-8 EX-9.1",
      "CT-5 §6.4"
    ],
    "preconditions": [
      "Composant d'ancrage avec mise à niveau OpenTimestamps auprès de deux calendriers réels ; une preuve mise à niveau après inclusion dans Bitcoin."
    ],
    "steps": [
      "Mesurer la taille en octets de dix preuves `.ots` mises à niveau ; rapport : ligne `b_ots_mis_a_niveau`, `max` et `mean`."
    ],
    "oracle": "Ligne présente, `met` null ; la valeur remplace 233 dans les entrées du calculateur (membre `coefficients`).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 5,
      "blocking": "Composant d'ancrage non construit ; mise à niveau réelle requise."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "octets d'une preuve OpenTimestamps mise à niveau",
      "unit": "octets",
      "target": null,
      "comparison": "aucune_cible",
      "source": "CT-8 EX-9.1",
      "failure_threshold": "aucun : mesure publiée",
      "method": "comparaison_octets",
      "percentiles": [
        "mean",
        "max"
      ],
      "warmup": 0,
      "repetitions": 10,
      "result_name": "b_ots_mis_a_niveau",
      "conditions": [
        "preuves mises à niveau après inclusion"
      ]
    }
  },
  {
    "id": "TM-31",
    "level": "TM",
    "title": "Coefficient `b_cap` de CT-8 §9.2 : octets de la capture d'une transaction dans un bloc plein (CT-4 §9.2 : non mesuré)",
    "specs": [
      "CT-8",
      "CT-4"
    ],
    "covers": [
      "CT-8 EX-9.1",
      "CT-4 §9.2",
      "CT-4 §4.4"
    ],
    "preconditions": [
      "Réseau de développement lancé par `chain/scripts/dev-net.sh start` ; outil de référence de CT-4 ; 64 expéditeurs pour remplir un bloc."
    ],
    "steps": [
      "Émettre 64 transactions d'ancre dans le même bloc ; capturer l'une d'elles (en-tête, certificat de commit, reçu) ; mesurer les octets de la capture.",
      "Rapport : ligne `b_cap_bloc_plein`, `max`."
    ],
    "oracle": "Ligne présente, `met` null ; la valeur remplace 11 096 dans les entrées du calculateur si elle est supérieure.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 3,
      "blocking": "Outillage de remplissage d'un bloc à écrire ; le réseau de développement existe."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "octets de la capture d'une transaction d'un bloc plein",
      "unit": "octets",
      "target": null,
      "comparison": "aucune_cible",
      "source": "CT-8 EX-9.1",
      "failure_threshold": "aucun : mesure publiée",
      "method": "comparaison_octets",
      "percentiles": [
        "max"
      ],
      "warmup": 0,
      "repetitions": 3,
      "result_name": "b_cap_bloc_plein",
      "conditions": [
        "bloc de 64 transactions sur le réseau de développement"
      ]
    }
  },
  {
    "id": "TM-32",
    "level": "TM",
    "title": "Coefficient `blocs_par_s` de CT-8 §9.2 sur l'instance de production du registre (réseau de développement : 1,10 le 2026-10-25)",
    "specs": [
      "CT-8",
      "CT-4"
    ],
    "covers": [
      "CT-8 EX-9.1",
      "CT-4 §4.4"
    ],
    "preconditions": [
      "Instance de production du registre publiée par l'exploitant (manifeste d'instance, CT-4 §4.8)."
    ],
    "steps": [
      "Relever les numéros et horodatages de blocs sur une heure par RPC ; `blocs_par_s` = blocs / durée.",
      "Rapport : ligne `blocs_par_s_production`."
    ],
    "oracle": "Ligne présente, `met` null ; la valeur remplace 1,10 dans les entrées du calculateur.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 3,
      "blocking": "Instance de production du registre non déployée (hors du déploiement chez un client, CT-8 §15)."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "blocs par seconde de l'instance de production",
      "unit": "blocs_par_s",
      "target": null,
      "comparison": "aucune_cible",
      "source": "CT-8 EX-9.1",
      "failure_threshold": "aucun : mesure publiée",
      "method": "releve",
      "percentiles": [],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "blocs_par_s_production",
      "conditions": [
        "une heure de relevé par RPC"
      ]
    }
  },
  {
    "id": "TM-33",
    "level": "TM",
    "title": "Coefficients sans valeur par défaut de CT-8 §9.2 : `f_pic`, `b_o`, `b_acq`, `b_crl`, `n_crl` (hypothèses de 9.5 jusqu'à la mesure)",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 EX-9.1",
      "CT-8 §9.5",
      "CT-8 IC-1"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Enregistreur et composant d'ancrage en service une semaine sur la démonstration de référence."
    ],
    "steps": [
      "`f_pic` : rapport entre le débit de pointe horaire et le débit moyen ; `b_o` : octets moyens d'une ligne du journal d'exploitation ; `b_acq` : octets d'un enregistrement d'acquisition ; `b_crl`, `n_crl` : taille et nombre des CRL des prestataires.",
      "Rapport : une ligne par coefficient ; IC-1 refait avec les valeurs mesurées."
    ],
    "oracle": "Cinq lignes présentes, `met` null ; les hypothèses de 9.5 (4, 512, 2 048, 833, 2) sont remplacées au procès-verbal.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Composants non construits ; hypothèses de 9.5 en vigueur."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "coefficients f_pic, b_o, b_acq, b_crl, n_crl",
      "unit": "nombre",
      "target": null,
      "comparison": "aucune_cible",
      "source": "CT-8 EX-9.1",
      "failure_threshold": "aucun : mesure publiée ; IC-1 refait après mesure",
      "method": "releve",
      "percentiles": [
        "mean",
        "max"
      ],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "f_pic",
      "conditions": [
        "une semaine de la démonstration de référence"
      ]
    }
  },
  {
    "id": "TM-34",
    "level": "TM",
    "title": "Seuils d'alerte « cible » de la supervision de CT-8 §10 : distribution des métriques en fonctionnement nominal et dans chaque scénario de runbook",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 §10.4",
      "CT-8 §10.5",
      "CT-8 §10.6",
      "CT-8 §10.7",
      "CT-8 EX-10.11"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Fichiers de `deploiement/observabilite/` produits (lot suivant de CT-8) ; `promtool` ; charge de TM-3 pendant une heure ; scénarios RB-1 à RB-8 rejoués."
    ],
    "steps": [
      "Relever, par métrique à seuil cible, la valeur maximale en nominal et la valeur atteinte dans le scénario qui doit lever l'alerte.",
      "Compter les faux positifs (alerte en nominal) et les faux négatifs (pas d'alerte dans le scénario).",
      "Rapport : ligne `supervision_faux_positifs`, `supervision_faux_negatifs` et une ligne par métrique."
    ],
    "oracle": "`supervision_faux_positifs = 0` et `supervision_faux_negatifs = 0` ; sinon le seuil est revu (proposition PD- à CT-8).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Supervision outillée non livrée (CT-8 §15, lot suivant)."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "faux positifs et faux négatifs des alertes à seuil cible",
      "unit": "nombre",
      "target": 0,
      "comparison": "egalite",
      "source": "CT-8 EX-10.11",
      "failure_threshold": "une alerte levée en nominal ou absente dans son scénario",
      "method": "comptage",
      "percentiles": [
        "max"
      ],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "supervision_faux_positifs",
      "conditions": [
        "une heure nominale puis RB-1 à RB-8"
      ]
    }
  },
  {
    "id": "TM-35",
    "level": "TM",
    "title": "Seuil `<M>` de la mempool du nœud relais (CT-8 §10.6) : moitié de `-txpool-max-pending`, confronté à la file observée",
    "specs": [
      "CT-8",
      "CT-4"
    ],
    "covers": [
      "CT-8 §10.6",
      "CT-4 EX-9.6"
    ],
    "preconditions": [
      "Nœud relais du réseau de développement ; supervision outillée ; charge d'ancres de points de TM-12."
    ],
    "steps": [
      "Lire `-txpool-max-pending` du nœud (la valeur par défaut n'est pas imprimée par `noorcore -h`) et écrire `<M>` en nombre dans le rapport ; relever la taille de la file en attente sur une heure ; rapport : ligne `mempool_max_observe`, `target` = `<M>`."
    ],
    "oracle": "`max < <M>` en nominal ; sinon `met` faux et `<M>` est revu.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Supervision non livrée ; taille exacte de la mempool non établie (CT-8 §15)."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "taille maximale observée de la file en attente du nœud",
      "unit": "nombre",
      "target": "moitié de -txpool-max-pending",
      "comparison": "strictement_inferieur",
      "source": "CT-8 §10.6",
      "failure_threshold": "file observée ≥ <M> en nominal",
      "method": "releve",
      "percentiles": [
        "max"
      ],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "mempool_max_observe",
      "conditions": [
        "une heure de charge d'ancres",
        "`<M>` : moitié de `-txpool-max-pending` lue sur le nœud au début de la mesure et écrite dans `conditions` ; `noorcore -h` n'imprime pas la valeur par défaut (« 0 = default », relevé du 2026-11-01)"
      ]
    }
  },
  {
    "id": "TM-36",
    "level": "TM",
    "title": "Durées des runbooks RB-1 à RB-8 de CT-8 (aucune n'est mesurée), rejoués sur la démonstration de référence",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 RB-1",
      "CT-8 RB-2",
      "CT-8 RB-3",
      "CT-8 RB-4",
      "CT-8 RB-5",
      "CT-8 RB-6",
      "CT-8 RB-7",
      "CT-8 RB-8",
      "CT-8 §10.11"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Démonstration de référence en service ; incident provoqué pour chaque runbook (panne injectée) ; ingénieur d'exploitation qui n'a que le runbook."
    ],
    "steps": [
      "Pour chaque runbook, chronométrer du déclenchement de l'alerte à la vérification de sortie réussie ; relever les portes franchies.",
      "Rapport : lignes `rb_1` à `rb_8` (`value` en s)."
    ],
    "oracle": "Huit lignes présentes, `met` null ; une sortie non atteinte est un échec du TE- du runbook, pas de cette mesure.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Composants et runbooks non exécutables (CT-8 §10.11 : aucune durée mesurée)."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "durée de chaque runbook, alerte à sortie vérifiée",
      "unit": "s",
      "target": null,
      "comparison": "aucune_cible",
      "source": "CT-8 §10.11",
      "failure_threshold": "aucun : mesure publiée",
      "method": "chronometre",
      "percentiles": [],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "rb_1",
      "conditions": [
        "incident provoqué, ingénieur avec le seul runbook"
      ]
    }
  },
  {
    "id": "TM-37",
    "level": "TM",
    "title": "EX-11.5 de CT-8 : RPO et RTO par composant, et cadence de sauvegarde de l'état du service d'approbation (15 min), mesurés par des exercices de restauration",
    "specs": [
      "CT-8",
      "CT-2",
      "CT-3"
    ],
    "covers": [
      "CT-8 EX-11.5",
      "CT-8 EX-11.4",
      "CT-8 §11.2",
      "CT-8 §11.3",
      "CT-2 EX-12.16",
      "CT-3 EX-7.25"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Démonstration de référence avec copie WORM, sauvegarde et service d'approbation ; exercices de restauration par les chemins A et B (CT-8 §11.4)."
    ],
    "steps": [
      "Pour chaque composant de la table d'EX-11.5, provoquer la perte, restaurer, chronométrer (RTO) et mesurer la perte de données (RPO) ; relever la cadence réelle des sauvegardes de l'état du service.",
      "Rapport : lignes `rpo_<composant>`, `rto_<composant>`, `sauvegarde_etat_service_cadence`."
    ],
    "oracle": "Chaque valeur sous sa cible : segments fermés RTO ≤ 4 h ; segment ouvert bascule ≤ `lease.ttl_ms` (10 s) + 2 s ; pièces RTO ≤ 4 h ; service RPO ≤ 15 min, RTO ≤ 1 h ; ancrage RTO ≤ 4 h ; configuration RTO ≤ durée de TM-22 ; sinon `met` faux.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Composants, outil de sauvegarde et runbooks non construits (CT-8 §15)."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "RPO et RTO par composant, cadence de sauvegarde de l'état du service",
      "unit": "s",
      "target": "RTO : 14 400 s (journal, pièces, ancrage), 12 s (bascule du segment ouvert), 3 600 s (service) ; RPO service : 900 s",
      "comparison": "au_plus",
      "source": "CT-8 EX-11.5",
      "failure_threshold": "une valeur mesurée au-dessus de sa cible",
      "method": "chronometre",
      "percentiles": [
        "max"
      ],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "rto_journal_segments_fermes",
      "conditions": [
        "exercice de restauration par composant"
      ]
    }
  },
  {
    "id": "TM-38",
    "level": "TM",
    "title": "Mode observation (CT-8 §12.2) : latence ajoutée et durée d'écriture, cibles de CT-2 §16.1, par paire avec et sans l'enregistreur",
    "specs": [
      "CT-8",
      "CT-2"
    ],
    "covers": [
      "CT-8 EX-12.3",
      "CT-8 EX-12.5",
      "CT-8 §12.2",
      "CT-2 §16.1"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Harnais `scripts/mesures/ct-2-perf.mjs` (CT-2 EX-16.2, phase 2) et configuration `spec/vecteurs/ct-2/mesures/configuration-mesure.json` (classe D, bail `file`, politique `pii-v1`).",
      "Configuration en mode `observation` (suffixe `-observation`, CT-2 EX-15.8)."
    ],
    "steps": [
      "Rejouer TM-1 en mode observation ; mesurer aussi, par paire (11.2 : même machine, même charge, même séquence), la latence de bout en bout avec et sans l'enregistreur sur le chemin.",
      "Relever la durée d'écriture (intention et événement) par appel ; rapport : lignes `observation_latence`, `observation_latence_paire`, `observation_ecriture`."
    ],
    "oracle": "`observation_latence` : `p50 ≤ 5`, `p99 ≤ 50` ms ; la différence des percentiles de la paire est publiée avec les deux séries ; `observation_ecriture` publiée (aucune borne normative en 0.1).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 4,
      "blocking": "Mode observation du démon non construit (CT-2 révision 0.6)."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "latence ajoutée en mode observation",
      "unit": "ms",
      "target": {
        "p50": 5,
        "p99": 50
      },
      "comparison": "p50_et_p99_au_plus",
      "source": "CT-8 EX-12.5",
      "failure_threshold": "p50 > 5 ms ou p99 > 50 ms",
      "method": "paire_avec_sans",
      "percentiles": [
        "p50",
        "p95",
        "p99",
        "max"
      ],
      "warmup": 2000,
      "repetitions": 20000,
      "result_name": "observation_latence",
      "conditions": [
        "mode observation",
        "paire avec et sans l'enregistreur"
      ]
    }
  },
  {
    "id": "TM-39",
    "level": "TM",
    "title": "EX-11.19 de CT-8 : disponibilité et format du journal d'accès aux objets chez chaque fournisseur de support WORM",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 EX-11.19",
      "CT-8 §11.10",
      "CT-8 §15"
    ],
    "preconditions": [
      "Un support WORM par fournisseur visé (S3, Azure, GCS), journal d'accès activé au pas IC-9 ; collecteur de CT-8 §11.10."
    ],
    "steps": [
      "Lire et écrire un objet ; attendre la publication du journal d'accès ; relever le délai, le format et les champs présents ; convertir une ligne par le collecteur.",
      "Rapport : une ligne par fournisseur, `text_value` = format relevé, `value` = délai de publication en s."
    ],
    "oracle": "Chaque fournisseur : journal présent, convertible par le collecteur ; `journal_acces_support` n'est tenu pour acquis qu'alors.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "Supports réels à la porte 2 ; collecteur à écrire (CT-8 §11.10)."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "présence, format et délai du journal d'accès du support WORM",
      "unit": "texte",
      "target": "présent et convertible par le collecteur",
      "comparison": "egalite",
      "source": "CT-8 EX-11.19",
      "failure_threshold": "un fournisseur sans journal lisible",
      "method": "lecture_api",
      "percentiles": [],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "journal_acces_support_s3",
      "conditions": [
        "un support par fournisseur"
      ]
    }
  },
  {
    "id": "TM-40",
    "level": "TM",
    "title": "IP-5 de CT-8 : ordre des champs de `chronyc -c tracking` relevé sur chrony 4.6",
    "specs": [
      "CT-8"
    ],
    "covers": [
      "CT-8 IP-5",
      "CT-8 §B.2"
    ],
    "preconditions": [
      "Hôte avec chrony 4.6 installé et synchronisé."
    ],
    "steps": [
      "Exécuter `chronyc -c tracking` ; comparer l'ordre des champs à celui que suppose le contrôle préalable (statut de saut, `System time`, `Root dispersion`, `Root delay`).",
      "Rapport : ligne `chronyc_ordre_champs`, `text_value` = ordre relevé."
    ],
    "oracle": "Ordre relevé égal à l'ordre supposé par IP-5 ; sinon le contrôle préalable est corrigé (proposition PD- à CT-8).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 7,
      "blocking": "chrony absent de l'environnement de rédaction ; relevé à faire sur le système de référence."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "ordre des champs de chronyc -c tracking",
      "unit": "texte",
      "target": "ordre supposé par IP-5",
      "comparison": "egalite",
      "source": "CT-8 IP-5",
      "failure_threshold": "un ordre différent",
      "method": "releve",
      "percentiles": [],
      "warmup": 0,
      "repetitions": 1,
      "result_name": "chronyc_ordre_champs",
      "conditions": [
        "chrony 4.6"
      ]
    }
  },
  {
    "id": "TM-41",
    "level": "TM",
    "title": "Fenêtre d'ordre observée `W_ordre` : délai entre un événement et l'inclusion au registre du premier point qui l'engage (CT-5 §3.3 : 60 s + d_registre)",
    "specs": [
      "CT-5",
      "CT-1"
    ],
    "covers": [
      "CT-5 §3.3",
      "CT-5 EX-3.3",
      "CT-1 §10.9"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Mêmes conditions que TM-11 et TM-12 ; horloge de l'enregistreur."
    ],
    "steps": [
      "Pour chaque événement d'une période : instant de réception du reçu d'inclusion de l'ancre du premier point de `tree_size` supérieur, moins `ts` ; rapport : ligne `w_ordre`, `p50`, `p99`, `max`."
    ],
    "oracle": "`p99 ≤ 120` s (60 s + `inclusion_alert_s`) ; publié avec `d_registre` ; cette durée est de conception, aucun dossier ne la prouve (CT-5 §3.3).",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 5,
      "blocking": "Composant d'ancrage non construit."
    },
    "threats": [
      "MN-17"
    ],
    "measure": {
      "measured": null,
      "quantity": "W_ordre : événement → inclusion au registre du premier point",
      "unit": "s",
      "target": 120,
      "comparison": "p99_au_plus",
      "source": "CT-5 EX-3.3",
      "failure_threshold": "p99 > 120 s en fonctionnement nominal",
      "method": "releve",
      "percentiles": [
        "p50",
        "p99",
        "max"
      ],
      "warmup": 0,
      "repetitions": 3600,
      "result_name": "w_ordre",
      "conditions": [
        "c_K = 60 s, registry.checkpoints nouveaux_evenements",
        "horloge de l'enregistreur"
      ]
    }
  },
  {
    "id": "TM-42",
    "level": "TM",
    "title": "Fenêtre de réécriture pour la date, observée : `rewrite_window_end − ts` du premier point contresigné qui engage l'événement ; critère de la porte 2 : au plus 5 minutes",
    "specs": [
      "CT-5",
      "CT-6",
      "CT-1"
    ],
    "covers": [
      "CT-5 §3.3",
      "CT-5 EX-3.3",
      "CT-5 EX-3.5",
      "CT-6 §7.9",
      "CT-6 EX-6.17",
      "CT-1 §10.9"
    ],
    "preconditions": [
      "Système de référence de la porte 2 (section 11.1), nommé dans le rapport ; `fdatasync` actif sur disque local.",
      "Composant d'ancrage et prestataire joignable ; deux configurations : par défaut (`c_K` 60 s, `c_T` 300 s) et celle de la porte 2 (`c_T` 60 s, points chez le principal, cas `cadence-une-minute-principal` de CT-5 §12.3)."
    ],
    "steps": [
      "Pour chaque événement d'une période, exporter le dossier et lire `facts.checkpoint.rewrite_window_ms` (CT-6 EX-6.17) du premier point contresigné qui l'engage ; convertir en s.",
      "Publier les deux configurations : ligne `w_date_defaut` (cible de conception 300 s + d_jeton) et ligne `w_date_porte_2` (cible du plan : 300 s).",
      "Rapport : `p50`, `p99`, `max` pour chaque ligne."
    ],
    "oracle": "`w_date_porte_2` : `p99 ≤ 300` s (critère de la porte 2) ; `w_date_defaut` : `p99 ≤ 300 + d_jeton` s avec le `d_jeton` de TM-13 ; sinon `met` faux.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 5,
      "blocking": "Composant d'ancrage non construit ; la configuration de la porte 2 (c_T = 60 s) est à confirmer par le plan."
    },
    "threats": [
      "MN-17"
    ],
    "measure": {
      "measured": null,
      "quantity": "W_date : événement → genTime + précision du jeton du premier point contresigné",
      "unit": "s",
      "target": 300,
      "comparison": "p99_au_plus",
      "source": "CT-5 EX-3.3",
      "failure_threshold": "p99 > 300 s avec la configuration de la porte 2 (c_T = 60 s) ; p99 > 300 s + d_jeton avec la configuration par défaut",
      "method": "releve",
      "percentiles": [
        "p50",
        "p99",
        "max"
      ],
      "warmup": 0,
      "repetitions": 3600,
      "result_name": "w_date_porte_2",
      "conditions": [
        "configuration de la porte 2 : c_K = 60 s, c_T = 60 s, points chez le principal",
        "configuration par défaut publiée à côté : c_T = 300 s",
        "valeur rapportée, calculée depuis le ts déclaré (CT-6 §7.9)"
      ]
    }
  },
  {
    "id": "TM-43",
    "level": "TM",
    "title": "EX-19.1 de CT-2 : la démonstration de référence se déroule en moins de deux minutes, temps mesuré et imprimé par `verificateur`",
    "specs": [
      "CT-2"
    ],
    "covers": [
      "CT-2 EX-19.1",
      "CT-2 §19.2"
    ],
    "preconditions": [
      "Démonstration de référence (`docker compose`, CT-2 §19) construite ; images téléchargées à l'avance ; système de référence (EX-11.1) pour que la mesure compte ; une exécution sur un portable, machine visée par CT-2 EX-19.1, PEUT être publiée en plus, avec `reference` faux, `counts_for_targets` faux et `met` null (EX-11.2) ; elle n'est pas exigée, la mesure qui compte pour la cible étant celle du système de référence (EX-11.1)."
    ],
    "steps": [
      "Lancer la démonstration en une commande ; lire la durée imprimée par `verificateur` (CT-2 EX-19.1) : origine au démarrage du processus `verificateur`, fin à l'impression du résultat, horloge monotone de ce processus (EX-11.5) ; la définition exacte des deux instants est proposée à CT-2 (PD-25).",
      "Relever en plus, sur l'horloge murale du harnais, l'intervalle du lancement de la commande unique à la fin de `verificateur` ; le publier dans `conditions` pour recoupement, jamais comparé à la cible (la cible est jugée sur la valeur imprimée, EX-11.14). La commande unique est celle de CT-2 §19 (`docker compose up`), qui ne rend pas la main tant que les autres services tournent : le harnais la termine à la fin de `verificateur`, sans l'arrêter à la fin d'`agent-demo`, qui se termine avant lui (CT-2 §19.1), et consigne le moyen employé dans `conditions` ; `--exit-code-from verificateur` ne convient pas tel quel, puisqu'il implique `--abort-on-container-exit`, qui arrête tous les conteneurs dès que l'un d'eux s'arrête (annexe B.4) ; `docker compose up --detach` suivi de `docker compose wait verificateur`, qui bloque jusqu'à l'arrêt de ce service, en est un. Le recoupement a un objet : si `verificateur` démarre après la fin d'`agent-demo`, la durée murale et la durée imprimée divergent ; l'écart, publié dans `conditions`, est consigné comme écart connu et rattaché à PD-25 (définition des deux instants par CT-2).",
      "Au moins trois exécutions d'échauffement puis au moins dix répétitions (EX-11.3), nombres écrits dans le rapport ; ligne `demonstration_duree`, `max`. Une répétition qui imprime une durée est un échantillon quel que soit le code de retour de `verificateur` (EX-11.4 : aucun échantillon n'est retiré) ; un code non nul fait échouer TE-3, dont l'oracle exige la sortie de CT-2 §19.4, pas TM-43 ; une répétition sans durée imprimée n'est pas un échantillon et, sous les dix échantillons qu'EX-11.3 exige, la ligne porte `excluded_reason` `echantillon_insuffisant` (EX-11.3) ; les codes de retour de chaque répétition sont publiés dans `conditions` de la ligne."
    ],
    "oracle": "`max < 120` s (120,0 s exactement est un échec) ; la comparaison porte sur la valeur imprimée par `verificateur`, à la précision que CT-2 fixe (PD-25 : millisecondes ou trois décimales de seconde ; avec une impression en secondes entières, une exécution de 119,6 s imprimée « 120 s » est un échec, EX-11.14) ; sinon `met` faux.",
    "status": {
      "state": "a_ecrire",
      "phase2_step": 8,
      "blocking": "Démonstration de référence non construite (étape 8 : tests de bout en bout)."
    },
    "threats": [],
    "measure": {
      "measured": null,
      "quantity": "durée de la démonstration de référence",
      "unit": "s",
      "target": 120,
      "comparison": "strictement_inferieur",
      "source": "CT-2 EX-19.1",
      "failure_threshold": "120 s ou plus (120,0 s exactement est un échec), images déjà téléchargées",
      "method": "releve",
      "percentiles": [
        "max"
      ],
      "warmup": 3,
      "repetitions": 10,
      "result_name": "demonstration_duree",
      "conditions": [
        "images déjà téléchargées",
        "sans clé d'API ni accès à Internet",
        "durée imprimée par `verificateur` : origine au démarrage de ce processus, fin à l'impression, horloge monotone (PD-25 à CT-2 pour la définition exacte)",
        "recoupement : durée murale du lancement de la commande unique à la fin de `verificateur`, publiée, non comparée à la cible ; moyen de terminer la commande et écart avec la durée imprimée consignés (PD-25)"
      ]
    }
  }
];
