// Source de données du catalogue CT-9 : risques acceptés (10.6). Nom, borne,
// porteur et menace viennent de menaces.json ; l'ordre et la colonne « non testé »
// sont fixés ici.

export const RISQUES_ACCEPTES = [
  {
    "id": "RA-1",
    "not_tested": "qu'aucune voie hors du pare-feu déclaré n'existe : seul l'essai de sortie du client (CT-7 EX-3.13) s'en approche"
  },
  {
    "id": "RA-2",
    "not_tested": "l'exactitude de run_id et on_behalf_of déclarés par l'hôte"
  },
  {
    "id": "RA-3",
    "not_tested": "un fractionnement sous des règles et plafonds que le client n'a pas écrits"
  },
  {
    "id": "RA-4",
    "not_tested": "une liste d'exclusion contournée par une forme que la validation signale sans l'interdire"
  },
  {
    "id": "RA-5",
    "not_tested": "la lecture attentive des approbateurs sous le plafond"
  },
  {
    "id": "RA-6",
    "not_tested": "un changement de définition qui garde la même empreinte, ou une définition trompeuse dès la première lecture"
  },
  {
    "id": "RA-7",
    "not_tested": "le vol du jeton d'un hôte légitime, qui journalise sous l'identité du jeton"
  },
  {
    "id": "RA-8",
    "not_tested": "une évasion du bac à sable propre au noyau de l'hôte"
  },
  {
    "id": "RA-9",
    "not_tested": "l'écriture exécutée côté serveur entre le pas 9 et la panne, hors de toute intention"
  },
  {
    "id": "RA-10",
    "not_tested": "une clé de fournisseur copiée hors de la passerelle par un autre canal"
  },
  {
    "id": "RA-11",
    "not_tested": "ce que le fournisseur exécute côté serveur quand provider_mcp vaut relayer"
  },
  {
    "id": "RA-12",
    "not_tested": "la capture en lecture seule (mode miroir) qui ne bloque rien, par construction"
  },
  {
    "id": "RA-13",
    "not_tested": "la véracité des arguments déclarés par le SDK (chemin déclaratif)"
  },
  {
    "id": "RA-14",
    "not_tested": "la véracité des spans d'une source authentifiée"
  },
  {
    "id": "RA-15",
    "not_tested": "la réécriture des événements que le dernier point ancré n'engage pas encore (fenêtre d'au plus c_K)",
    "measured_by": [
      "TM-13",
      "TM-42"
    ]
  },
  {
    "id": "RA-16",
    "not_tested": "un acte vu par l'enregistreur et jamais journalisé, ou un dossier défavorable non exporté"
  },
  {
    "id": "RA-17",
    "not_tested": "une fourche sur un stockage qui ne vérifie pas le jeton de clôture"
  },
  {
    "id": "RA-18",
    "not_tested": "une horloge fausse mais cohérente dans la tolérance"
  },
  {
    "id": "RA-19",
    "not_tested": "un accès au stockage par un privilège du système hors du modèle de CT-2"
  },
  {
    "id": "RA-20",
    "not_tested": "une configuration d'exploitation changée hors de policy avant l'adoption de PA-2"
  },
  {
    "id": "RA-21",
    "not_tested": "la lecture du coffre par le détenteur légitime de la seconde approbation"
  },
  {
    "id": "RA-22",
    "not_tested": "une image malveillante dont l'empreinte est celle publiée (chaîne de construction compromise)"
  },
  {
    "id": "RA-23",
    "not_tested": "la rétention du support au-delà de ce que son API rend"
  },
  {
    "id": "RA-24",
    "not_tested": "une collusion des deux personnes de la levée"
  },
  {
    "id": "RA-25",
    "not_tested": "la perte d'une copie avant l'échéance de la comparaison horaire"
  },
  {
    "id": "RA-26",
    "not_tested": "la copie de la clé elle-même en classe C ou D, sans signal"
  },
  {
    "id": "RA-27",
    "not_tested": "un compte inférieur du journal d'audit du backend (CT-7 EX-3.7 ne le qualifie pas)"
  },
  {
    "id": "RA-28",
    "not_tested": "une opération d'administration faite hors cérémonie et jamais constatée"
  },
  {
    "id": "RA-29",
    "not_tested": "la disponibilité du signataire : seule la rupture propre est testée"
  },
  {
    "id": "RA-30",
    "not_tested": "la consommation sous deux fois le budget"
  },
  {
    "id": "RA-31",
    "not_tested": "un portefeuille matériel compromis ou un approbateur qui signe sans lire"
  },
  {
    "id": "RA-32",
    "not_tested": "deux personnes réelles qui partagent volontairement une clé déclarée à l'une"
  },
  {
    "id": "RA-33",
    "not_tested": "le vol d'une clé de gouvernance de classe A à C sans trace"
  },
  {
    "id": "RA-34",
    "not_tested": "une réassignation que le client ne sonde pas (CT-4 EX-8.12)"
  },
  {
    "id": "RA-35",
    "not_tested": "une double signature au-delà de f fautifs (hypothèse de consensus)"
  },
  {
    "id": "RA-36",
    "not_tested": "un approvisionnement vers un destinataire admis mais détourné ensuite"
  },
  {
    "id": "RA-37",
    "not_tested": "l'usage des identifiants volés avant leur rotation"
  },
  {
    "id": "RA-38",
    "not_tested": "la qualité des jetons internes, étiquetés non qualifiés par construction"
  },
  {
    "id": "RA-39",
    "not_tested": "la fuite d'un secret par un canal hors du démon (mémoire, cœur, sauvegarde)"
  },
  {
    "id": "RA-40",
    "not_tested": "l'intégrité du service en dehors des remises vérifiables par le noyau"
  },
  {
    "id": "RA-41",
    "not_tested": "une console compromise dont l'empreinte publiée est celle de la version altérée"
  },
  {
    "id": "RA-42",
    "not_tested": "un portefeuille malveillant choisi explicitement par l'approbateur"
  },
  {
    "id": "RA-43",
    "not_tested": "un administrateur de l'annuaire qui valide une inscription qu'il n'a pas vérifiée hors ligne"
  },
  {
    "id": "RA-44",
    "not_tested": "une collusion d'au moins required membres"
  },
  {
    "id": "RA-45",
    "not_tested": "un abaissement de seuil décidé avant l'ouverture du ticket"
  },
  {
    "id": "RA-46",
    "not_tested": "un validateur partenaire complice"
  },
  {
    "id": "RA-47",
    "not_tested": "la confidentialité des métadonnées vues par le relais du parcours c"
  },
  {
    "id": "RA-48",
    "not_tested": "une demande écrite fausse mais consignée"
  },
  {
    "id": "RA-49",
    "not_tested": "au-delà de f validateurs fautifs, et la qualité des opérateurs partenaires"
  },
  {
    "id": "RA-50",
    "not_tested": "une saturation sous la garde d'admission (débit légitime)"
  },
  {
    "id": "RA-51",
    "not_tested": "la réutilisation d'une signature dans une autre instance au même identifiant (hypothèse d'unicité des instances)"
  },
  {
    "id": "RA-52",
    "not_tested": "un squat qui précède l'envoi de l'ancre (course perdue)"
  },
  {
    "id": "RA-53",
    "not_tested": "une faille de contrat sans redéploiement (cycle de publication)"
  },
  {
    "id": "RA-54",
    "not_tested": "un antidatage dans la tolérance clock_tolerance_s, non contredit par une autre ancre"
  },
  {
    "id": "RA-55",
    "not_tested": "l'allongement de la fenêtre de date pendant la panne, qui est mesuré (TM-42), non empêché",
    "measured_by": [
      "TM-42"
    ]
  },
  {
    "id": "RA-56",
    "not_tested": "un arrêt de l'ancrage au-delà de ce que la série des points montre"
  },
  {
    "id": "RA-57",
    "not_tested": "l'environnement d'exécution du vérificateur jusqu'au binaire reproductible de la phase 2"
  },
  {
    "id": "RA-58",
    "not_tested": "le choix des ancres par le réviseur lui-même"
  },
  {
    "id": "RA-59",
    "not_tested": "une chaîne d'en-têtes au-dessus du point de contrôle plus longue que la profondeur minimale et fausse (hypothèse de travail)"
  },
  {
    "id": "RA-60",
    "not_tested": "un jeu de validateurs obtenu de deux opérateurs complices"
  },
  {
    "id": "RA-61",
    "not_tested": "la lecture de la cadence des ancres par un observateur de la chaîne"
  },
  {
    "id": "RA-62",
    "not_tested": "une confirmation hors bande forgée"
  },
  {
    "id": "RA-63",
    "not_tested": "l'exactitude du périmètre déclaré et le choix de ce qui est exporté"
  },
  {
    "id": "RA-64",
    "not_tested": "des alertes coupées entre deux relectures du Lecteur"
  },
  {
    "id": "RA-65",
    "not_tested": "un délai de réponse dans max_response_delay_s"
  },
  {
    "id": "RA-66",
    "not_tested": "une interruption sans point manqué (plus courte que 2 × c_K)",
    "measured_by": [
      "TM-10"
    ]
  },
  {
    "id": "RA-67",
    "not_tested": "une corruption silencieuse d'une ligne complète que la relecture ne couvre pas"
  },
  {
    "id": "RA-68",
    "not_tested": "la véracité du périmètre déclaré"
  },
  {
    "id": "RA-69",
    "not_tested": "une attestation renouvelée avec un périmètre faux"
  },
  {
    "id": "RA-70",
    "not_tested": "un jeu déclaratif différent choisi sciemment"
  },
  {
    "id": "RA-71",
    "not_tested": "une inscription forgée sous la clé de l'événement prouvé par qui détient cette clé"
  },
  {
    "id": "RA-72",
    "not_tested": "la date réelle de rédaction d'une attestation non inscrite"
  },
  {
    "id": "RA-73",
    "not_tested": "les informations que le client choisit d'écrire dans l'attestation"
  },
  {
    "id": "RA-74",
    "not_tested": "un hôte ajouté avant l'adoption de PA-10 et PA-11"
  },
  {
    "id": "RA-75",
    "not_tested": "la vigueur réelle d'une politique de même nom"
  },
  {
    "id": "RA-76",
    "not_tested": "deux personnes réelles qui se prêtent leurs clés de participant"
  },
  {
    "id": "RA-77",
    "not_tested": "l'écart entre l'ancre de D_C et la fin déclarée, que le réviseur juge"
  },
  {
    "id": "RA-78",
    "not_tested": "une restauration hors cérémonie révélée seulement à l'usage de la clé"
  },
  {
    "id": "RA-79",
    "not_tested": "un témoin complice"
  },
  {
    "id": "RA-80",
    "not_tested": "la copie elle-même avant l'adoption de PA-18 et sa mise en place"
  },
  {
    "id": "RA-81",
    "not_tested": "un second outil lui aussi modifié"
  },
  {
    "id": "RA-82",
    "not_tested": "la décision du réviseur face à une attestation non inscrite"
  }
];
