// Copies à l'identique des schémas de spec/schemas que le sous-module
// « registre » emploie (CT-4 §9.4 : index de capture, envoi, issue, demande de
// signature ; CT-4 §4.8 : manifeste d'instance ; CT-6 §11.2 : parties
// registre.json, certificat-commit.json, validateurs.json).
// test/ancrage-registre-capture.test.js les compare membre pour membre aux
// originaux.
export const SCHEMA_OPERATIONS_REGISTRE = Object.freeze({
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://noortrace.example/schemas/v0/operations-registre.schema.json",
  "title": "Formats des opérations du registre, version 0 (CT-4 §7 à §9)",
  "description": "La racine est l'index de capture d'une transaction du registre (CT-4 §9.4) : les réponses JSON-RPC brutes (en-tête, reçus de toutes les transactions du bloc, certificat de commit) sont écrites à côté, telles que reçues, et l'index les désigne par leur nom et leur SHA-256. Les $defs portent la demande de signature (7.7), l'envoi d'une transaction (8.6), la sortie d'une commande des outils de référence (7.2) et le format des fichiers de vecteurs de CT-4 (annexe A). Aucune clé privée n'y figure jamais.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version",
    "role",
    "evm_chain_id",
    "bft_chain_id",
    "contract",
    "transaction_hash",
    "block_number",
    "block_hash",
    "transaction_index",
    "log_index",
    "files",
    "node",
    "validator_set_hash",
    "captured_at",
    "attempts",
    "checks",
    "sending"
  ],
  "properties": {
    "version": {
      "const": 0
    },
    "role": {
      "enum": [
        "deploiement",
        "jeu_approbateurs",
        "assignation",
        "approvisionnement",
        "inscription",
        "revocation",
        "ancre",
        "cloture",
        "administration_jeu",
        "reassignation"
      ],
      "description": "Seuls inscription, ancre et cloture deviennent des entrées de registre.json (CT-6 §11.2.1, CT-4 EX-9.8) ; deploiement sert le manifeste d'instance (evidence, CT-4 EX-4.27, RG-19) ; les autres servent le dossier d'inscription (7.10) et l'exploitation."
    },
    "evm_chain_id": {
      "type": "integer",
      "minimum": 1,
      "maximum": 2147483647
    },
    "bft_chain_id": {
      "type": "string",
      "pattern": "^noortrace-[1-9][0-9]{0,9}-[a-z0-9]{1,16}$",
      "description": "Identifiant BFT de l'instance (CT-4 EX-4.6)."
    },
    "contract": {
      "oneOf": [
        {
          "type": "null"
        },
        {
          "$ref": "#/$defs/adresse"
        }
      ],
      "description": "Adresse du contrat appelé, ou créé pour les rôles deploiement et jeu_approbateurs ; null pour un approvisionnement (virement de NUR, RG-15)."
    },
    "transaction_hash": {
      "$ref": "#/$defs/hex32"
    },
    "block_number": {
      "type": "integer",
      "minimum": 1,
      "maximum": 9007199254740991
    },
    "block_hash": {
      "$ref": "#/$defs/hex32"
    },
    "transaction_index": {
      "type": "integer",
      "minimum": 0,
      "maximum": 255
    },
    "log_index": {
      "oneOf": [
        {
          "type": "null"
        },
        {
          "type": "integer",
          "minimum": 0,
          "maximum": 255
        }
      ],
      "description": "Indice, dans les journaux du reçu de la transaction, du journal prouvé (CP-5) ; null quand le rôle n'en a pas."
    },
    "files": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "block",
        "receipts",
        "certificate"
      ],
      "properties": {
        "block": {
          "$ref": "#/$defs/fichier",
          "description": "Réponse brute de eth_getBlockByNumber(h, false)."
        },
        "receipts": {
          "type": "array",
          "minItems": 1,
          "maxItems": 256,
          "items": {
            "$ref": "#/$defs/fichier"
          },
          "description": "Réponses brutes de eth_getTransactionReceipt, une par transaction du bloc, dans l'ordre de transactions de l'en-tête."
        },
        "certificate": {
          "$ref": "#/$defs/fichier",
          "description": "Réponse brute de noor_getCommitCertificate(h)."
        }
      }
    },
    "node": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "rpc",
        "validator_id"
      ],
      "properties": {
        "rpc": {
          "type": "string",
          "minLength": 1,
          "maxLength": 256,
          "description": "Point JSON-RPC interrogé, sans jeton ni secret."
        },
        "validator_id": {
          "oneOf": [
            {
              "type": "null"
            },
            {
              "type": "string",
              "minLength": 1,
              "maxLength": 128
            }
          ],
          "description": "Identifiant du validateur que l'exploitant déclare derrière ce point, s'il est connu."
        }
      }
    },
    "validator_set_hash": {
      "$ref": "#/$defs/hex32",
      "description": "valset_hash (CT-6 EX-11.8) du jeu du manifeste d'instance (CT-4 §4.8) contre lequel CP-4 a vérifié le certificat."
    },
    "captured_at": {
      "$ref": "#/$defs/horodatage"
    },
    "attempts": {
      "type": "integer",
      "minimum": 1,
      "maximum": 1000,
      "description": "Nombre d'appels à noor_getCommitCertificate pour obtenir le certificat (9.3)."
    },
    "checks": {
      "type": "array",
      "minItems": 6,
      "maxItems": 6,
      "items": {
        "$ref": "#/$defs/verification"
      },
      "description": "CP-1 à CP-6, dans cet ordre."
    },
    "sending": {
      "oneOf": [
        {
          "type": "null"
        },
        {
          "$ref": "#/$defs/envoi"
        }
      ],
      "description": "L'envoi de la transaction par l'outil, quand c'est lui qui l'a envoyée ; null pour une capture d'une transaction d'autrui."
    }
  },
  "$defs": {
    "hex32": {
      "type": "string",
      "pattern": "^0x[0-9a-f]{64}$"
    },
    "adresse": {
      "type": "string",
      "pattern": "^0x[0-9a-f]{40}$"
    },
    "entier_decimal": {
      "type": "string",
      "pattern": "^(0|[1-9][0-9]{0,77})$"
    },
    "horodatage": {
      "type": "string",
      "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$"
    },
    "fichier": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "name",
        "sha256"
      ],
      "properties": {
        "name": {
          "type": "string",
          "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\\.json$",
          "description": "Nom du fichier, dans le répertoire de l'index, sans chemin."
        },
        "sha256": {
          "$ref": "#/$defs/hex32",
          "description": "SHA-256 des octets du fichier, tels que reçus du nœud."
        }
      }
    },
    "statut": {
      "enum": [
        "reussi",
        "echoue",
        "non_execute"
      ]
    },
    "verification": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "id",
        "status",
        "detail"
      ],
      "properties": {
        "id": {
          "type": "string",
          "pattern": "^(OP|CP)-[1-9][0-9]?$"
        },
        "status": {
          "$ref": "#/$defs/statut"
        },
        "detail": {
          "type": "string",
          "maxLength": 1024
        }
      }
    },
    "signature": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "signer",
        "v",
        "r",
        "s"
      ],
      "properties": {
        "signer": {
          "$ref": "#/$defs/adresse"
        },
        "v": {
          "enum": [
            27,
            28
          ]
        },
        "r": {
          "$ref": "#/$defs/hex32"
        },
        "s": {
          "$ref": "#/$defs/hex32"
        }
      }
    },
    "meta_periode": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "org_id",
        "journal_id",
        "period_hash",
        "root",
        "period_start",
        "period_end",
        "first_seq",
        "last_seq",
        "version",
        "uri"
      ],
      "description": "PeriodRegistry.PeriodMeta, champ pour champ depuis le manifeste (CT-1 §10.4) ; bornes en entiers décimaux.",
      "properties": {
        "org_id": {
          "$ref": "#/$defs/hex32"
        },
        "journal_id": {
          "$ref": "#/$defs/hex32"
        },
        "period_hash": {
          "$ref": "#/$defs/hex32"
        },
        "root": {
          "$ref": "#/$defs/hex32"
        },
        "period_start": {
          "$ref": "#/$defs/entier_decimal"
        },
        "period_end": {
          "$ref": "#/$defs/entier_decimal"
        },
        "first_seq": {
          "$ref": "#/$defs/entier_decimal"
        },
        "last_seq": {
          "$ref": "#/$defs/entier_decimal"
        },
        "version": {
          "type": "integer",
          "minimum": 0,
          "maximum": 4294967295
        },
        "uri": {
          "type": "string",
          "pattern": "^[ -~]{0,64}$",
          "description": "Chaîne vide ou au plus 64 caractères ASCII imprimables (RG-5)."
        }
      }
    },
    "demande_signature": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "version",
        "operation",
        "evm_chain_id",
        "contract",
        "fields",
        "digest",
        "eip191_digest",
        "signer_set",
        "signatures",
        "prepared_at"
      ],
      "description": "Ce qu'un signataire reçoit, recalcule et signe (EIP-191) pour une opération du registre (CT-4 §7.7). Le signataire recalcule digest depuis fields, evm_chain_id et contract avant de signer (OP-6, EX-7.10) ; il ne signe jamais un condensé qu'il n'a pas recalculé. Les signatures sont rangées par adresse de signataire croissante (RG-13).",
      "properties": {
        "version": {
          "const": 0
        },
        "operation": {
          "enum": [
            "inscription",
            "revocation",
            "cloture",
            "ancre",
            "administration_jeu"
          ]
        },
        "evm_chain_id": {
          "type": "integer",
          "minimum": 1,
          "maximum": 2147483647
        },
        "contract": {
          "$ref": "#/$defs/adresse",
          "description": "Adresse du contrat qui vérifie la signature : RecorderRegistry, PeriodRegistry, AttestationRegistry ou le CuratorSet administré."
        },
        "fields": {
          "type": "object"
        },
        "digest": {
          "$ref": "#/$defs/hex32",
          "description": "Condensé interne de la section 6, avant préfixe EIP-191."
        },
        "eip191_digest": {
          "$ref": "#/$defs/hex32",
          "description": "keccak256(\"\\x19Ethereum Signed Message:\\n32\" ‖ digest), le hachage que recouvre ecrecover."
        },
        "signer_set": {
          "oneOf": [
            {
              "type": "null"
            },
            {
              "type": "object",
              "additionalProperties": false,
              "required": [
                "curator_set",
                "threshold",
                "height",
                "block_hash"
              ],
              "properties": {
                "curator_set": {
                  "$ref": "#/$defs/adresse"
                },
                "threshold": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 64
                },
                "height": {
                  "type": "integer",
                  "minimum": 0,
                  "maximum": 9007199254740991
                },
                "block_hash": {
                  "$ref": "#/$defs/hex32"
                }
              }
            }
          ],
          "description": "Jeu et seuil lus à la préparation, pour les opérations au seuil (inscription, revocation, cloture) ; null pour ancre et administration_jeu."
        },
        "signatures": {
          "type": "array",
          "maxItems": 64,
          "items": {
            "$ref": "#/$defs/signature"
          }
        },
        "prepared_at": {
          "$ref": "#/$defs/horodatage"
        },
        "expires_at": {
          "oneOf": [
            {
              "type": "null"
            },
            {
              "$ref": "#/$defs/horodatage"
            }
          ],
          "description": "Échéance de la fenêtre de signature, facultative (8.2, EX-8.19) : la console (CT-3 §13) et signer refusent de signer après ; elle ne lie ni le contrat ni un relayeur qui détient déjà les signatures."
        }
      },
      "allOf": [
        {
          "if": {
            "properties": {
              "operation": {
                "const": "inscription"
              }
            }
          },
          "then": {
            "properties": {
              "fields": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                  "org_id",
                  "journal_id",
                  "chain_key",
                  "ed25519_public_key"
                ],
                "properties": {
                  "org_id": {
                    "$ref": "#/$defs/hex32"
                  },
                  "journal_id": {
                    "$ref": "#/$defs/hex32"
                  },
                  "chain_key": {
                    "$ref": "#/$defs/adresse"
                  },
                  "ed25519_public_key": {
                    "$ref": "#/$defs/hex32"
                  }
                }
              },
              "signer_set": {
                "type": "object"
              }
            }
          }
        },
        {
          "if": {
            "properties": {
              "operation": {
                "const": "revocation"
              }
            }
          },
          "then": {
            "properties": {
              "fields": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                  "org_id",
                  "chain_key",
                  "registered_at"
                ],
                "properties": {
                  "org_id": {
                    "$ref": "#/$defs/hex32"
                  },
                  "chain_key": {
                    "$ref": "#/$defs/adresse"
                  },
                  "registered_at": {
                    "$ref": "#/$defs/entier_decimal",
                    "description": "recorderOf(org_id, chain_key).registeredAt lu à la préparation."
                  }
                }
              },
              "signer_set": {
                "type": "object"
              }
            }
          }
        },
        {
          "if": {
            "properties": {
              "operation": {
                "const": "cloture"
              }
            }
          },
          "then": {
            "properties": {
              "fields": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                  "period_meta"
                ],
                "properties": {
                  "period_meta": {
                    "$ref": "#/$defs/meta_periode"
                  }
                }
              },
              "signer_set": {
                "type": "object"
              }
            }
          }
        },
        {
          "if": {
            "properties": {
              "operation": {
                "const": "ancre"
              }
            }
          },
          "then": {
            "properties": {
              "fields": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                  "fingerprint",
                  "doc_type",
                  "issuer"
                ],
                "properties": {
                  "fingerprint": {
                    "$ref": "#/$defs/hex32"
                  },
                  "doc_type": {
                    "$ref": "#/$defs/hex32"
                  },
                  "issuer": {
                    "$ref": "#/$defs/adresse"
                  }
                }
              },
              "signer_set": {
                "type": "null"
              },
              "signatures": {
                "type": "array",
                "maxItems": 1
              }
            }
          }
        },
        {
          "if": {
            "properties": {
              "operation": {
                "const": "administration_jeu"
              }
            }
          },
          "then": {
            "properties": {
              "fields": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                  "op",
                  "arg",
                  "nonce"
                ],
                "properties": {
                  "op": {
                    "enum": [
                      "CuratorSet.addCurator",
                      "CuratorSet.removeCurator",
                      "CuratorSet.setThreshold",
                      "CuratorSet.proposeAdmin",
                      "CuratorSet.acceptAdmin"
                    ]
                  },
                  "arg": {
                    "$ref": "#/$defs/hex32"
                  },
                  "nonce": {
                    "$ref": "#/$defs/entier_decimal"
                  }
                }
              },
              "signer_set": {
                "type": "null"
              },
              "signatures": {
                "type": "array",
                "maxItems": 1
              }
            }
          }
        }
      ]
    },
    "envoi": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "from",
        "to",
        "nonce",
        "type",
        "max_fee_per_gas",
        "max_priority_fee_per_gas",
        "gas_limit",
        "value",
        "raw_transaction",
        "transaction_hash",
        "submitted_to",
        "submitted_at"
      ],
      "description": "Transaction signée par l'outil, gardée pour la reprise (renvoi des mêmes octets, remplacement au même nonce, 8.6).",
      "properties": {
        "from": {
          "$ref": "#/$defs/adresse"
        },
        "to": {
          "oneOf": [
            {
              "type": "null"
            },
            {
              "$ref": "#/$defs/adresse"
            }
          ]
        },
        "nonce": {
          "type": "integer",
          "minimum": 0,
          "maximum": 9007199254740991
        },
        "type": {
          "const": 2
        },
        "max_fee_per_gas": {
          "$ref": "#/$defs/entier_decimal"
        },
        "max_priority_fee_per_gas": {
          "$ref": "#/$defs/entier_decimal"
        },
        "gas_limit": {
          "$ref": "#/$defs/entier_decimal"
        },
        "value": {
          "$ref": "#/$defs/entier_decimal",
          "description": "En wei ; nul sauf pour un approvisionnement par la trésorerie (RG-15)."
        },
        "raw_transaction": {
          "type": "string",
          "pattern": "^0x02([0-9a-f]{2})+$",
          "minLength": 6,
          "maxLength": 1048580,
          "description": "Transaction de type 2 sérialisée (6.7.3), au plus 524 288 octets (borne de l'outil, 8.6) : la longueur est bornée par maxLength, pas par le motif, dont une répétition bornée au-delà de 1000 ne tient pas dans RE2."
        },
        "transaction_hash": {
          "$ref": "#/$defs/hex32"
        },
        "submitted_to": {
          "type": "array",
          "minItems": 1,
          "maxItems": 8,
          "items": {
            "type": "string",
            "minLength": 1,
            "maxLength": 256
          }
        },
        "submitted_at": {
          "$ref": "#/$defs/horodatage"
        }
      }
    },
    "issue": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "version",
        "transaction_hash"
      ],
      "description": "Issue connue d'un envoi, fichier issue-<hachage>.json du répertoire des captures (8.6, EX-8.16) : inclusion (block_number, status), remplacement accepté (state remplacee, replaced_by) ou mise à l'écart (state ecartee) ; un envoi sans fichier d'issue est sans issue connue (OP-3).",
      "properties": {
        "version": {
          "const": 0
        },
        "transaction_hash": {
          "$ref": "#/$defs/hex32"
        },
        "block_number": {
          "type": "integer",
          "minimum": 1,
          "maximum": 9007199254740991
        },
        "status": {
          "enum": [
            "0x0",
            "0x1"
          ]
        },
        "state": {
          "enum": [
            "remplacee",
            "ecartee"
          ]
        },
        "replaced_by": {
          "$ref": "#/$defs/hex32",
          "description": "Hachage du remplaçant au même nonce (state remplacee) ; l'envoi remplacé reste sans issue tant que le remplaçant n'en a pas."
        },
        "replaces": {
          "$ref": "#/$defs/hex32",
          "description": "Hachage de l'envoi que celui-ci remplaçait (state ecartee : l'original a été inclus)."
        },
        "recorded_at": {
          "$ref": "#/$defs/horodatage"
        }
      }
    },
    "sortie": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "version",
        "command",
        "result",
        "exit_code",
        "checks",
        "error",
        "outputs"
      ],
      "description": "Sortie standard, en JSON, d'une commande de scripts/registre/noortrace-registre.mjs (7.2). Révision 0.7 de CT-4 : commande paquet-client (production et contrôle du paquet client, EX-7.30) et ses codes dossier_inacheve, paquet_manifeste à paquet_captures (points 1 à 6 d'EX-7.22) et secret_present (EX-7.21).",
      "properties": {
        "version": {
          "const": 0
        },
        "command": {
          "enum": [
            "etat",
            "cles-essai",
            "inscrire-client",
            "approvisionner",
            "condense",
            "signer",
            "inscrire-cle",
            "revoquer-cle",
            "manifeste-essai",
            "ancrer",
            "clore",
            "administrer-jeu",
            "reassigner",
            "capturer",
            "exporter",
            "verifier",
            "publier-jeu",
            "paquet-client"
          ]
        },
        "result": {
          "enum": [
            "reussi",
            "deja_fait",
            "refuse",
            "echoue",
            "incertain",
            "inutilisable"
          ]
        },
        "exit_code": {
          "enum": [
            0,
            1,
            2,
            3
          ]
        },
        "checks": {
          "type": "array",
          "maxItems": 32,
          "items": {
            "$ref": "#/$defs/verification"
          }
        },
        "error": {
          "oneOf": [
            {
              "type": "null"
            },
            {
              "type": "object",
              "additionalProperties": false,
              "required": [
                "code",
                "check",
                "message"
              ],
              "properties": {
                "code": {
                  "enum": [
                    "usage",
                    "entree_illisible",
                    "reseau_non_developpement",
                    "instance_illisible",
                    "chaine_differente",
                    "jeu_validateurs_different",
                    "code_absent",
                    "noeud_suiveur",
                    "noeud_injoignable",
                    "organisation_existante",
                    "organisation_inconnue",
                    "jeu_invalide",
                    "pas_administrateur",
                    "compte_inattendu",
                    "solde_insuffisant",
                    "provision_excessive",
                    "examen_requis",
                    "transaction_en_attente",
                    "condense_different",
                    "signature_non_canonique",
                    "signataire_hors_jeu",
                    "signatures_insuffisantes",
                    "cle_deja_active",
                    "cle_revoquee",
                    "cle_ed25519_active",
                    "cle_inconnue",
                    "cle_chaine_non_inscrite",
                    "empreinte_squattee",
                    "ancre_manquante",
                    "periode_invalide",
                    "doublon",
                    "discontinuite_temporelle",
                    "discontinuite_sequence",
                    "transaction_refusee",
                    "transaction_annulee",
                    "recu_absent",
                    "certificat_indisponible",
                    "certificat_elague",
                    "certificat_invalide",
                    "capture_incomplete",
                    "cle_invalide",
                    "demande_existante",
                    "demande_expiree",
                    "dossier_inacheve",
                    "paquet_manifeste",
                    "paquet_fichiers",
                    "paquet_forme",
                    "paquet_organisation",
                    "paquet_jeu",
                    "paquet_captures",
                    "secret_present"
                  ]
                },
                "check": {
                  "oneOf": [
                    {
                      "type": "null"
                    },
                    {
                      "type": "string",
                      "pattern": "^(OP|CP)-[1-9][0-9]?$"
                    }
                  ]
                },
                "message": {
                  "type": "string",
                  "minLength": 1,
                  "maxLength": 2048
                }
              }
            }
          ]
        },
        "outputs": {
          "type": "object"
        }
      }
    },
    "cas_vecteur": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "id",
        "description",
        "checks",
        "input",
        "expected",
        "refusal"
      ],
      "properties": {
        "id": {
          "type": "string",
          "pattern": "^[a-z0-9][a-z0-9-]{0,79}$"
        },
        "description": {
          "type": "string",
          "minLength": 1,
          "maxLength": 1024
        },
        "checks": {
          "type": "array",
          "minItems": 1,
          "maxItems": 16,
          "items": {
            "type": "string",
            "pattern": "^(RG|OP|CP)-[1-9][0-9]?$"
          },
          "description": "Vérifications que le cas exerce (section 6 pour RG-, 7.3 pour OP-, 9.4 pour CP-)."
        },
        "input": {
          "type": "object"
        },
        "expected": {
          "oneOf": [
            {
              "type": "null"
            },
            {
              "type": "object"
            }
          ],
          "description": "Valeurs attendues ; null pour un cas de refus, sauf : (a) famille transactions, tout cas dont input.fields est donné : expected porte la transaction recalculée et signée depuis fields (signing_payload, signing_hash, y_parity, r, s, raw_transaction, transaction_hash, from) même quand RG-15 échoue sur les frais, la chaîne, la limite de gaz ou l'objet (transactions de la capture de CT-6, EX-A.4, et cas remplacement-insuffisant, autre-chaine, frais-nuls, frais-inegaux, limite-au-dela-2-24, approvisionnement-excessif, deploiement-avec-destinataire) ; un cas donné par raw_transaction seule a expected null ; (b) familles manifestes et capture : expected.verdicts donne le verdict de chaque vérification et refusal la première en échec (et, pour manifestes, expected.registry l'ancre dérivée, nulle quand RG-20 échoue)."
        },
        "refusal": {
          "oneOf": [
            {
              "type": "null"
            },
            {
              "type": "object",
              "additionalProperties": false,
              "required": [
                "check",
                "code"
              ],
              "properties": {
                "check": {
                  "type": "string",
                  "pattern": "^(RG|OP|CP)-[1-9][0-9]?$"
                },
                "code": {
                  "type": "string",
                  "pattern": "^[a-z][a-z0-9_]{0,63}$"
                }
              }
            }
          ],
          "description": "Première vérification en échec et code d'erreur attendus ; null pour un cas valide."
        }
      }
    },
    "fichier_vecteurs": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "version",
        "family",
        "description",
        "cases"
      ],
      "description": "Un fichier de famille des vecteurs de CT-4 (annexe A.4).",
      "properties": {
        "version": {
          "const": 0
        },
        "family": {
          "enum": [
            "identifiants",
            "doctypes",
            "condenses",
            "empreintes",
            "appels",
            "transactions",
            "manifestes",
            "demandes",
            "inscription",
            "capture"
          ]
        },
        "description": {
          "type": "string",
          "minLength": 1,
          "maxLength": 2048
        },
        "cases": {
          "type": "array",
          "minItems": 1,
          "maxItems": 512,
          "items": {
            "$ref": "#/$defs/cas_vecteur"
          }
        }
      }
    }
  }
});

export const SCHEMA_REGISTRE = Object.freeze({
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://noortrace.example/schemas/v0/registre.schema.json",
  "title": "Parties registre.json et certificat-commit.json d'un dossier de preuve, version 0 (CT-6 §11.2)",
  "description": "Le schéma principal décrit registre.json : une entrée par transaction de registre prouvée (clôture, ancre, inscriptions), chacune avec les champs engagés de l'en-tête de son bloc et tous les reçus du bloc. Le $defs certificat_commit décrit certificat-commit.json : un certificat par bloc, tel que noor_getCommitCertificate le rend. Tout y est déclaratif ; le vérificateur recalcule hachages, racines et condensés (contrôle 8). Révision 0.2 de CT-6 (ajout compatible) : une entrée facultative de rôle ancre_point_de_controle, l'ancre d'un point de contrôle du journal (AttestationRegistry.anchor, docType noortrace/point-de-controle/v0), au plus une, vérifiée par R-11 et rattachée à la partie points-de-controle.json du dossier (K-8).",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version",
    "source",
    "entries"
  ],
  "properties": {
    "version": {
      "const": 0
    },
    "source": {
      "type": "string",
      "minLength": 1,
      "maxLength": 512
    },
    "entries": {
      "type": "array",
      "minItems": 2,
      "maxItems": 17,
      "items": {
        "$ref": "#/$defs/entree"
      },
      "allOf": [
        {
          "contains": {
            "type": "object",
            "properties": {
              "role": {
                "const": "cloture"
              }
            }
          },
          "minContains": 1,
          "maxContains": 1
        },
        {
          "contains": {
            "type": "object",
            "properties": {
              "role": {
                "const": "ancre"
              }
            }
          },
          "minContains": 1,
          "maxContains": 1
        },
        {
          "contains": {
            "type": "object",
            "properties": {
              "role": {
                "const": "inscription"
              }
            }
          },
          "minContains": 0,
          "maxContains": 8
        },
        {
          "contains": {
            "type": "object",
            "properties": {
              "role": {
                "const": "ancre_point_de_controle"
              }
            }
          },
          "minContains": 0,
          "maxContains": 1
        }
      ]
    }
  },
  "$defs": {
    "hex32": {
      "type": "string",
      "pattern": "^0x[0-9a-f]{64}$"
    },
    "adresse": {
      "type": "string",
      "pattern": "^0x[0-9a-f]{40}$"
    },
    "quantite64": {
      "type": "string",
      "pattern": "^0x(0|[1-9a-f][0-9a-f]{0,15})$",
      "description": "Entier de 0 à 2^64 − 1 en quantité JSON-RPC : hexadécimal minuscule sans zéro de tête."
    },
    "quantite256": {
      "type": "string",
      "pattern": "^0x(0|[1-9a-f][0-9a-f]{0,63})$"
    },
    "entree": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "role",
        "block",
        "receipts",
        "transaction_index",
        "log_index",
        "transaction_hash"
      ],
      "properties": {
        "role": {
          "type": "string",
          "enum": [
            "cloture",
            "ancre",
            "inscription",
            "ancre_point_de_controle"
          ],
          "description": "cloture : PeriodRegistry.submitPeriod ; ancre : AttestationRegistry.anchor d'une période ; inscription : RecorderRegistry.registerRecorder ; ancre_point_de_controle (CT-6 révision 0.2) : AttestationRegistry.anchor d'un point de contrôle du journal, au plus une entrée (R-11, K-8)."
        },
        "block": {
          "$ref": "#/$defs/entete"
        },
        "receipts": {
          "type": "array",
          "minItems": 1,
          "maxItems": 256,
          "items": {
            "$ref": "#/$defs/recu"
          }
        },
        "transaction_index": {
          "type": "integer",
          "minimum": 0,
          "maximum": 255
        },
        "log_index": {
          "type": "integer",
          "minimum": 0,
          "maximum": 255
        },
        "transaction_hash": {
          "$ref": "#/$defs/hex32",
          "description": "Déclaratif, rapporté, non vérifié en version 0."
        }
      }
    },
    "entete": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "number",
        "hash",
        "parentHash",
        "timestamp",
        "stateRoot",
        "transactionsRoot",
        "receiptsRoot",
        "gasUsed",
        "gasLimit",
        "baseFeePerGas"
      ],
      "properties": {
        "number": {
          "$ref": "#/$defs/quantite64"
        },
        "hash": {
          "$ref": "#/$defs/hex32"
        },
        "parentHash": {
          "$ref": "#/$defs/hex32"
        },
        "timestamp": {
          "$ref": "#/$defs/quantite64"
        },
        "stateRoot": {
          "$ref": "#/$defs/hex32"
        },
        "transactionsRoot": {
          "$ref": "#/$defs/hex32"
        },
        "receiptsRoot": {
          "$ref": "#/$defs/hex32"
        },
        "gasUsed": {
          "$ref": "#/$defs/quantite64"
        },
        "gasLimit": {
          "$ref": "#/$defs/quantite64"
        },
        "baseFeePerGas": {
          "$ref": "#/$defs/quantite256"
        }
      }
    },
    "recu": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "type",
        "status",
        "cumulativeGasUsed",
        "logs"
      ],
      "properties": {
        "type": {
          "type": "string",
          "enum": [
            "0x0",
            "0x1",
            "0x2",
            "0x3",
            "0x4"
          ]
        },
        "status": {
          "type": "string",
          "enum": [
            "0x0",
            "0x1"
          ]
        },
        "cumulativeGasUsed": {
          "$ref": "#/$defs/quantite64"
        },
        "logs": {
          "type": "array",
          "maxItems": 256,
          "items": {
            "$ref": "#/$defs/journal"
          }
        }
      }
    },
    "journal": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "address",
        "topics",
        "data"
      ],
      "properties": {
        "address": {
          "$ref": "#/$defs/adresse"
        },
        "topics": {
          "type": "array",
          "maxItems": 4,
          "items": {
            "$ref": "#/$defs/hex32"
          }
        },
        "data": {
          "type": "string",
          "maxLength": 262146,
          "pattern": "^0x([0-9a-f]{2})*$"
        }
      }
    },
    "certificat_commit": {
      "title": "certificat-commit.json",
      "description": "Un certificat par hauteur de bloc nommée dans registre.json, chacun étant le champ result de noor_getCommitCertificate. Seuls height, round, chainId, valsetHash, blockHash, proposal.line et precommits[].line sont lus ; les autres champs que le nœud ajoute sont admis et ignorés.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "version",
        "certificates"
      ],
      "properties": {
        "version": {
          "const": 0
        },
        "certificates": {
          "type": "array",
          "minItems": 1,
          "maxItems": 16,
          "items": {
            "$ref": "#/$defs/certificat"
          }
        }
      }
    },
    "certificat": {
      "type": "object",
      "required": [
        "height",
        "round",
        "chainId",
        "valsetHash",
        "blockHash",
        "proposal",
        "precommits"
      ],
      "properties": {
        "height": {
          "$ref": "#/$defs/quantite64"
        },
        "round": {
          "$ref": "#/$defs/quantite64"
        },
        "chainId": {
          "type": "string",
          "minLength": 1,
          "maxLength": 64
        },
        "valsetHash": {
          "$ref": "#/$defs/hex32"
        },
        "blockHash": {
          "$ref": "#/$defs/hex32"
        },
        "proposal": {
          "$ref": "#/$defs/ligne"
        },
        "precommits": {
          "type": "array",
          "minItems": 1,
          "maxItems": 128,
          "items": {
            "$ref": "#/$defs/ligne"
          }
        }
      }
    },
    "ligne": {
      "type": "object",
      "required": [
        "line"
      ],
      "properties": {
        "line": {
          "type": "string",
          "minLength": 1,
          "maxLength": 4194304,
          "description": "Ligne brute de l'enveloppe signée, telle que stockée par le nœud."
        }
      }
    }
  }
});

export const SCHEMA_VALIDATEURS = Object.freeze({
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://noortrace.example/schemas/v0/validateurs.schema.json",
  "title": "Partie validateurs.json d'un dossier de preuve, version 0 (CT-6 §11.2.3)",
  "description": "Le ou les jeux de validateurs que l'exportateur déclare pour les blocs du dossier, dans la forme du fichier validators.json de noorcore, avec leur intervalle de hauteurs et leur provenance. Partie déclarative : le quorum du contrôle 8 se calcule sur le jeu du fichier d'ancres du réviseur ; cette partie ne sert qu'à la cohérence (R-3).",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version",
    "sets"
  ],
  "properties": {
    "version": {
      "const": 0
    },
    "sets": {
      "type": "array",
      "minItems": 1,
      "maxItems": 16,
      "items": {
        "$ref": "#/$defs/jeu_validateurs"
      }
    }
  },
  "$defs": {
    "validateur": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "id",
        "pubKeyHex"
      ],
      "properties": {
        "id": {
          "type": "string",
          "minLength": 1,
          "maxLength": 128
        },
        "pubKeyHex": {
          "type": "string",
          "pattern": "^0x([0-9a-f]{66}|[0-9a-f]{128}|[0-9a-f]{130})$"
        }
      }
    },
    "jeu_validateurs": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "from_height",
        "to_height",
        "validators",
        "source"
      ],
      "properties": {
        "from_height": {
          "type": "integer",
          "minimum": 0,
          "maximum": 9007199254740991
        },
        "to_height": {
          "oneOf": [
            {
              "type": "null"
            },
            {
              "type": "integer",
              "minimum": 0,
              "maximum": 9007199254740991
            }
          ]
        },
        "validators": {
          "type": "array",
          "minItems": 1,
          "maxItems": 128,
          "items": {
            "$ref": "#/$defs/validateur"
          }
        },
        "source": {
          "type": "string",
          "minLength": 1,
          "maxLength": 512
        }
      }
    }
  }
});

export const SCHEMA_INSTANCE_REGISTRE = Object.freeze({
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://noortrace.example/schemas/v0/instance-registre.schema.json",
  "title": "Manifeste d'une instance du registre, version 0 (CT-4 §4.8)",
  "description": "Ce que l'exploitant d'une instance de noorcore publie, hors des dossiers, pour les clients, les opérateurs de validateurs et les réviseurs : identifiants, document de genèse et ligne de règles, version de noorcore et correctifs (par leur nom et leur empreinte, jamais leur contenu), jeux de validateurs avec leurs hauteurs de validité, règle de frais, contrats avec leurs transactions de déploiement et les preuves capturées de leurs blocs, comptes de l'exploitant. Tout y est déclaratif : les vérifications RG-16 à RG-20 de CT-4 recalculent ce qui se recalcule, le reste se recoupe (CT-6 §12.5). Clés en anglais, valeurs énumérées en français sans accent, hexadécimal en minuscules (CT-1 §3).",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version",
    "revision",
    "previous_sha256",
    "published_at",
    "nature",
    "bft_chain_id",
    "evm_chain_id",
    "evm_chain_id_registration",
    "genesis",
    "noorcore",
    "validator_sets",
    "fees",
    "contracts",
    "compilation",
    "accounts",
    "source"
  ],
  "properties": {
    "version": {
      "const": 0
    },
    "revision": {
      "type": "integer",
      "minimum": 1,
      "maximum": 9007199254740991,
      "description": "Numéro de révision du manifeste, croissant de 1 en 1 à partir de 1 (EX-4.25)."
    },
    "previous_sha256": {
      "oneOf": [
        {
          "type": "null"
        },
        {
          "$ref": "#/$defs/hex32"
        }
      ],
      "description": "SHA-256 des octets du fichier de la révision précédente ; null pour la révision 1 (RG-16)."
    },
    "published_at": {
      "$ref": "#/$defs/horodatage"
    },
    "nature": {
      "enum": [
        "developpement",
        "production"
      ],
      "description": "Mêmes valeurs que recorder.environment de CT-2 §15."
    },
    "bft_chain_id": {
      "type": "string",
      "pattern": "^noortrace-[1-9][0-9]{0,9}-[a-z0-9]{1,16}$",
      "description": "Identifiant de chaîne BFT (-chain-id, rules.chainId) : domaine de chaque enveloppe signée par les validateurs (CT-6 EX-11.7), registry.chain_id du fichier d'ancres de CT-6 (RG-20). Le nombre qu'il contient est evm_chain_id (EX-4.6, RG-17)."
    },
    "evm_chain_id": {
      "type": "integer",
      "minimum": 1,
      "maximum": 2147483647,
      "description": "Identifiant EVM (eth_chainId, EIP-155), lié à chaque transaction et à chaque condensé des contrats (block.chainid)."
    },
    "evm_chain_id_registration": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "status",
        "checked_at",
        "source"
      ],
      "properties": {
        "status": {
          "enum": [
            "inscrit",
            "absent",
            "attribue_a_un_tiers"
          ],
          "description": "État de l'identifiant EVM dans le registre public ethereum-lists/chains à la date de consultation (EX-4.7)."
        },
        "checked_at": {
          "$ref": "#/$defs/horodatage"
        },
        "source": {
          "$ref": "#/$defs/texte"
        }
      }
    },
    "genesis": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "file",
        "sha256",
        "rules_line",
        "alloc_total_wei"
      ],
      "properties": {
        "file": {
          "$ref": "#/$defs/chemin"
        },
        "sha256": {
          "$ref": "#/$defs/hex32",
          "description": "SHA-256 des octets du document de genèse publié (RG-17)."
        },
        "rules_line": {
          "type": "string",
          "minLength": 1,
          "maxLength": 512,
          "description": "Ligne de règles canonique que le nœud journalise après « genesis rules: verified against … | » (EX-4.3, RG-17)."
        },
        "alloc_total_wei": {
          "$ref": "#/$defs/decimal",
          "description": "Somme des soldes de genèse, en wei, écrite en décimal : l'offre totale de NUR de l'instance, qui ne peut que baisser (4.5)."
        }
      }
    },
    "noorcore": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "repository",
        "commit",
        "go_version",
        "patches",
        "artifacts"
      ],
      "properties": {
        "repository": {
          "type": "string",
          "pattern": "^https://[^\\s]{1,200}$"
        },
        "commit": {
          "type": "string",
          "pattern": "^[0-9a-f]{40}$"
        },
        "go_version": {
          "type": "string",
          "pattern": "^[0-9]{1,3}\\.[0-9]{1,3}(\\.[0-9]{1,3})?$"
        },
        "patches": {
          "type": "array",
          "maxItems": 16,
          "items": {
            "$ref": "#/$defs/correctif"
          },
          "description": "Correctifs appliqués dans l'ordre de leurs noms, désignés par leur nom et leur empreinte ; leur contenu n'est jamais publié (EX-4.23)."
        },
        "artifacts": {
          "type": "array",
          "minItems": 1,
          "maxItems": 16,
          "items": {
            "$ref": "#/$defs/artefact"
          }
        }
      }
    },
    "validator_sets": {
      "type": "array",
      "minItems": 1,
      "maxItems": 16,
      "items": {
        "$ref": "#/$defs/jeu_publie"
      },
      "description": "Jeux de validateurs avec leurs hauteurs de validité. Les quatre premiers membres de chaque entrée ont la forme exacte d'un jeu du fichier d'ancres de CT-6 (§12.2, $defs/jeu_validateurs) ; RG-20 en dérive registry.validator_sets."
    },
    "fees": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "transaction_type",
        "max_fee_per_gas_wei",
        "max_priority_fee_per_gas_wei",
        "gas_limit",
        "gas_limit_max",
        "provision_days",
        "refill_below_days"
      ],
      "properties": {
        "transaction_type": {
          "const": 2
        },
        "max_fee_per_gas_wei": {
          "const": "1"
        },
        "max_priority_fee_per_gas_wei": {
          "const": "1"
        },
        "gas_limit": {
          "type": "integer",
          "minimum": 1000000,
          "maximum": 16777216,
          "description": "Limite de gaz de chaque transaction des outils (EX-4.17)."
        },
        "gas_limit_max": {
          "const": 16777216
        },
        "provision_days": {
          "type": "integer",
          "minimum": 1,
          "maximum": 366
        },
        "refill_below_days": {
          "type": "integer",
          "minimum": 1,
          "maximum": 366
        },
        "max_daily_budget_gas": {
          "oneOf": [
            {
              "type": "null"
            },
            {
              "type": "integer",
              "minimum": 1,
              "maximum": 9007199254740991
            }
          ],
          "description": "Plafond du budget journalier b_k qu'un approvisionnement peut retenir (EX-8.20) ; facultatif, nul : aucun plafond."
        }
      }
    },
    "contracts": {
      "type": "array",
      "minItems": 4,
      "maxItems": 16,
      "items": {
        "$ref": "#/$defs/contrat"
      },
      "allOf": [
        {
          "contains": {
            "type": "object",
            "properties": {
              "name": {
                "const": "AttestationRegistry"
              }
            }
          }
        },
        {
          "contains": {
            "type": "object",
            "properties": {
              "name": {
                "const": "CuratorSetRegistry"
              }
            }
          }
        },
        {
          "contains": {
            "type": "object",
            "properties": {
              "name": {
                "const": "PeriodRegistry"
              }
            }
          }
        },
        {
          "contains": {
            "type": "object",
            "properties": {
              "name": {
                "const": "RecorderRegistry"
              }
            }
          }
        }
      ]
    },
    "compilation": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "solc",
        "via_ir",
        "optimizer_runs",
        "source_commit"
      ],
      "properties": {
        "solc": {
          "type": "string",
          "pattern": "^[0-9]{1,2}\\.[0-9]{1,2}\\.[0-9]{1,3}$"
        },
        "via_ir": {
          "type": "boolean"
        },
        "optimizer_runs": {
          "type": "integer",
          "minimum": 0,
          "maximum": 4294967295
        },
        "source_commit": {
          "oneOf": [
            {
              "type": "null"
            },
            {
              "type": "string",
              "pattern": "^[0-9a-f]{40}$"
            }
          ],
          "description": "Commit du dépôt NOORTRACE dont contracts/ a été compilé pour le déploiement ; null si aucun commit n'est établi (EX-5.8)."
        }
      }
    },
    "accounts": {
      "type": "array",
      "minItems": 1,
      "maxItems": 64,
      "items": {
        "$ref": "#/$defs/compte"
      },
      "description": "Comptes de l'exploitant, par rôle, avec leurs hauteurs de validité (EX-3.1, 5.5)."
    },
    "source": {
      "$ref": "#/$defs/texte"
    }
  },
  "$defs": {
    "texte": {
      "type": "string",
      "minLength": 1,
      "maxLength": 512
    },
    "chemin": {
      "type": "string",
      "pattern": "^[A-Za-z0-9._-][A-Za-z0-9._/-]{0,255}$",
      "description": "Chemin relatif d'un fichier publié avec le manifeste, ou dans le dépôt public."
    },
    "hex32": {
      "type": "string",
      "pattern": "^0x[0-9a-f]{64}$"
    },
    "adresse": {
      "type": "string",
      "pattern": "^0x[0-9a-f]{40}$"
    },
    "decimal": {
      "type": "string",
      "pattern": "^(0|[1-9][0-9]{0,77})$"
    },
    "hauteur": {
      "type": "integer",
      "minimum": 0,
      "maximum": 9007199254740991
    },
    "horodatage": {
      "type": "string",
      "pattern": "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\\.[0-9]{3}Z$",
      "description": "RFC 3339, UTC, trois décimales, suffixe Z (CT-1 §3) ; la date doit exister."
    },
    "fichier": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "file",
        "sha256"
      ],
      "properties": {
        "file": {
          "$ref": "#/$defs/chemin"
        },
        "sha256": {
          "$ref": "#/$defs/hex32"
        }
      }
    },
    "correctif": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "name",
        "sha256",
        "effect"
      ],
      "properties": {
        "name": {
          "type": "string",
          "pattern": "^[0-9]{4}-[A-Za-z0-9._-]{1,96}\\.patch$"
        },
        "sha256": {
          "$ref": "#/$defs/hex32"
        },
        "effect": {
          "$ref": "#/$defs/texte"
        }
      }
    },
    "artefact": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "kind",
        "name",
        "sha256",
        "build"
      ],
      "properties": {
        "kind": {
          "enum": [
            "binaire",
            "image"
          ]
        },
        "name": {
          "type": "string",
          "minLength": 1,
          "maxLength": 256
        },
        "sha256": {
          "$ref": "#/$defs/hex32",
          "description": "SHA-256 du fichier binaire, ou condensé du manifeste de l'image conteneur."
        },
        "build": {
          "$ref": "#/$defs/texte"
        }
      }
    },
    "validateur": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "id",
        "pubKeyHex"
      ],
      "properties": {
        "id": {
          "type": "string",
          "minLength": 1,
          "maxLength": 128
        },
        "pubKeyHex": {
          "type": "string",
          "pattern": "^0x([0-9a-f]{66}|[0-9a-f]{128}|[0-9a-f]{130})$",
          "description": "Clé publique secp256k1 telle que validators.json la déclare ; le hachage du jeu porte sur ces octets (CT-6 EX-11.8)."
        }
      }
    },
    "operateur": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "validator",
        "operator",
        "site",
        "retention_heights"
      ],
      "properties": {
        "validator": {
          "type": "string",
          "minLength": 1,
          "maxLength": 128
        },
        "operator": {
          "type": "string",
          "minLength": 1,
          "maxLength": 128,
          "description": "Organisation qui exploite le validateur et détient sa clé."
        },
        "site": {
          "type": "string",
          "minLength": 1,
          "maxLength": 128,
          "description": "Domaine de panne : site, région ou machine ; jamais une adresse réseau."
        },
        "retention_heights": {
          "oneOf": [
            {
              "type": "null"
            },
            {
              "type": "integer",
              "minimum": 1,
              "maximum": 9007199254740991
            }
          ],
          "description": "Rétention des certificats de commit déclarée par l'opérateur (NOOR_BFT_CERT_RETENTION_HEIGHTS) ; null si inconnue."
        }
      }
    },
    "jeu_publie": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "from_height",
        "to_height",
        "validators",
        "source",
        "valset_hash",
        "operators"
      ],
      "properties": {
        "from_height": {
          "$ref": "#/$defs/hauteur"
        },
        "to_height": {
          "oneOf": [
            {
              "type": "null"
            },
            {
              "$ref": "#/$defs/hauteur"
            }
          ]
        },
        "validators": {
          "type": "array",
          "minItems": 4,
          "maxItems": 128,
          "items": {
            "$ref": "#/$defs/validateur"
          }
        },
        "source": {
          "$ref": "#/$defs/texte"
        },
        "valset_hash": {
          "$ref": "#/$defs/hex32",
          "description": "Hachage du jeu selon CT-6 EX-11.8, recalculé par RG-18."
        },
        "operators": {
          "type": "array",
          "minItems": 4,
          "maxItems": 128,
          "items": {
            "$ref": "#/$defs/operateur"
          }
        }
      }
    },
    "preuve_deploiement": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "capture"
      ],
      "properties": {
        "capture": {
          "$ref": "#/$defs/fichier",
          "description": "Index de capture (CT-4 §9.4, operations-registre-v0, rôle deploiement) de la transaction de déploiement : en-tête, reçus de toutes les transactions du bloc et certificat de commit, capturés auprès d'un validateur avant l'élagage (EX-4.27)."
        }
      }
    },
    "contrat": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "name",
        "address",
        "deployer",
        "nonce",
        "constructor_args",
        "transaction_hash",
        "block_number",
        "block_hash",
        "evidence",
        "to_height"
      ],
      "properties": {
        "name": {
          "enum": [
            "AttestationRegistry",
            "CuratorSetRegistry",
            "PeriodRegistry",
            "RecorderRegistry"
          ]
        },
        "address": {
          "$ref": "#/$defs/adresse"
        },
        "deployer": {
          "$ref": "#/$defs/adresse"
        },
        "nonce": {
          "type": "integer",
          "minimum": 0,
          "maximum": 9007199254740991,
          "description": "Nonce du déployeur pour la transaction de création ; address = CREATE(deployer, nonce) (RG-19)."
        },
        "constructor_args": {
          "type": "array",
          "maxItems": 4,
          "items": {
            "$ref": "#/$defs/adresse"
          }
        },
        "transaction_hash": {
          "$ref": "#/$defs/hex32"
        },
        "block_number": {
          "type": "integer",
          "minimum": 1,
          "maximum": 9007199254740991
        },
        "block_hash": {
          "oneOf": [
            {
              "type": "null"
            },
            {
              "$ref": "#/$defs/hex32"
            }
          ],
          "description": "null tant que le hachage du bloc n'est pas relevé ; non nul en production (RG-19, EX-4.28)."
        },
        "evidence": {
          "oneOf": [
            {
              "type": "null"
            },
            {
              "$ref": "#/$defs/preuve_deploiement"
            }
          ],
          "description": "null tant que la capture du bloc de déploiement n'est pas faite ; non nul en production (EX-4.27, EX-4.28)."
        },
        "to_height": {
          "oneOf": [
            {
              "type": "null"
            },
            {
              "$ref": "#/$defs/hauteur"
            }
          ],
          "description": "Hauteur après laquelle le contrat n'est plus en service (remplacé, EX-5.9) ; null s'il l'est."
        }
      }
    },
    "compte": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "role",
        "address",
        "from_height",
        "to_height"
      ],
      "properties": {
        "role": {
          "enum": [
            "tresorerie",
            "deployeur",
            "administrateur_registre",
            "relayeur"
          ]
        },
        "address": {
          "$ref": "#/$defs/adresse"
        },
        "from_height": {
          "$ref": "#/$defs/hauteur"
        },
        "to_height": {
          "oneOf": [
            {
              "type": "null"
            },
            {
              "$ref": "#/$defs/hauteur"
            }
          ]
        }
      }
    }
  }
});
