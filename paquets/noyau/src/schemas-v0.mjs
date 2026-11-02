// Copie à l'identique des cinq schémas JSON que CT-1 version 0.4 nomme
// (spec/schemas/*.json, draft 2020-12). La bibliothèque est pure et ne lit
// aucun fichier : les schémas sont embarqués ici. Le test
// test/noyau.test.js exige l'égalité, membre pour membre, de chaque copie avec
// son fichier de spec/schemas ; une copie qui dériverait le fait échouer.
// Ne pas modifier à la main : recopier le fichier de spec/schemas.

function gelerProfond(o) {
  if (o && typeof o === "object") {
    for (const v of Object.values(o)) gelerProfond(v);
    Object.freeze(o);
  }
  return o;
}

/** Copie de spec/schemas/evenement-v0.schema.json (`$id` https://noortrace.example/schemas/v0/evenement.schema.json). */
export const SCHEMA_EVENEMENT = gelerProfond({
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://noortrace.example/schemas/v0/evenement.schema.json",
  "title": "Événement de journal NOORTRACE, version 0",
  "description": "Un événement signé et chaîné du journal d'un enregistreur NOORTRACE : enveloppe (version, seq, ts, org_id, journal_id, recorder_key_id, prev_hash, hash, sig) et les huit champs du modèle. Spécification : spec/CT-1-evenements-et-formats.md. Les contraintes qu'un schéma ne peut pas exprimer (hash et sig recalculés, chaînage, longueurs égales des tableaux approvers et signatures) sont celles du vérificateur.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version",
    "seq",
    "ts",
    "org_id",
    "journal_id",
    "recorder_key_id",
    "prev_hash",
    "delegation",
    "code",
    "intent",
    "policy",
    "approval",
    "execution",
    "effects",
    "context",
    "hash",
    "sig"
  ],
  "properties": {
    "version": {
      "const": 0,
      "description": "Version du format d'événement."
    },
    "seq": {
      "$ref": "#/$defs/seq",
      "description": "Numéro de séquence dans le journal, entier strictement positif, incrémenté de 1 à chaque événement."
    },
    "ts": {
      "$ref": "#/$defs/horodatage",
      "description": "Instant de l'événement selon l'horloge de l'enregistreur, RFC 3339 UTC avec millisecondes."
    },
    "org_id": {
      "$ref": "#/$defs/hex32",
      "description": "Identifiant de l'organisation (bytes32), celui de RecorderRegistry et PeriodRegistry."
    },
    "journal_id": {
      "$ref": "#/$defs/hex32",
      "description": "Identifiant du journal (bytes32), jamais nul."
    },
    "recorder_key_id": {
      "$ref": "#/$defs/identifiant_cle",
      "description": "Identifiant de la clé Ed25519 de l'enregistreur qui a produit sig."
    },
    "prev_hash": {
      "$ref": "#/$defs/hex32",
      "description": "hash de l'événement précédent du journal ; 32 octets nuls pour seq = 1."
    },
    "delegation": {
      "$ref": "#/$defs/delegation"
    },
    "code": {
      "$ref": "#/$defs/code"
    },
    "intent": {
      "description": "Ce que l'agent déclare vouloir faire : texte, ou référence si volumineux ou rédigé, ou null.",
      "oneOf": [
        {
          "type": "string",
          "maxLength": 4096
        },
        {
          "$ref": "#/$defs/reference"
        },
        {
          "type": "null"
        }
      ]
    },
    "policy": {
      "$ref": "#/$defs/policy"
    },
    "approval": {
      "description": "Décision d'approbation humaine liée à l'événement, ou null.",
      "oneOf": [
        {
          "$ref": "#/$defs/approval"
        },
        {
          "type": "null"
        }
      ]
    },
    "execution": {
      "$ref": "#/$defs/execution"
    },
    "effects": {
      "type": "array",
      "description": "Ressources lues, écrites, supprimées, envoyées ou exécutées. Vide si aucun effet.",
      "items": {
        "$ref": "#/$defs/effect"
      },
      "maxItems": 1024
    },
    "context": {
      "type": "array",
      "description": "Provenance du contexte : références aux documents, données et mémoire utilisés.",
      "items": {
        "$ref": "#/$defs/context_item"
      },
      "maxItems": 1024
    },
    "hash": {
      "$ref": "#/$defs/hex32",
      "description": "SHA-256(\"noortrace/evenement/v0\\n\" || JCS(événement sans hash ni sig))."
    },
    "sig": {
      "$ref": "#/$defs/signature_ed25519",
      "description": "Ed25519(clé recorder_key_id, \"noortrace/signature-evenement/v0\\n\" || JCS(événement sans hash ni sig))."
    }
  },
  "$defs": {
    "hex32": {
      "type": "string",
      "pattern": "^0x[0-9a-f]{64}$",
      "description": "32 octets en hexadécimal minuscule préfixé 0x (66 caractères)."
    },
    "signature_ed25519": {
      "type": "string",
      "pattern": "^0x[0-9a-f]{128}$",
      "description": "Signature Ed25519 de 64 octets en hexadécimal minuscule préfixé 0x (130 caractères)."
    },
    "signature_eip191": {
      "type": "string",
      "pattern": "^0x[0-9a-f]{130}$",
      "description": "Signature secp256k1 EIP-191 de 65 octets r || s || v (v = 0x1b ou 0x1c), hexadécimal minuscule préfixé 0x (132 caractères)."
    },
    "adresse": {
      "type": "string",
      "pattern": "^0x[0-9a-f]{40}$",
      "description": "Adresse Ethereum de 20 octets, hexadécimal minuscule préfixé 0x (sans somme de contrôle EIP-55)."
    },
    "horodatage": {
      "type": "string",
      "pattern": "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\\.[0-9]{3}Z$",
      "description": "RFC 3339, UTC, exactement trois décimales de seconde, suffixe Z. Les secondes intercalaires ne sont pas représentées. La date doit exister dans le calendrier grégorien proleptique (CT-1 §3) : le motif ne l'exprime pas, le vérificateur refuse (E-1) un horodatage qui respecte le motif mais ne se décode pas (30 février, 31 avril, 29 février hors année bissextile)."
    },
    "seq": {
      "type": "integer",
      "minimum": 1,
      "maximum": 9007199254740991
    },
    "entier_positif_ou_nul": {
      "type": "integer",
      "minimum": 0,
      "maximum": 9007199254740991
    },
    "identifiant_cle": {
      "type": "string",
      "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
    },
    "nom_outil": {
      "type": "string",
      "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$",
      "description": "Nom d'outil MCP tel qu'annoncé par tools/list, ou nom réservé noortrace.* pour les événements qui ne sont pas des appels d'outil."
    },
    "type_mime": {
      "type": "string",
      "pattern": "^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$",
      "maxLength": 127
    },
    "reference": {
      "type": "object",
      "description": "Référence à une pièce conservée chez le client : SHA-256 de ses octets tels que stockés, longueur en octets, drapeau de rédaction. value porte la pièce en ligne quand elle est petite et non rédigée ; la pièce est alors JCS(value). media_type et value sont absentes quand elles ne s'appliquent pas, jamais null (CT-1 §3).",
      "additionalProperties": false,
      "required": [
        "sha256",
        "length",
        "redacted"
      ],
      "properties": {
        "sha256": {
          "$ref": "#/$defs/hex32"
        },
        "length": {
          "$ref": "#/$defs/entier_positif_ou_nul"
        },
        "redacted": {
          "type": "boolean"
        },
        "media_type": {
          "$ref": "#/$defs/type_mime"
        },
        "value": {
          "description": "Valeur JSON en ligne, conforme à JCS v0 (aucun nombre non entier)."
        }
      },
      "if": {
        "properties": {
          "redacted": {
            "const": true
          }
        }
      },
      "then": {
        "properties": {
          "value": false
        }
      }
    },
    "context_item": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "sha256",
        "length",
        "redacted",
        "kind"
      ],
      "properties": {
        "sha256": {
          "$ref": "#/$defs/hex32"
        },
        "length": {
          "$ref": "#/$defs/entier_positif_ou_nul"
        },
        "redacted": {
          "type": "boolean"
        },
        "kind": {
          "type": "string",
          "enum": [
            "document",
            "donnees",
            "memoire",
            "autre"
          ]
        },
        "media_type": {
          "$ref": "#/$defs/type_mime"
        }
      }
    },
    "delegation": {
      "type": "object",
      "description": "Provenance de la délégation : qui a lancé l'agent, pour le compte de qui, avec quels droits.",
      "additionalProperties": false,
      "required": [
        "launched_by",
        "on_behalf_of",
        "scope",
        "run_id"
      ],
      "properties": {
        "launched_by": {
          "type": "string",
          "minLength": 1,
          "maxLength": 256
        },
        "on_behalf_of": {
          "type": [
            "string",
            "null"
          ],
          "maxLength": 256
        },
        "scope": {
          "type": "string",
          "minLength": 1,
          "maxLength": 1024
        },
        "run_id": {
          "type": [
            "string",
            "null"
          ],
          "maxLength": 128
        }
      }
    },
    "code": {
      "type": "object",
      "description": "Provenance du code : version du modèle, du prompt système, de la politique et de l'enregistreur.",
      "additionalProperties": false,
      "required": [
        "model",
        "prompt_version",
        "policy_version",
        "recorder"
      ],
      "properties": {
        "model": {
          "type": [
            "string",
            "null"
          ],
          "maxLength": 256
        },
        "prompt_version": {
          "oneOf": [
            {
              "$ref": "#/$defs/hex32"
            },
            {
              "type": "null"
            }
          ]
        },
        "policy_version": {
          "type": "string",
          "minLength": 1,
          "maxLength": 128
        },
        "recorder": {
          "type": "string",
          "minLength": 1,
          "maxLength": 64
        }
      }
    },
    "policy": {
      "type": "object",
      "description": "Évaluation de politique : règle appliquée, décision, ticket d'approbation, règle de rédaction appliquée aux pièces.",
      "additionalProperties": false,
      "required": [
        "rule",
        "decision",
        "ticket",
        "redaction"
      ],
      "properties": {
        "rule": {
          "type": [
            "string",
            "null"
          ],
          "maxLength": 1024
        },
        "decision": {
          "type": "string",
          "enum": [
            "autorise",
            "a_approuver",
            "refuse",
            "sans_objet"
          ]
        },
        "ticket": {
          "type": [
            "string",
            "null"
          ],
          "maxLength": 128
        },
        "redaction": {
          "type": [
            "string",
            "null"
          ],
          "maxLength": 128
        }
      },
      "allOf": [
        {
          "if": {
            "properties": {
              "decision": {
                "const": "a_approuver"
              }
            }
          },
          "then": {
            "properties": {
              "rule": {
                "type": "string"
              },
              "ticket": {
                "type": "string",
                "minLength": 1
              }
            }
          }
        },
        {
          "if": {
            "properties": {
              "decision": {
                "const": "sans_objet"
              }
            }
          },
          "then": {
            "properties": {
              "rule": {
                "type": "null"
              }
            }
          }
        }
      ]
    },
    "threshold": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "required",
        "size"
      ],
      "properties": {
        "required": {
          "type": "integer",
          "minimum": 1,
          "maximum": 65535
        },
        "size": {
          "type": "integer",
          "minimum": 1,
          "maximum": 65535
        }
      }
    },
    "approval": {
      "type": "object",
      "description": "Décision d'approbation humaine : décision, ticket, hachage de l'événement de demande, seuil, approbateurs, signatures EIP-191 (approvers[i] a produit signatures[i]), instant, motif.",
      "additionalProperties": false,
      "required": [
        "decision",
        "ticket",
        "request_hash",
        "threshold",
        "approvers",
        "signatures",
        "at",
        "reason"
      ],
      "properties": {
        "decision": {
          "type": "string",
          "enum": [
            "approuve",
            "refuse",
            "expire"
          ]
        },
        "ticket": {
          "type": "string",
          "minLength": 1,
          "maxLength": 128
        },
        "request_hash": {
          "$ref": "#/$defs/hex32"
        },
        "threshold": {
          "$ref": "#/$defs/threshold"
        },
        "approvers": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/adresse"
          },
          "uniqueItems": true,
          "maxItems": 65535
        },
        "signatures": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/signature_eip191"
          },
          "maxItems": 65535
        },
        "at": {
          "$ref": "#/$defs/horodatage"
        },
        "reason": {
          "type": [
            "string",
            "null"
          ],
          "maxLength": 1024
        }
      },
      "allOf": [
        {
          "if": {
            "properties": {
              "decision": {
                "const": "expire"
              }
            }
          },
          "then": {
            "properties": {
              "approvers": {
                "type": "array",
                "maxItems": 0
              },
              "signatures": {
                "type": "array",
                "maxItems": 0
              }
            }
          }
        },
        {
          "if": {
            "properties": {
              "decision": {
                "const": "approuve"
              }
            }
          },
          "then": {
            "properties": {
              "approvers": {
                "type": "array",
                "minItems": 1
              },
              "signatures": {
                "type": "array",
                "minItems": 1
              }
            }
          }
        }
      ]
    },
    "execution": {
      "type": "object",
      "description": "Exécution : outil, arguments (référence), statut, résultat (référence), durée, erreur. L'allOf porte la table par sorte de CT-1 §5.3 : result, duration_ms et is_error sont obligatoires (non nuls) pour un appel d'outil exécuté et pour un échange avec le modèle, nuls pour un appel retenu ou refusé et pour les trois autres événements réservés (décision d'approbation, rotation de clé, changement de politique).",
      "additionalProperties": false,
      "required": [
        "tool",
        "arguments",
        "status",
        "result",
        "duration_ms",
        "is_error"
      ],
      "properties": {
        "tool": {
          "$ref": "#/$defs/nom_outil"
        },
        "arguments": {
          "$ref": "#/$defs/reference"
        },
        "status": {
          "type": "string",
          "enum": [
            "executee",
            "retenue",
            "refusee"
          ]
        },
        "result": {
          "oneOf": [
            {
              "$ref": "#/$defs/reference"
            },
            {
              "type": "null"
            }
          ]
        },
        "duration_ms": {
          "oneOf": [
            {
              "$ref": "#/$defs/entier_positif_ou_nul"
            },
            {
              "type": "null"
            }
          ]
        },
        "is_error": {
          "type": [
            "boolean",
            "null"
          ]
        }
      },
      "allOf": [
        {
          "if": {
            "properties": {
              "status": {
                "enum": [
                  "retenue",
                  "refusee"
                ]
              }
            }
          },
          "then": {
            "properties": {
              "result": {
                "type": "null"
              },
              "duration_ms": {
                "type": "null"
              },
              "is_error": {
                "type": "null"
              }
            }
          }
        },
        {
          "if": {
            "properties": {
              "status": {
                "const": "executee"
              },
              "tool": {
                "type": "string",
                "anyOf": [
                  {
                    "not": {
                      "pattern": "^noortrace\\."
                    }
                  },
                  {
                    "const": "noortrace.modele.echange"
                  }
                ]
              }
            }
          },
          "then": {
            "properties": {
              "result": {
                "$ref": "#/$defs/reference"
              },
              "duration_ms": {
                "type": "integer"
              },
              "is_error": {
                "type": "boolean"
              }
            }
          }
        },
        {
          "if": {
            "properties": {
              "tool": {
                "type": "string",
                "enum": [
                  "noortrace.approbation.decision",
                  "noortrace.journal.rotation-cle",
                  "noortrace.journal.politique"
                ]
              }
            }
          },
          "then": {
            "properties": {
              "result": {
                "type": "null"
              },
              "duration_ms": {
                "type": "null"
              },
              "is_error": {
                "type": "null"
              }
            }
          }
        },
        {
          "if": {
            "properties": {
              "tool": {
                "type": "string",
                "pattern": "^noortrace\\."
              }
            }
          },
          "then": {
            "properties": {
              "tool": {
                "type": "string",
                "enum": [
                  "noortrace.modele.echange",
                  "noortrace.approbation.decision",
                  "noortrace.journal.rotation-cle",
                  "noortrace.journal.politique"
                ]
              }
            }
          }
        }
      ]
    },
    "effect": {
      "type": "object",
      "description": "Un effet sur un système du client. amount et currency sont tous deux null ou tous deux renseignés.",
      "additionalProperties": false,
      "required": [
        "system",
        "action",
        "object",
        "amount",
        "currency"
      ],
      "properties": {
        "system": {
          "type": "string",
          "minLength": 1,
          "maxLength": 128
        },
        "action": {
          "type": "string",
          "enum": [
            "lecture",
            "ecriture",
            "suppression",
            "envoi",
            "execution"
          ]
        },
        "object": {
          "type": "string",
          "minLength": 1,
          "maxLength": 512
        },
        "amount": {
          "type": [
            "string",
            "null"
          ],
          "pattern": "^-?(0|[1-9][0-9]*)(\\.[0-9]{1,8})?$"
        },
        "currency": {
          "type": [
            "string",
            "null"
          ],
          "pattern": "^[A-Z]{3}$"
        }
      },
      "allOf": [
        {
          "if": {
            "properties": {
              "amount": {
                "type": "null"
              }
            }
          },
          "then": {
            "properties": {
              "currency": {
                "type": "null"
              }
            }
          }
        },
        {
          "if": {
            "properties": {
              "amount": {
                "type": "string"
              }
            }
          },
          "then": {
            "properties": {
              "currency": {
                "type": "string"
              }
            }
          }
        }
      ]
    }
  }
});

/** Copie de spec/schemas/manifeste-v0.schema.json (`$id` https://noortrace.example/schemas/v0/manifeste.schema.json). */
export const SCHEMA_MANIFESTE = gelerProfond({
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://noortrace.example/schemas/v0/manifeste.schema.json",
  "title": "Manifeste de période NOORTRACE, version 0",
  "description": "Le manifeste d'une période horaire d'un journal : bornes de temps et de séquence, nombre d'événements, racine de Merkle RFC 6962, chaînage avec la période précédente, clé de l'enregistreur, nonce. periodHash = SHA-256(\"noortrace/manifeste/v0\\n\" || JCS(manifeste)). La signature Ed25519 du manifeste est portée à côté (manifeste.sig), jamais dedans. Les relations arithmétiques (period_end = period_start + 3600, count = last_seq - first_seq + 1, racine nulle si et seulement si count = 0) sont vérifiées par le vérificateur.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version",
    "org_id",
    "journal_id",
    "period_start",
    "period_end",
    "first_seq",
    "last_seq",
    "count",
    "root",
    "prev_period_hash",
    "recorder_key_id",
    "nonce",
    "generated_at"
  ],
  "properties": {
    "version": {
      "const": 0
    },
    "org_id": {
      "$ref": "#/$defs/hex32"
    },
    "journal_id": {
      "$ref": "#/$defs/hex32"
    },
    "period_start": {
      "type": "integer",
      "minimum": 0,
      "maximum": 9007199254740991,
      "multipleOf": 3600,
      "description": "Début de la période, secondes UNIX, heure UTC pleine (inclus)."
    },
    "period_end": {
      "type": "integer",
      "minimum": 3600,
      "maximum": 9007199254740991,
      "multipleOf": 3600,
      "description": "Fin de la période, secondes UNIX, heure UTC pleine (exclue) : period_start + 3600."
    },
    "first_seq": {
      "type": "integer",
      "minimum": 1,
      "maximum": 9007199254740991
    },
    "last_seq": {
      "type": "integer",
      "minimum": 0,
      "maximum": 9007199254740991,
      "description": "Dernier seq de la période ; first_seq - 1 pour une période vide."
    },
    "count": {
      "type": "integer",
      "minimum": 0,
      "maximum": 9007199254740991
    },
    "root": {
      "$ref": "#/$defs/hex32",
      "description": "Racine de Merkle RFC 6962 des hash des événements de la période ; 32 octets nuls pour une période vide (convention NOORTRACE imposée par PeriodRegistry)."
    },
    "prev_period_hash": {
      "$ref": "#/$defs/hex32",
      "description": "periodHash de la période précédente du même journal ; 32 octets nuls pour la première période."
    },
    "recorder_key_id": {
      "type": "string",
      "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
    },
    "nonce": {
      "$ref": "#/$defs/hex32",
      "description": "32 octets aléatoires : deux clôtures d'une même heure n'ont jamais la même empreinte."
    },
    "generated_at": {
      "type": "string",
      "pattern": "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\\.[0-9]{3}Z$",
      "description": "Instant de production du manifeste, RFC 3339 UTC à trois décimales ; la date doit exister dans le calendrier grégorien proleptique (CT-1 §3)."
    }
  },
  "allOf": [
    {
      "if": {
        "properties": {
          "count": {
            "const": 0
          }
        }
      },
      "then": {
        "properties": {
          "root": {
            "const": "0x0000000000000000000000000000000000000000000000000000000000000000"
          }
        }
      },
      "else": {
        "properties": {
          "root": {
            "not": {
              "const": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }
          }
        }
      }
    }
  ],
  "$defs": {
    "hex32": {
      "type": "string",
      "pattern": "^0x[0-9a-f]{64}$"
    }
  }
});

/** Copie de spec/schemas/point-de-controle-v0.schema.json (`$id` https://noortrace.example/schemas/v0/point-de-controle.schema.json). */
export const SCHEMA_POINT_DE_CONTROLE = gelerProfond({
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://noortrace.example/schemas/v0/point-de-controle.schema.json",
  "title": "Point de contrôle NOORTRACE, version 0 (CT-1 révision 0.3, §10.5)",
  "description": "Tête signée de l'arbre de Merkle de la période en cours, produite par l'enregistreur à cadence courte (défaut : au plus 60 s entre deux points, et un point à la clôture). root est la racine RFC 6962 des tree_size premières feuilles de la période (règle de hachage de CT-1 §9.1 ; 32 octets nuls si tree_size = 0), last_seq le seq du dernier événement couvert (first_seq - 1 si tree_size = 0), last_hash son hash recalculé (32 octets nuls si le journal est vide). checkpointHash = SHA-256(\"noortrace/point-de-controle/v0\\n\" || JCS(point sans sig)) ; sig = Ed25519(clé key_id, \"noortrace/signature-point-de-controle/v0\\n\" || JCS(point sans sig)). Contrairement au manifeste, la signature est portée dans l'objet, et le hachage ne la couvre pas. prev_checkpoint_hash est le checkpointHash du point précédent de la même période, 32 octets nuls pour le premier point de la période. Le dernier point d'une période a tree_size = count et root = root du manifeste. Les relations arithmétiques (last_seq = first_seq + tree_size - 1, racine nulle si et seulement si tree_size = 0, tree_size non décroissant le long de la chaîne) sont vérifiées par le vérificateur (CT-1 §11.4, K-1 à K-6).",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version",
    "org_id",
    "journal_id",
    "period_start",
    "tree_size",
    "root",
    "last_seq",
    "last_hash",
    "checkpoint_ts",
    "prev_checkpoint_hash",
    "key_id",
    "sig"
  ],
  "properties": {
    "version": {
      "const": 0
    },
    "org_id": {
      "$ref": "#/$defs/hex32"
    },
    "journal_id": {
      "$ref": "#/$defs/hex32"
    },
    "period_start": {
      "type": "integer",
      "minimum": 0,
      "maximum": 9007199254740991,
      "multipleOf": 3600,
      "description": "Début de la période couverte, secondes UNIX, heure UTC pleine : le period_start du manifeste de la même période."
    },
    "tree_size": {
      "type": "integer",
      "minimum": 0,
      "maximum": 9007199254740991,
      "description": "Nombre n de feuilles engagées : les n premiers événements de la période, dans l'ordre des seq. 0 pour un point de preuve de vie avant le premier événement de la période."
    },
    "root": {
      "$ref": "#/$defs/hex32",
      "description": "Racine RFC 6962 des n premières feuilles (CT-1 §9.1) ; 32 octets nuls si et seulement si tree_size = 0 (convention de la période vide, CT-1 §9.2)."
    },
    "last_seq": {
      "type": "integer",
      "minimum": 0,
      "maximum": 9007199254740991,
      "description": "seq du dernier événement couvert : first_seq + tree_size - 1 ; first_seq - 1 si tree_size = 0."
    },
    "last_hash": {
      "$ref": "#/$defs/hex32",
      "description": "hash de l'événement last_seq (tête de chaîne) ; 32 octets nuls si last_seq = 0 (journal vide)."
    },
    "checkpoint_ts": {
      "type": "string",
      "pattern": "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\\.[0-9]{3}Z$",
      "description": "Instant de production du point, horloge de l'enregistreur, RFC 3339 UTC à trois décimales (déclaratif : seule une contresignature extérieure date le point) ; la date doit exister dans le calendrier grégorien proleptique (CT-1 §3) ; supérieur ou égal à period_start et non décroissant le long de la chaîne des points."
    },
    "prev_checkpoint_hash": {
      "$ref": "#/$defs/hex32",
      "description": "checkpointHash du point précédent de la même période ; 32 octets nuls pour le premier point de la période."
    },
    "key_id": {
      "type": "string",
      "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
      "description": "Identifiant de la clé Ed25519 de l'enregistreur qui signe le point : la clé en vigueur à checkpoint_ts (même règle que recorder_key_id du manifeste, CT-1 §10.1) ; même espace de noms que recorder_key_id."
    },
    "sig": {
      "type": "string",
      "pattern": "^0x[0-9a-f]{128}$",
      "description": "Signature Ed25519 de \"noortrace/signature-point-de-controle/v0\\n\" || JCS(point sans sig) par la clé key_id."
    }
  },
  "allOf": [
    {
      "if": {
        "properties": {
          "tree_size": {
            "const": 0
          }
        }
      },
      "then": {
        "properties": {
          "root": {
            "const": "0x0000000000000000000000000000000000000000000000000000000000000000"
          }
        }
      },
      "else": {
        "properties": {
          "root": {
            "not": {
              "const": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }
          }
        }
      }
    }
  ],
  "$defs": {
    "hex32": {
      "type": "string",
      "pattern": "^0x[0-9a-f]{64}$"
    }
  }
});

/** Copie de spec/schemas/attestation-perimetre-v0.schema.json (`$id` https://noortrace.example/schemas/v0/attestation-perimetre.schema.json). */
export const SCHEMA_ATTESTATION_PERIMETRE = gelerProfond({
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://noortrace.example/schemas/v0/attestation-perimetre.schema.json",
  "title": "Attestation de périmètre de capture NOORTRACE, version 0 (CT-7 §7, CT-1 révision 0.4)",
  "description": "Le schéma principal décrit l'attestation P : le document que l'administrateur du client remplit et que des membres du jeu d'approbateurs de l'organisation signent. Son condensé est D_P = keccak256(\"noortrace/attestation-perimetre/v0\\n\" || JCS(P)), signé en EIP-191 version 0x45 (CT-1 §6.3). Les $defs décrivent l'attestation signée (attestation_signee), le jeu d'approbateurs déclaré (jeu_approbateurs) et le fichier de cas des vecteurs ct-7/attestations (cas_attestation, fichier_vecteurs). Les relations que le schéma n'exprime pas (validity.from <= validity.until, journal de chaque agent parmi journals, adresses distinctes) relèvent de AT-1 ; le condensé, les signatures et le seuil de AT-2 à AT-4 (CT-1 §11.4). Une attestation est déclarative : sa vérification établit qui l'a signée, jamais que son contenu est vrai.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version",
    "org",
    "journals",
    "validity",
    "issued_at",
    "prepared_by",
    "agents",
    "tools_via_proxy_only",
    "egress",
    "gateway_credentials",
    "not_captured",
    "signatories",
    "declaration"
  ],
  "properties": {
    "version": {
      "const": 0
    },
    "org": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "org_id",
        "slug",
        "name"
      ],
      "properties": {
        "org_id": {
          "$ref": "#/$defs/hex32",
          "description": "Identifiant d'organisation de CT-1 §3, celui des événements des journaux couverts."
        },
        "slug": {
          "type": "string",
          "pattern": "^[a-z0-9][a-z0-9-]{0,63}$",
          "description": "Nom court de l'organisation, celui d'où org_id est dérivé (CT-4) ; déclaratif."
        },
        "name": {
          "type": "string",
          "minLength": 1,
          "maxLength": 256
        }
      }
    },
    "journals": {
      "type": "array",
      "minItems": 1,
      "maxItems": 64,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "journal_id",
          "name"
        ],
        "properties": {
          "journal_id": {
            "$ref": "#/$defs/hex32"
          },
          "name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128
          }
        }
      },
      "description": "Journaux couverts ; journal_id distincts (AT-1)."
    },
    "validity": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "from",
        "until"
      ],
      "properties": {
        "from": {
          "$ref": "#/$defs/horodatage"
        },
        "until": {
          "$ref": "#/$defs/horodatage"
        }
      },
      "description": "Période de validité déclarée, bornes incluses ; from <= until (AT-1). L'événement prouvé y tombe (AT-5)."
    },
    "issued_at": {
      "$ref": "#/$defs/horodatage",
      "description": "Instant de rédaction déclaré par l'administrateur ; non prouvé."
    },
    "prepared_by": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "identity",
        "function"
      ],
      "properties": {
        "identity": {
          "type": "string",
          "minLength": 1,
          "maxLength": 256,
          "description": "Identité de l'administrateur du client, telle que son système d'identité la nomme (même forme que delegation.launched_by, CT-1 §5.3)."
        },
        "function": {
          "type": "string",
          "minLength": 1,
          "maxLength": 256
        }
      }
    },
    "agents": {
      "type": "array",
      "minItems": 1,
      "maxItems": 4096,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "agent_id",
          "journal_id",
          "host",
          "framework",
          "capture_channels",
          "notes"
        ],
        "properties": {
          "agent_id": {
            "type": "string",
            "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"
          },
          "journal_id": {
            "$ref": "#/$defs/hex32",
            "description": "Journal où l'agent est capturé ; l'un des journal_id de journals (AT-1)."
          },
          "host": {
            "type": "string",
            "minLength": 1,
            "maxLength": 256,
            "description": "Nom d'inventaire de l'hôte de l'agent ; jamais une adresse IP, ni un secret."
          },
          "framework": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "description": "Cadre ou hôte d'agent (nom et version), dans le vocabulaire du client."
          },
          "capture_channels": {
            "type": "array",
            "minItems": 1,
            "maxItems": 6,
            "uniqueItems": true,
            "items": {
              "$ref": "#/$defs/canal_capture"
            }
          },
          "notes": {
            "type": [
              "string",
              "null"
            ],
            "minLength": 1,
            "maxLength": 1024
          }
        }
      },
      "description": "Inventaire des agents ; agent_id distincts (AT-1)."
    },
    "tools_via_proxy_only": {
      "type": "array",
      "maxItems": 1024,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "server_alias",
          "tools",
          "enforcement"
        ],
        "properties": {
          "server_alias": {
            "type": "string",
            "pattern": "^[a-z0-9][a-z0-9-]{0,31}$",
            "description": "Alias du serveur d'outils dans policy.servers de la configuration de l'enregistreur (CT-2 EX-4.9)."
          },
          "tools": {
            "type": "array",
            "minItems": 1,
            "maxItems": 1024,
            "uniqueItems": true,
            "items": {
              "type": "string",
              "pattern": "^(\\*|[A-Za-z0-9][A-Za-z0-9._:/-]{0,127})$"
            },
            "description": "Noms d'outils, ou \"*\" pour tous les outils du serveur."
          },
          "enforcement": {
            "type": "string",
            "minLength": 1,
            "maxLength": 1024,
            "description": "Comment l'organisation empêche de joindre ce serveur sans passer par le mandataire (règle de pare-feu, réseau, identifiants) ; déclaratif."
          }
        }
      }
    },
    "egress": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "default_policy",
        "rules_sha256",
        "rules_format",
        "summary",
        "allowed_destinations"
      ],
      "properties": {
        "default_policy": {
          "enum": [
            "refus_par_defaut",
            "autorisation_par_defaut"
          ]
        },
        "rules_sha256": {
          "$ref": "#/$defs/hex32",
          "description": "SHA-256 des octets de l'export des règles de sortie tel que le client le conserve ; le fichier n'est pas joint."
        },
        "rules_format": {
          "type": "string",
          "minLength": 1,
          "maxLength": 128
        },
        "summary": {
          "type": "string",
          "minLength": 1,
          "maxLength": 4096
        },
        "allowed_destinations": {
          "type": "array",
          "maxItems": 1024,
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": [
              "name",
              "via",
              "description"
            ],
            "properties": {
              "name": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256
              },
              "via": {
                "enum": [
                  "enregistreur",
                  "mandataire_sortant",
                  "direct"
                ],
                "description": "enregistreur : seul le démon de l'enregistreur joint la destination ; mandataire_sortant : par le mandataire HTTPS du client (ICAP ou miroir) ; direct : joignable sans capture, à déclarer aussi dans not_captured."
              },
              "description": {
                "type": "string",
                "minLength": 1,
                "maxLength": 1024
              }
            }
          }
        }
      }
    },
    "gateway_credentials": {
      "type": "array",
      "maxItems": 1024,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "route",
          "provider_label",
          "secret_ref"
        ],
        "properties": {
          "route": {
            "type": "string",
            "pattern": "^/[A-Za-z0-9._~/-]{0,255}$",
            "description": "path de la route du frontal modèle (policy.model.routes, CT-2 EX-5.2)."
          },
          "provider_label": {
            "type": "string",
            "pattern": "^[a-z0-9][a-z0-9.-]{0,31}$"
          },
          "secret_ref": {
            "$ref": "#/$defs/reference_secret"
          }
        }
      },
      "description": "Identifiants d'API que seule la passerelle détient : leur désignation, jamais leur valeur."
    },
    "not_captured": {
      "type": "array",
      "maxItems": 1024,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "channel",
          "description",
          "compensating_control"
        ],
        "properties": {
          "channel": {
            "type": "string",
            "minLength": 1,
            "maxLength": 256
          },
          "description": {
            "type": "string",
            "minLength": 1,
            "maxLength": 1024
          },
          "compensating_control": {
            "type": [
              "string",
              "null"
            ],
            "minLength": 1,
            "maxLength": 1024
          }
        }
      },
      "description": "Exceptions connues : ce que l'organisation sait ne pas être capturé. Un tableau vide déclare qu'aucune exception n'est connue, non qu'il n'en existe pas."
    },
    "signatories": {
      "type": "array",
      "minItems": 1,
      "maxItems": 64,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "name",
          "function",
          "address"
        ],
        "properties": {
          "name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 256
          },
          "function": {
            "type": "string",
            "minLength": 1,
            "maxLength": 256
          },
          "address": {
            "$ref": "#/$defs/adresse"
          }
        }
      },
      "description": "Personnes appelées à signer, adresses distinctes (AT-1) ; chaque signature porte l'adresse d'un signataire (AT-4)."
    },
    "declaration": {
      "type": "string",
      "minLength": 1,
      "maxLength": 4096,
      "description": "Texte que les signataires déclarent, en clair ; il n'entre jamais dans l'énoncé du vérificateur."
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
    "signature_eip191": {
      "type": "string",
      "pattern": "^0x[0-9a-f]{130}$"
    },
    "horodatage": {
      "type": "string",
      "pattern": "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\\.[0-9]{3}Z$",
      "description": "RFC 3339, UTC, trois décimales, suffixe Z ; date existante du calendrier grégorien (CT-1 §3), contrôlée par AT-1."
    },
    "canal_capture": {
      "enum": [
        "mandataire_mcp",
        "passerelle",
        "icap",
        "miroir",
        "sdk",
        "opentelemetry"
      ],
      "description": "Canal par lequel l'enregistreur voit l'agent (CT-2 §4, §5.1, §6) : frontal MCP, frontal modèle en mode passerelle, icap ou miroir, point d'entrée du SDK, ingestion OpenTelemetry."
    },
    "reference_secret": {
      "description": "Désignation d'un secret par son emplacement, même forme que CT-2 §15.2 sans encoding : exactement une des clés env, file, vault.",
      "oneOf": [
        {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "env"
          ],
          "properties": {
            "env": {
              "type": "string",
              "pattern": "^[A-Z][A-Z0-9_]{0,127}$"
            }
          }
        },
        {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "file"
          ],
          "properties": {
            "file": {
              "type": "string",
              "pattern": "^/[^\\u0000]{1,4095}$"
            }
          }
        },
        {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "vault"
          ],
          "properties": {
            "vault": {
              "type": "object",
              "additionalProperties": false,
              "required": [
                "path",
                "field"
              ],
              "properties": {
                "path": {
                  "type": "string",
                  "minLength": 1,
                  "maxLength": 512
                },
                "field": {
                  "type": "string",
                  "minLength": 1,
                  "maxLength": 128
                }
              }
            }
          }
        }
      ]
    },
    "jeu_approbateurs": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "threshold",
        "members",
        "source"
      ],
      "properties": {
        "threshold": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "required",
            "size"
          ],
          "properties": {
            "required": {
              "type": "integer",
              "minimum": 1,
              "maximum": 65535
            },
            "size": {
              "type": "integer",
              "minimum": 1,
              "maximum": 65535
            }
          }
        },
        "members": {
          "type": "array",
          "minItems": 1,
          "maxItems": 65535,
          "uniqueItems": true,
          "items": {
            "$ref": "#/$defs/adresse"
          }
        },
        "source": {
          "type": "string",
          "minLength": 1,
          "maxLength": 256
        }
      },
      "description": "Jeu d'approbateurs déclaré, même forme que approver_set de approbations.json (CT-1 §11.2) ; déclaratif, avec sa source."
    },
    "attestation_signee": {
      "title": "Attestation signée",
      "description": "Ce que l'administrateur du client remet : l'attestation P, son condensé D_P déclaré (recalculé par AT-2) et les signatures EIP-191 des signataires sur D_P, chacune avec l'adresse qu'elle doit recouvrer (AT-3).",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "version",
        "attestation",
        "digest",
        "signatures"
      ],
      "properties": {
        "version": {
          "const": 0
        },
        "attestation": {
          "$ref": "#"
        },
        "digest": {
          "$ref": "#/$defs/hex32"
        },
        "signatures": {
          "type": "array",
          "minItems": 1,
          "maxItems": 64,
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": [
              "address",
              "signature"
            ],
            "properties": {
              "address": {
                "$ref": "#/$defs/adresse"
              },
              "signature": {
                "$ref": "#/$defs/signature_eip191"
              }
            }
          }
        }
      }
    },
    "statut_at": {
      "enum": [
        "reussi",
        "echoue",
        "non_execute"
      ]
    },
    "cas_attestation": {
      "title": "Cas de la famille ct-7/attestations",
      "description": "Une attestation signée et un jeu déclaré, soumis hors de tout dossier aux vérifications AT-1 à AT-4 ; input est libre pour qu'un cas invalide puisse violer le schéma (AT-1).",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "name",
        "description",
        "input",
        "expected"
      ],
      "properties": {
        "name": {
          "type": "string",
          "pattern": "^[a-z0-9][a-z0-9-]{0,63}$"
        },
        "description": {
          "type": "string",
          "minLength": 1,
          "maxLength": 1024
        },
        "input": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "signed",
            "approver_set"
          ],
          "properties": {
            "signed": {},
            "approver_set": {}
          }
        },
        "expected": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "digest",
            "recovered",
            "checks",
            "retained"
          ],
          "properties": {
            "digest": {
              "oneOf": [
                {
                  "$ref": "#/$defs/hex32"
                },
                {
                  "type": "null"
                }
              ],
              "description": "D_P recalculé, null si AT-1 échoue."
            },
            "recovered": {
              "type": [
                "array",
                "null"
              ],
              "items": {
                "oneOf": [
                  {
                    "$ref": "#/$defs/adresse"
                  },
                  {
                    "type": "null"
                  }
                ]
              },
              "description": "Adresse recouvrée de chaque signature, dans l'ordre, null pour une signature non recouvrable ou non canonique ; null si AT-3 n'est pas exécutée."
            },
            "checks": {
              "type": "array",
              "minItems": 4,
              "maxItems": 4,
              "items": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                  "id",
                  "status",
                  "reason"
                ],
                "properties": {
                  "id": {
                    "enum": [
                      "AT-1",
                      "AT-2",
                      "AT-3",
                      "AT-4"
                    ]
                  },
                  "status": {
                    "$ref": "#/$defs/statut_at"
                  },
                  "reason": {
                    "oneOf": [
                      {
                        "enum": [
                          "prerequis_en_echec"
                        ]
                      },
                      {
                        "type": "null"
                      }
                    ]
                  }
                }
              }
            },
            "retained": {
              "type": "boolean",
              "description": "Vrai si et seulement si AT-1 à AT-4 réussissent."
            }
          }
        }
      }
    },
    "fichier_vecteurs": {
      "title": "Fichier de la famille ct-7/attestations",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "version",
        "family",
        "prefix_hex",
        "cases"
      ],
      "properties": {
        "version": {
          "const": 0
        },
        "family": {
          "const": "attestations"
        },
        "prefix_hex": {
          "const": "6e6f6f7274726163652f6174746573746174696f6e2d706572696d657472652f76300a"
        },
        "cases": {
          "type": "array",
          "minItems": 1,
          "items": {
            "$ref": "#/$defs/cas_attestation"
          }
        }
      }
    },
    "croises": {
      "title": "Fichier ct-7/attestations/croises.json (CT-7 EX-A.9)",
      "description": "Signatures croisées d'un même compte sur des objets de domaines différents (décision D_A, texte d'inscription, procès-verbal D_C, condensé du registre, attestation D_P), chacune présentée pour un autre domaine et refusée par la vérification nommée. target est absent quand l'objet présenté est l'attestation de l'exemple.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "version",
        "family",
        "account",
        "address",
        "attestation_digest",
        "cases"
      ],
      "properties": {
        "version": {
          "const": 0
        },
        "family": {
          "const": "croises"
        },
        "account": {
          "type": "integer",
          "minimum": 0,
          "maximum": 19
        },
        "address": {
          "$ref": "#/$defs/adresse"
        },
        "attestation_digest": {
          "$ref": "#/$defs/hex32"
        },
        "cases": {
          "type": "array",
          "minItems": 1,
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": [
              "name",
              "description",
              "message",
              "signature",
              "presented_as",
              "expected"
            ],
            "properties": {
              "name": {
                "type": "string",
                "pattern": "^[a-z0-9-]+$"
              },
              "description": {
                "type": "string",
                "minLength": 1
              },
              "message": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                  "kind"
                ],
                "properties": {
                  "kind": {
                    "enum": [
                      "approbation",
                      "inscription",
                      "ceremonie",
                      "registre",
                      "attestation"
                    ]
                  },
                  "digest": {
                    "$ref": "#/$defs/hex32"
                  },
                  "text": {
                    "type": "string",
                    "minLength": 1
                  },
                  "case": {
                    "type": "string",
                    "minLength": 1
                  }
                }
              },
              "signature": {
                "$ref": "#/$defs/signature_eip191"
              },
              "presented_as": {
                "enum": [
                  "attestation",
                  "approbation",
                  "inscription",
                  "ceremonie"
                ]
              },
              "target": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                  "digest": {
                    "$ref": "#/$defs/hex32"
                  },
                  "text": {
                    "type": "string",
                    "minLength": 1
                  },
                  "case": {
                    "type": "string",
                    "minLength": 1
                  }
                }
              },
              "expected": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                  "check",
                  "status",
                  "recovered"
                ],
                "properties": {
                  "check": {
                    "type": "string",
                    "pattern": "^CT-[1-7] [A-Z]{1,2}-[0-9]+$"
                  },
                  "status": {
                    "const": "echoue"
                  },
                  "recovered": {
                    "oneOf": [
                      {
                        "type": "null"
                      },
                      {
                        "$ref": "#/$defs/adresse"
                      }
                    ]
                  }
                }
              }
            }
          }
        }
      }
    },
    "grille_attestation": {
      "description": "Grille de l'épreuve à l'aveugle de l'administrateur du client (`acceptation-attestation-attendu.json`, CT-7 EX-9.4, EX-9.5) ; jamais remise à la personne éprouvée.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "version",
        "test",
        "rule",
        "success",
        "questions"
      ],
      "properties": {
        "version": {
          "const": 0
        },
        "test": {
          "const": "acceptation-attestation"
        },
        "rule": {
          "type": "string"
        },
        "success": {
          "type": "string",
          "minLength": 1
        },
        "questions": {
          "type": "array",
          "minItems": 1,
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": [
              "id",
              "question",
              "expected"
            ],
            "properties": {
              "id": {
                "type": "string",
                "pattern": "^Q[1-9]$"
              },
              "question": {
                "type": "string",
                "minLength": 1
              },
              "expected": {
                "type": "array",
                "minItems": 1,
                "items": {
                  "type": "string"
                }
              }
            }
          }
        }
      }
    }
  }
});

/** Copie de spec/schemas/dossier-v0.schema.json (`$id` https://noortrace.example/schemas/v0/dossier.schema.json). */
export const SCHEMA_DOSSIER = gelerProfond({
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://noortrace.example/schemas/v0/dossier.schema.json",
  "title": "Dossier de preuve NOORTRACE, version 0 : index dossier.json et fichiers compagnons",
  "description": "Le schéma principal décrit l'index dossier.json. Les $defs voisins, chemin, manifeste_sig, cles et approbations décrivent les fichiers compagnons du même répertoire ; evenement.json se valide contre le schéma d'événement et manifeste.json contre le schéma de manifeste. Les douze parties sont toujours déclarées, dans cet ordre, présentes ou absentes avec leur raison. La révision 0.3 de CT-1 ajoute une treizième partie facultative, points_de_controle (points-de-controle.json, $defs points_de_controle), déclarée en treizième position quand le dossier la connaît, présente ou absente avec une raison ; un index à douze parties reste valide. La révision 0.4 de CT-1 ajoute une quatorzième partie facultative, attestation_perimetre (attestation-perimetre.json, $defs attestation_perimetre), qui n'est déclarée qu'en quatorzième position, la treizième (points_de_controle, présente ou absente avec sa raison) étant alors déclarée ; un index à douze ou treize parties reste valide.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version",
    "event",
    "org_id",
    "journal_id",
    "generated_at",
    "parts"
  ],
  "properties": {
    "version": {
      "const": 0
    },
    "event": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "seq",
        "hash"
      ],
      "properties": {
        "seq": {
          "type": "integer",
          "minimum": 1,
          "maximum": 9007199254740991
        },
        "hash": {
          "$ref": "#/$defs/hex32"
        }
      }
    },
    "org_id": {
      "$ref": "#/$defs/hex32"
    },
    "journal_id": {
      "$ref": "#/$defs/hex32"
    },
    "generated_at": {
      "$ref": "#/$defs/horodatage"
    },
    "parts": {
      "type": "array",
      "description": "Douze parties (format v0 d'origine), treize (révision 0.3 : la partie facultative points_de_controle en treizième position) ou quatorze (révision 0.4 : points_de_controle en treizième position, présente ou absente, puis la partie facultative attestation_perimetre en quatorzième), toujours dans cet ordre.",
      "oneOf": [
        {
          "minItems": 12,
          "maxItems": 12,
          "items": false,
          "prefixItems": [
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "evenement"
                },
                "file": {
                  "const": "evenement.json"
                },
                "present": {
                  "const": true
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "voisins"
                },
                "file": {
                  "const": "voisins.json"
                },
                "present": {
                  "const": true
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "chemin"
                },
                "file": {
                  "const": "chemin.json"
                },
                "present": {
                  "const": true
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "manifeste"
                },
                "file": {
                  "const": "manifeste.json"
                },
                "present": {
                  "const": true
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "manifeste_sig"
                },
                "file": {
                  "const": "manifeste.sig"
                },
                "present": {
                  "const": true
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "cles"
                },
                "file": {
                  "const": "cles.json"
                },
                "present": {
                  "const": true
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "approbations"
                },
                "file": {
                  "const": "approbations.json"
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "jeton_rfc3161"
                },
                "file": {
                  "const": "jeton-rfc3161.der"
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "preuve_ots"
                },
                "file": {
                  "const": "preuve.ots"
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "registre"
                },
                "file": {
                  "const": "registre.json"
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "certificat_commit"
                },
                "file": {
                  "const": "certificat-commit.json"
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "validateurs"
                },
                "file": {
                  "const": "validateurs.json"
                }
              }
            }
          ]
        },
        {
          "minItems": 13,
          "maxItems": 13,
          "items": false,
          "prefixItems": [
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "evenement"
                },
                "file": {
                  "const": "evenement.json"
                },
                "present": {
                  "const": true
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "voisins"
                },
                "file": {
                  "const": "voisins.json"
                },
                "present": {
                  "const": true
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "chemin"
                },
                "file": {
                  "const": "chemin.json"
                },
                "present": {
                  "const": true
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "manifeste"
                },
                "file": {
                  "const": "manifeste.json"
                },
                "present": {
                  "const": true
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "manifeste_sig"
                },
                "file": {
                  "const": "manifeste.sig"
                },
                "present": {
                  "const": true
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "cles"
                },
                "file": {
                  "const": "cles.json"
                },
                "present": {
                  "const": true
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "approbations"
                },
                "file": {
                  "const": "approbations.json"
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "jeton_rfc3161"
                },
                "file": {
                  "const": "jeton-rfc3161.der"
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "preuve_ots"
                },
                "file": {
                  "const": "preuve.ots"
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "registre"
                },
                "file": {
                  "const": "registre.json"
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "certificat_commit"
                },
                "file": {
                  "const": "certificat-commit.json"
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "validateurs"
                },
                "file": {
                  "const": "validateurs.json"
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "points_de_controle"
                },
                "file": {
                  "const": "points-de-controle.json"
                }
              }
            }
          ]
        },
        {
          "minItems": 14,
          "maxItems": 14,
          "items": false,
          "prefixItems": [
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "evenement"
                },
                "file": {
                  "const": "evenement.json"
                },
                "present": {
                  "const": true
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "voisins"
                },
                "file": {
                  "const": "voisins.json"
                },
                "present": {
                  "const": true
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "chemin"
                },
                "file": {
                  "const": "chemin.json"
                },
                "present": {
                  "const": true
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "manifeste"
                },
                "file": {
                  "const": "manifeste.json"
                },
                "present": {
                  "const": true
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "manifeste_sig"
                },
                "file": {
                  "const": "manifeste.sig"
                },
                "present": {
                  "const": true
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "cles"
                },
                "file": {
                  "const": "cles.json"
                },
                "present": {
                  "const": true
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "approbations"
                },
                "file": {
                  "const": "approbations.json"
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "jeton_rfc3161"
                },
                "file": {
                  "const": "jeton-rfc3161.der"
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "preuve_ots"
                },
                "file": {
                  "const": "preuve.ots"
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "registre"
                },
                "file": {
                  "const": "registre.json"
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "certificat_commit"
                },
                "file": {
                  "const": "certificat-commit.json"
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "validateurs"
                },
                "file": {
                  "const": "validateurs.json"
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "points_de_controle"
                },
                "file": {
                  "const": "points-de-controle.json"
                }
              }
            },
            {
              "type": "object",
              "$ref": "#/$defs/part",
              "properties": {
                "name": {
                  "const": "attestation_perimetre"
                },
                "file": {
                  "const": "attestation-perimetre.json"
                }
              }
            }
          ]
        }
      ]
    }
  },
  "$defs": {
    "hex32": {
      "type": "string",
      "pattern": "^0x[0-9a-f]{64}$"
    },
    "horodatage": {
      "type": "string",
      "pattern": "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\\.[0-9]{3}Z$",
      "description": "RFC 3339, UTC, trois décimales, suffixe Z ; la date doit exister dans le calendrier grégorien proleptique (CT-1 §3), ce que le motif n'exprime pas et que le vérificateur contrôle."
    },
    "identifiant_cle": {
      "type": "string",
      "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
    },
    "adresse": {
      "type": "string",
      "pattern": "^0x[0-9a-f]{40}$"
    },
    "signature_ed25519": {
      "type": "string",
      "pattern": "^0x[0-9a-f]{128}$"
    },
    "part": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "name",
        "file",
        "sha256",
        "present",
        "reason_if_absent"
      ],
      "properties": {
        "name": {
          "type": "string",
          "enum": [
            "evenement",
            "voisins",
            "chemin",
            "manifeste",
            "manifeste_sig",
            "cles",
            "approbations",
            "jeton_rfc3161",
            "preuve_ots",
            "registre",
            "certificat_commit",
            "validateurs",
            "points_de_controle",
            "attestation_perimetre"
          ]
        },
        "file": {
          "type": "string",
          "enum": [
            "evenement.json",
            "voisins.json",
            "chemin.json",
            "manifeste.json",
            "manifeste.sig",
            "cles.json",
            "approbations.json",
            "jeton-rfc3161.der",
            "preuve.ots",
            "registre.json",
            "certificat-commit.json",
            "validateurs.json",
            "points-de-controle.json",
            "attestation-perimetre.json"
          ]
        },
        "sha256": {
          "oneOf": [
            {
              "$ref": "#/$defs/hex32"
            },
            {
              "type": "null"
            }
          ],
          "description": "SHA-256 des octets du fichier tel qu'il est dans le répertoire ; null si absent."
        },
        "present": {
          "type": "boolean"
        },
        "reason_if_absent": {
          "type": [
            "string",
            "null"
          ],
          "minLength": 1,
          "maxLength": 256
        }
      },
      "if": {
        "properties": {
          "present": {
            "const": true
          }
        }
      },
      "then": {
        "properties": {
          "sha256": {
            "$ref": "#/$defs/hex32"
          },
          "reason_if_absent": {
            "type": "null"
          }
        }
      },
      "else": {
        "properties": {
          "sha256": {
            "type": "null"
          },
          "reason_if_absent": {
            "type": "string"
          }
        }
      }
    },
    "voisins": {
      "title": "voisins.json",
      "description": "L'événement précédent et l'événement suivant, complets, ou null quand ils n'existent pas (premier événement du journal ; dernier événement connu).",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "version",
        "previous",
        "next"
      ],
      "properties": {
        "version": {
          "const": 0
        },
        "previous": {
          "oneOf": [
            {
              "$ref": "https://noortrace.example/schemas/v0/evenement.schema.json"
            },
            {
              "type": "null"
            }
          ]
        },
        "next": {
          "oneOf": [
            {
              "$ref": "https://noortrace.example/schemas/v0/evenement.schema.json"
            },
            {
              "type": "null"
            }
          ]
        }
      }
    },
    "chemin": {
      "title": "chemin.json",
      "description": "Preuve d'inclusion RFC 6962 §2.1.1 : taille de l'arbre, indice de la feuille (seq - first_seq), hachage de la feuille, chemin d'audit de la feuille vers la racine, racine attendue.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "version",
        "tree_size",
        "leaf_index",
        "leaf_hash",
        "path",
        "root"
      ],
      "properties": {
        "version": {
          "const": 0
        },
        "tree_size": {
          "type": "integer",
          "minimum": 1,
          "maximum": 9007199254740991
        },
        "leaf_index": {
          "type": "integer",
          "minimum": 0,
          "maximum": 9007199254740990
        },
        "leaf_hash": {
          "$ref": "#/$defs/hex32"
        },
        "path": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/hex32"
          },
          "maxItems": 64
        },
        "root": {
          "$ref": "#/$defs/hex32"
        }
      }
    },
    "manifeste_sig": {
      "title": "manifeste.sig",
      "description": "Signature Ed25519 du manifeste par l'enregistreur : Ed25519(clé recorder_key_id, \"noortrace/signature-manifeste/v0\\n\" || JCS(manifeste)).",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "version",
        "period_hash",
        "recorder_key_id",
        "sig"
      ],
      "properties": {
        "version": {
          "const": 0
        },
        "period_hash": {
          "$ref": "#/$defs/hex32"
        },
        "recorder_key_id": {
          "$ref": "#/$defs/identifiant_cle"
        },
        "sig": {
          "$ref": "#/$defs/signature_ed25519"
        }
      }
    },
    "cle_enregistreur": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "key_id",
        "algorithm",
        "public_key",
        "valid_from",
        "valid_to",
        "source"
      ],
      "properties": {
        "key_id": {
          "$ref": "#/$defs/identifiant_cle"
        },
        "algorithm": {
          "const": "ed25519"
        },
        "public_key": {
          "$ref": "#/$defs/hex32",
          "description": "Clé publique Ed25519, 32 octets (RFC 8032)."
        },
        "valid_from": {
          "$ref": "#/$defs/horodatage"
        },
        "valid_to": {
          "oneOf": [
            {
              "$ref": "#/$defs/horodatage"
            },
            {
              "type": "null"
            }
          ],
          "description": "Fin de validité annoncée (incluse), null si la clé est encore en service ; sinon supérieure ou égale à valid_from (contrôle E-8 du vérificateur)."
        },
        "source": {
          "type": "string",
          "minLength": 1,
          "maxLength": 256,
          "description": "D'où vient l'annonce de validité : registre (CT-4), événement de rotation, onboarding, vecteurs."
        }
      }
    },
    "cles": {
      "title": "cles.json",
      "description": "Les clés publiques Ed25519 de l'enregistreur nécessaires au dossier, avec leur période de validité telle qu'annoncée. org_id et journal_id sont ceux de l'événement prouvé ; key_id et public_key sont uniques dans keys (unicité d'un sous-champ, non exprimable ici : contrôle E-8 du vérificateur, CT-1 §11.2).",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "version",
        "org_id",
        "journal_id",
        "keys"
      ],
      "properties": {
        "version": {
          "const": 0
        },
        "org_id": {
          "$ref": "#/$defs/hex32"
        },
        "journal_id": {
          "$ref": "#/$defs/hex32"
        },
        "keys": {
          "type": "array",
          "minItems": 1,
          "maxItems": 1024,
          "uniqueItems": true,
          "items": {
            "$ref": "#/$defs/cle_enregistreur"
          }
        }
      }
    },
    "approbations": {
      "title": "approbations.json",
      "description": "Les événements d'approbation liés au ticket de l'événement prouvé, avec le jeu d'approbateurs déclaré et son seuil. Quand l'événement prouvé n'a pas d'approbation, le fichier est absent (reason_if_absent = \"aucune approbation liée\"). Pour le dossier d'une décision, events contient l'événement prouvé lui-même (CT-1 §11.4, A-2).",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "version",
        "ticket",
        "request_hash",
        "approver_set",
        "events"
      ],
      "properties": {
        "version": {
          "const": 0
        },
        "ticket": {
          "type": "string",
          "minLength": 1,
          "maxLength": 128
        },
        "request_hash": {
          "$ref": "#/$defs/hex32"
        },
        "approver_set": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "threshold",
            "members",
            "source"
          ],
          "properties": {
            "threshold": {
              "type": "object",
              "additionalProperties": false,
              "required": [
                "required",
                "size"
              ],
              "properties": {
                "required": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 65535
                },
                "size": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 65535
                }
              }
            },
            "members": {
              "type": "array",
              "minItems": 1,
              "maxItems": 65535,
              "uniqueItems": true,
              "items": {
                "$ref": "#/$defs/adresse"
              }
            },
            "source": {
              "type": "string",
              "minLength": 1,
              "maxLength": 256
            }
          }
        },
        "events": {
          "type": "array",
          "minItems": 1,
          "maxItems": 1024,
          "items": {
            "$ref": "https://noortrace.example/schemas/v0/evenement.schema.json"
          }
        }
      }
    },
    "base64": {
      "type": "string",
      "pattern": "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
      "minLength": 4,
      "maxLength": 131072,
      "description": "Base64 de la RFC 4648 §4, alphabet standard, avec remplissage, sans saut de ligne ; les octets décodés sont le fichier DER ou .ots tel que produit, jamais réencodé (CT-6 EX-13.3)."
    },
    "preuve_coherence": {
      "title": "Preuve de cohérence RFC 9162 §2.1.4 (CT-1 §10.7)",
      "description": "Preuve que l'arbre de first_size feuilles de racine first_root est un préfixe de l'arbre de second_size feuilles de racine second_root. Dans un dossier, first_size et first_root sont tree_size et root du point de contrôle, second_size et second_root sont count et root du manifeste ; path est vide si et seulement si first_size = second_size (K-5).",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "version",
        "first_size",
        "second_size",
        "first_root",
        "second_root",
        "path"
      ],
      "properties": {
        "version": {
          "const": 0
        },
        "first_size": {
          "type": "integer",
          "minimum": 1,
          "maximum": 9007199254740991
        },
        "second_size": {
          "type": "integer",
          "minimum": 1,
          "maximum": 9007199254740991
        },
        "first_root": {
          "$ref": "#/$defs/hex32"
        },
        "second_root": {
          "$ref": "#/$defs/hex32"
        },
        "path": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/hex32"
          },
          "maxItems": 64
        }
      }
    },
    "ancre_rfc3161_point": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "token"
      ],
      "properties": {
        "token": {
          "$ref": "#/$defs/base64",
          "description": "TimeStampToken RFC 3161 en DER, base64, dont le messageImprint est (SHA-256, checkpoint_hash) ; vérifié par T-1 à T-11 de CT-6 (K-7)."
        }
      }
    },
    "ancre_registre_point": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "chain_id",
        "contract",
        "fingerprint",
        "doc_type",
        "block_number",
        "block_hash",
        "transaction_hash",
        "log_index"
      ],
      "properties": {
        "chain_id": {
          "type": "integer",
          "minimum": 1,
          "maximum": 9007199254740991
        },
        "contract": {
          "$ref": "#/$defs/adresse",
          "description": "Adresse d'AttestationRegistry telle que l'exportateur la connaît ; déclarative, le vérificateur ne croit que le fichier d'ancres (CT-6 §12)."
        },
        "fingerprint": {
          "$ref": "#/$defs/hex32",
          "description": "keccak256(org_id || journal_id || checkpoint_hash), recalculée (K-8)."
        },
        "doc_type": {
          "$ref": "#/$defs/hex32",
          "description": "keccak256(utf8(\"noortrace/point-de-controle/v0\")) = 0x72c486c933f8fb8fef2c726539023e8fd80113cc0ca89e3fdf1314d553932178 (CT-4 §6.4, révision 0.3)."
        },
        "block_number": {
          "type": "integer",
          "minimum": 0,
          "maximum": 9007199254740991
        },
        "block_hash": {
          "$ref": "#/$defs/hex32"
        },
        "transaction_hash": {
          "$ref": "#/$defs/hex32"
        },
        "log_index": {
          "type": "integer",
          "minimum": 0,
          "maximum": 255
        }
      }
    },
    "ancre_ots_point": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "proof"
      ],
      "properties": {
        "proof": {
          "$ref": "#/$defs/base64",
          "description": "Fichier .ots OpenTimestamps, base64, dont l'empreinte de fichier est checkpoint_hash (SHA-256 de P_K || C_K) ; vérifié par O-1 à O-7 de CT-6 (K-9)."
        }
      }
    },
    "points_de_controle": {
      "title": "points-de-controle.json",
      "description": "Partie facultative (CT-1 révision 0.3, §11.2) : le point de contrôle de plus petit tree_size strictement supérieur à l'indice de feuille de l'événement prouvé, son checkpointHash, la preuve de cohérence de sa racine vers celle du manifeste, et ses ancres : jeton RFC 3161 sur checkpoint_hash, référence de l'ancre au registre, preuve OpenTimestamps ; chaque ancre non fournie vaut null. Vérifications K-1 à K-9 (CT-1 §11.4).",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "version",
        "checkpoint",
        "checkpoint_hash",
        "consistency",
        "anchors"
      ],
      "properties": {
        "version": {
          "const": 0
        },
        "checkpoint": {
          "$ref": "https://noortrace.example/schemas/v0/point-de-controle.schema.json"
        },
        "checkpoint_hash": {
          "$ref": "#/$defs/hex32",
          "description": "SHA-256(\"noortrace/point-de-controle/v0\\n\" || JCS(checkpoint sans sig)), recalculé par le vérificateur (K-2) : l'empreinte que les ancres portent."
        },
        "consistency": {
          "$ref": "#/$defs/preuve_coherence"
        },
        "anchors": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "rfc3161",
            "registry",
            "ots"
          ],
          "properties": {
            "rfc3161": {
              "oneOf": [
                {
                  "$ref": "#/$defs/ancre_rfc3161_point"
                },
                {
                  "type": "null"
                }
              ]
            },
            "registry": {
              "oneOf": [
                {
                  "$ref": "#/$defs/ancre_registre_point"
                },
                {
                  "type": "null"
                }
              ]
            },
            "ots": {
              "oneOf": [
                {
                  "$ref": "#/$defs/ancre_ots_point"
                },
                {
                  "type": "null"
                }
              ]
            }
          }
        }
      }
    },
    "base64_document": {
      "type": "string",
      "pattern": "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
      "minLength": 4,
      "maxLength": 2796204,
      "description": "Base64 de la RFC 4648 §4, alphabet standard, avec remplissage, sans saut de ligne (CT-1 §3, révision 0.4) : les octets décodés, au plus 2 097 152, sont le document d'ensemble de politique tel qu'il est stocké comme pièce sous policy_sha256 (CT-2 EX-8.11), jamais réencodé."
    },
    "attestation_perimetre": {
      "title": "attestation-perimetre.json",
      "description": "Partie facultative (CT-1 révision 0.4, §11.2 ; CT-7 §7) : l'attestation de périmètre signée par des membres du jeu d'approbateurs de l'organisation, le jeu déclaré auquel ses signataires sont comparés, et, si l'exportateur la fournit, son inscription au journal : l'événement noortrace.journal.politique dont l'ensemble de politique porte le condensé de l'attestation, avec le document de politique. Vérifications AT-1 à AT-7 (CT-1 §11.4), sans effet sur le verdict (CT-6 EX-5.10). Déclarative : elle dit qui a déclaré le périmètre, jamais que le périmètre est exact.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "version",
        "signed",
        "approver_set",
        "inscription"
      ],
      "properties": {
        "version": {
          "const": 0
        },
        "signed": {
          "$ref": "https://noortrace.example/schemas/v0/attestation-perimetre.schema.json#/$defs/attestation_signee"
        },
        "approver_set": {
          "$ref": "https://noortrace.example/schemas/v0/attestation-perimetre.schema.json#/$defs/jeu_approbateurs"
        },
        "inscription": {
          "oneOf": [
            {
              "type": "object",
              "additionalProperties": false,
              "required": [
                "event",
                "policy_document"
              ],
              "properties": {
                "event": {
                  "$ref": "https://noortrace.example/schemas/v0/evenement.schema.json",
                  "description": "L'événement noortrace.journal.politique qui inscrit l'attestation (CT-7 §7.6), complet."
                },
                "policy_document": {
                  "$ref": "#/$defs/base64_document",
                  "description": "Octets du document d'ensemble de politique dont event.execution.arguments.value.policy_sha256 est le SHA-256 ; son membre /perimeter/attestation_digest porte D_P (AT-6)."
                }
              }
            },
            {
              "type": "null"
            }
          ]
        }
      }
    }
  }
});

