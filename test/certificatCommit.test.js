import { expect } from "chai";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { SigningKey, randomBytes } from "ethers";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import {
  DOMAINE_SIGNATURE,
  HACHAGE_NUL,
  MOITIE_N_SECP256K1,
  N_SECP256K1,
  TYPE_PRECOMMIT,
  TYPE_PREVOTE,
  TYPE_PROPOSITION,
  VOTE_PRECOMMIT,
  VOTE_PREVOTE,
  analyserEnveloppe,
  base64Go,
  base64Strict,
  chargerJeuValidateurs,
  clePubliqueDe,
  digestEnveloppe,
  encoderProposition,
  encoderVote,
  hachageJeuValidateurs,
  hex,
  membresBruts,
  membresBrutsGo,
  normaliserCertificat,
  normaliserClePublique,
  octets,
  plierNomGo,
  quorum,
  recupererClePublique,
  sha256,
  signatureCanonique,
  signerDigest,
  signerEnveloppe,
  signerProposition,
  signerVote,
  trimSpaceGo,
  u64,
  verifierCertificat,
  verifierLigne,
} from "../scripts/lib/certificat-commit.mjs";

// LE VÉRIFICATEUR HORS LIGNE D'UN CERTIFICAT DE COMMIT : parité octet par octet
// avec le code Go de noorcore (digest signé, hachage du jeu, quorum, enveloppes
// signées, certificat complet), vecteurs synthétiques à clés jetables et toutes
// leurs altérations, chargement du jeu de validateurs, découpage brut des
// lignes, ligne de commande (codes de retour 0, 1, 2, --json, --rpc, --en-ligne).

// ---------------------------------------------------------------------------
// Vecteurs de référence produits par le code Go de noorcore
// (core/consensus/signing_vectors_test.go, test permanent qui les épingle et les
// exporte) : SigningDigest, Quorum2f1, ValidatorSetHash, SignProposalEnvelope /
// SignVoteEnvelope / EncodeSignedEnvelope, un DecidedCert complet signé par
// quatre clés privées jetables fixes (0x11…, 0x22…, 0x33…, 0x44…), des lignes
// d'enveloppe canoniques ou non avec le verdict que le nœud leur donne
// (« lignes »), et des fichiers validators.json avec ce que LoadValidatorSetFile
// en fait (« fichiers »). Régénération et recopie telles quelles, depuis la
// copie de travail de noorchain-core (le fichier de validateurs donné est celui
// du fixture, d'où valsetHash.fichier) :
//
//   NOOR_SIGNING_VECTORS_OUT=/tmp/vectors.json \
//   NOOR_SIGNING_VECTORS_VALIDATORS_FILE=$PWD/test/fixtures/certificat-commit/validators.json \
//     go test ./core/consensus/ -run TestSigningVectors -count=1
//
// Un vecteur qui change signale un changement du schéma de signature ou de la
// tolérance du décodeur : la cause est à chercher côté Go avant de recopier.
// ---------------------------------------------------------------------------
const VECTEURS_GO =
{
  "certificat": {
    "certJSON": {
      "chainId": "noortrace-2124-dev",
      "valsetHash": "0x519d4a20b4ec7f4667e0f3a74b895398882ab3e0d3b8bd5baaae36299ec0eb34",
      "h": 8328,
      "r": 1,
      "hash": "0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c",
      "prop": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PROPOSAL\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"CsFUnEfi5gBgT05agS4qET8Y19IOZKf6w1fPzD7xK5A=\",\"body\":{\"height\":8328,\"round\":1,\"proposer\":\"v2\",\"blockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"parentHash\":\"0x1111111111111111111111111111111111111111111111111111111111111110\",\"timestamp\":1761050000,\"stateRoot\":\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"receiptsRoot\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"txRoot\":\"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"gasUsed\":21000,\"gasLimit\":30000000,\"baseFeeHex\":\"0x1\",\"txsRaw\":[\"+GwBAgM=\"]},\"sig\":\"s6bb6pwRLZgU6ubsTelWrMgZhrQnWdCVyqbNiBQ7tp0r/PyMhdhPPfqmhllxqdunMAJNj9IO9PdLSbYeatiiRQA=\"}",
      "cmts": [
        "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v1\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"NeuRC2+W45lMky6WSGtRQyuBn9GTn0WNsNbfCsl44m4=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v1\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"Bc+wpUZ0at5hb7kmPQDFqQ6z6tLLsCswXX6lC17zBtxZQ/SzxXbnmfXilIafONE6XLlSLizTw/NSO4EwbzDfZAA=\"}",
        "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"k301QKPcfGXcygrBEgsoTOSBYoGJsVPm1TwIrZgJHKI=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v2\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"Ogpv1ckNbI5rnCn8vKCqGZak5pnSop89PWLgn3NrWN9knQXRjtc/T8cuOklFxG6rEMeA7WGDXH31BcMDt5D5/gA=\"}",
        "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v4\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"spm12WbJyf3DjKDBLqAzmm5LDnOL+cqt9iOBxPyq+cw=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v4\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"nWN1M+pdoouQq5tCcZWFn0HBGSZvTSPpPg7nure76eNrtGycIrTJgij0fup/5qbh9nEjqXjmZkwyGrlUdT4sPAE=\"}"
      ]
    },
    "nilPrecommitLine_v3": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v3\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"bodyHash\":\"SAKajuvze2btiarfmtV4iFyf/7amSmGNM1jzQw5E+SM=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v3\",\"Type\":2,\"BlockHash\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"Sig\":null},\"sig\":\"EdEuLjl78rqF3d1rYUQqYfMPTXUwSo4vCAaXp9SRQ8lYHMhk2gTbCi3BNf/b4+DSM8MaijtKXIwrbjzy1srmJAA=\"}",
    "precommits": [
      {
        "body": "{\"Height\":8328,\"Round\":1,\"Voter\":\"v1\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null}",
        "bodyHash": "0x35eb910b6f96e3994c932e96486b51432b819fd1939f458db0d6df0ac978e26e",
        "digest": "0xe732867f8a554e77cb9bca6fed90493d80ffd91e58590ebf59843f92c5aab889",
        "sig": "0x05cfb0a546746ade616fb9263d00c5a90eb3ead2cbb02b305d7ea50b5ef306dc5943f4b3c576e799f5e294869f38d13a5cb9522e2cd3c3f3523b81306f30df6400",
        "validatorId": "v1"
      },
      {
        "body": "{\"Height\":8328,\"Round\":1,\"Voter\":\"v2\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null}",
        "bodyHash": "0x937d3540a3dc7c65dcca0ac1120b284ce481628189b153e6d53c08ad98091ca2",
        "digest": "0x68989caaf9a78bf7f31c40622f6cc44af8969f1d556728081f9a669ca719ef37",
        "sig": "0x3a0a6fd5c90d6c8e6b9c29fcbca0aa1996a4e699d2a29f3d3d62e09f736b58df649d05d18ed73f4fc72e3a4945c46eab10c780ed61835c7df505c303b790f9fe00",
        "validatorId": "v2"
      },
      {
        "body": "{\"Height\":8328,\"Round\":1,\"Voter\":\"v4\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null}",
        "bodyHash": "0xb299b5d966c9c9fdc38ca0c12ea0339a6e4b0e738bf9caadf62381c4fcaaf9cc",
        "digest": "0x6940dd81df17abd2da8a392cb7687c7191f4724cc1567a1d7332786764085f29",
        "sig": "0x9d637533ea5da28b90ab9b427195859f41c119266f4d23e93e0ee7bab7bbe9e36bb46c9c22b4c98228f47eea7fe6a6e1f67123a978e6664c321ab954753e2c3c01",
        "validatorId": "v4"
      }
    ],
    "prevoteLine_v3": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PREVOTE\",\"validatorId\":\"v3\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"A2qmchNEzg7Y0+JdXjFBPAEDiPI/P58bmClxShF/zlE=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v3\",\"Type\":1,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"llkevD5kqyXLw4dHlwofpaz5PbedVGJwiJS/wyKrGsI3ARvVhGe9By2Q3XKHEkzDL90ByEFJOWLY/ltJmgkilgA=\"}",
    "privHex": {
      "v1": "1111111111111111111111111111111111111111111111111111111111111111",
      "v2": "2222222222222222222222222222222222222222222222222222222222222222",
      "v3": "3333333333333333333333333333333333333333333333333333333333333333",
      "v4": "4444444444444444444444444444444444444444444444444444444444444444"
    },
    "propBody": "{\"height\":8328,\"round\":1,\"proposer\":\"v2\",\"blockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"parentHash\":\"0x1111111111111111111111111111111111111111111111111111111111111110\",\"timestamp\":1761050000,\"stateRoot\":\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"receiptsRoot\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"txRoot\":\"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"gasUsed\":21000,\"gasLimit\":30000000,\"baseFeeHex\":\"0x1\",\"txsRaw\":[\"+GwBAgM=\"]}",
    "propBodyHash": "0x0ac1549c47e2e600604f4e5a812e2a113f18d7d20e64a7fac357cfcc3ef12b90",
    "propDigest": "0x857496fd0481471dbc1f5d7a062f68d7850ea3cf3ee34e773ea1fd58d6a334a6",
    "propSig": "0xb3a6dbea9c112d9814eae6ec4de956acc81986b42759d095caa6cd88143bb69d2bfcfc8c85d84f3dfaa6865971a9dba730024d8fd20ef4f74b49b61e6ad8a24500",
    "pubKeyHex": {
      "v1": "0x044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1",
      "v2": "0x04466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276728176c3c6431f8eeda4538dc37c865e2784f3a9e77d044f33e407797e1278a",
      "v3": "0x043c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b13b306b0fe085665d8fc1b28ae1676cd3ad6e08eaeda225fe38d0da4de55703e0",
      "v4": "0x042c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991ae31a9c671a36543f46cea8fce6984608aa316aa0472a7eed08847440218cb2f"
    },
    "validators": {
      "validators": [
        {
          "id": "v1",
          "pubKeyHex": "0x044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1"
        },
        {
          "id": "v2",
          "pubKeyHex": "0x04466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276728176c3c6431f8eeda4538dc37c865e2784f3a9e77d044f33e407797e1278a"
        },
        {
          "id": "v3",
          "pubKeyHex": "0x043c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b13b306b0fe085665d8fc1b28ae1676cd3ad6e08eaeda225fe38d0da4de55703e0"
        },
        {
          "id": "v4",
          "pubKeyHex": "0x042c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991ae31a9c671a36543f46cea8fce6984608aa316aa0472a7eed08847440218cb2f"
        }
      ]
    },
    "valsetHash": "0x519d4a20b4ec7f4667e0f3a74b895398882ab3e0d3b8bd5baaae36299ec0eb34"
  },
  "digests": [
    {
      "blockHash": "0xa3f1c2d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
      "bodyHash": "0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff",
      "chainId": "noortrace-2124-dev",
      "digest": "0x36ccf77aae7d2d9ff482eaf87507a96eb94847a89d52e3bfd6c6403ae7c347f9",
      "domain": "noor/v1/bft",
      "height": 8328,
      "round": 0,
      "type": "CONS_PRECOMMIT",
      "validatorId": "v2",
      "valsetHash": "0x0101010101010101010101010101010101010101010101010101010101010101"
    },
    {
      "blockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "bodyHash": "0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff",
      "chainId": "noortrace-2124-dev",
      "digest": "0xb327f4e8740c1e2f9facc83e9eede5e104ad11ba86c175e4e44997833e61fea5",
      "domain": "noor/v1/bft",
      "height": 1,
      "round": 7,
      "type": "CONS_PROPOSAL",
      "validatorId": "valé-ß",
      "valsetHash": "0x0101010101010101010101010101010101010101010101010101010101010101"
    },
    {
      "blockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "bodyHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "chainId": "",
      "digest": "0x320c38dd6bef6000858b453578c92d93c91c548208e2f71f1de8b65201781ea8",
      "domain": "",
      "height": 0,
      "round": 0,
      "type": "",
      "validatorId": "",
      "valsetHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
    },
    {
      "blockHash": "0xa3f1c2d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
      "bodyHash": "0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff",
      "chainId": "noortrace-2124-dev",
      "digest": "0xe21ce237e52c12198c207f6f701744e3f533c2ea27b57102cad0a171c81f47e8",
      "domain": "noor/v1/bft",
      "height": "18446744073709551615",
      "round": 4294967296,
      "type": "CONS_PREVOTE",
      "validatorId": "v4",
      "valsetHash": "0x0101010101010101010101010101010101010101010101010101010101010101"
    }
  ],
  "fichiers": [
    {
      "nom": "nettoyage_unicode",
      "contenu": "{\"validators\":[{\"id\":\"v1\",\"pubKeyHex\":\"0x044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1\"},{\"id\":\" v2﻿ \",\"pubKeyHex\":\" 0x04466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276728176c3c6431f8eeda4538dc37c865e2784f3a9e77d044f33e407797e1278a \"}]}",
      "ids": [
        "v1",
        "v2﻿"
      ],
      "hachage": "0x8ac91b18db20c743b81cfb68bce1678bae7a6fd9eafc1c52263e61845d9d4621"
    },
    {
      "nom": "cles_insensibles_casse",
      "contenu": "{\"Validators\":[{\"ID\":\"v1\",\"PUBKEYHEX\":\"0x044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1\"},{\"Id\":\"v2\",\"PubKeyHex\":\"0x04466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276728176c3c6431f8eeda4538dc37c865e2784f3a9e77d044f33e407797e1278a\"}]}",
      "ids": [
        "v1",
        "v2"
      ],
      "hachage": "0xe28361e3d86f711558b3be238163f4eea959cb83111cd05a4c150e4b00746694"
    },
    {
      "nom": "cles_dupliquees_derniere_gagne",
      "contenu": "{\"validators\":[{\"id\":\"v1\",\"ID\":\"v9\",\"pubKeyHex\":\"0x044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1\"}]}",
      "ids": [
        "v9"
      ],
      "hachage": "0x919c1a6f279761cca61fd28fa3a0d874d6a21176dc388190ef7c8edc72d48b29"
    },
    {
      "nom": "prefixe_0X_refuse",
      "contenu": "{\"validators\":[{\"id\":\"v1\",\"pubKeyHex\":\"0X044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1\"}]}",
      "ids": null,
      "hachage": "",
      "erreur": "validator[0] pubKeyHex invalid hex: encoding/hex: invalid byte: U+0058 'X'"
    },
    {
      "nom": "hex_majuscules",
      "contenu": "{\"validators\":[{\"id\":\"v1\",\"pubKeyHex\":\"0x044F355BDCB7CC0AF728EF3CCEB9615D90684BB5B2CA5F859AB0F0B704075871AA385B6B1B8EAD809CA67454D9683FCF2BA03456D6FE2C4ABE2B07F0FBDBB2F1C1\"}]}",
      "ids": [
        "v1"
      ],
      "hachage": "0xc18d825fdd98fca34eafd1f64085531c9da869293268174d822e1f52cae06217"
    },
    {
      "nom": "id_nombre_refuse",
      "contenu": "{\"validators\":[{\"id\":1,\"pubKeyHex\":\"0x044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1\"}]}",
      "ids": null,
      "hachage": "",
      "erreur": "parse validators-file json: json: cannot unmarshal number into Go struct field .validators.id of type string"
    },
    {
      "nom": "id_null",
      "contenu": "{\"validators\":[{\"id\":null,\"pubKeyHex\":\"0x044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1\"}]}",
      "ids": null,
      "hachage": "",
      "erreur": "validator id empty"
    }
  ],
  "jeux": {
    "standard": {
      "validators": {
        "validators": [
          {
            "id": "v1",
            "pubKeyHex": "0x044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1"
          },
          {
            "id": "v2",
            "pubKeyHex": "0x04466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276728176c3c6431f8eeda4538dc37c865e2784f3a9e77d044f33e407797e1278a"
          },
          {
            "id": "v3",
            "pubKeyHex": "0x043c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b13b306b0fe085665d8fc1b28ae1676cd3ad6e08eaeda225fe38d0da4de55703e0"
          },
          {
            "id": "v4",
            "pubKeyHex": "0x042c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991ae31a9c671a36543f46cea8fce6984608aa316aa0472a7eed08847440218cb2f"
          }
        ]
      },
      "valsetHash": "0x519d4a20b4ec7f4667e0f3a74b895398882ab3e0d3b8bd5baaae36299ec0eb34"
    },
    "v1Compresse": {
      "validators": {
        "validators": [
          {
            "id": "v1",
            "pubKeyHex": "0x034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
          },
          {
            "id": "v2",
            "pubKeyHex": "0x04466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276728176c3c6431f8eeda4538dc37c865e2784f3a9e77d044f33e407797e1278a"
          },
          {
            "id": "v3",
            "pubKeyHex": "0x043c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b13b306b0fe085665d8fc1b28ae1676cd3ad6e08eaeda225fe38d0da4de55703e0"
          },
          {
            "id": "v4",
            "pubKeyHex": "0x042c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991ae31a9c671a36543f46cea8fce6984608aa316aa0472a7eed08847440218cb2f"
          }
        ]
      },
      "valsetHash": "0x4238e49aefff7f61eaf429c0c97e3f2bcc35ba1bc7356e4cb4e940c2c54a0b94"
    }
  },
  "lignes": [
    {
      "nom": "canonique_v1",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v1\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"NeuRC2+W45lMky6WSGtRQyuBn9GTn0WNsNbfCsl44m4=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v1\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"Bc+wpUZ0at5hb7kmPQDFqQ6z6tLLsCswXX6lC17zBtxZQ/SzxXbnmfXilIafONE6XLlSLizTw/NSO4EwbzDfZAA=\"}",
      "go": "OK"
    },
    {
      "nom": "cle_Domain_majuscule",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"Domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v1\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"NeuRC2+W45lMky6WSGtRQyuBn9GTn0WNsNbfCsl44m4=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v1\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"Bc+wpUZ0at5hb7kmPQDFqQ6z6tLLsCswXX6lC17zBtxZQ/SzxXbnmfXilIafONE6XLlSLizTw/NSO4EwbzDfZAA=\"}",
      "go": "OK"
    },
    {
      "nom": "cle_BODY_majuscule",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v1\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"NeuRC2+W45lMky6WSGtRQyuBn9GTn0WNsNbfCsl44m4=\",\"BODY\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v1\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"Bc+wpUZ0at5hb7kmPQDFqQ6z6tLLsCswXX6lC17zBtxZQ/SzxXbnmfXilIafONE6XLlSLizTw/NSO4EwbzDfZAA=\"}",
      "go": "OK"
    },
    {
      "nom": "cle_SIG_majuscule",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v1\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"NeuRC2+W45lMky6WSGtRQyuBn9GTn0WNsNbfCsl44m4=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v1\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"SIG\":\"Bc+wpUZ0at5hb7kmPQDFqQ6z6tLLsCswXX6lC17zBtxZQ/SzxXbnmfXilIafONE6XLlSLizTw/NSO4EwbzDfZAA=\"}",
      "go": "OK"
    },
    {
      "nom": "cle_ſig_s_long",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v1\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"NeuRC2+W45lMky6WSGtRQyuBn9GTn0WNsNbfCsl44m4=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v1\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"ſig\":\"Bc+wpUZ0at5hb7kmPQDFqQ6z6tLLsCswXX6lC17zBtxZQ/SzxXbnmfXilIafONE6XLlSLizTw/NSO4EwbzDfZAA=\"}",
      "go": "OK"
    },
    {
      "nom": "cle_blocKHash_kelvin",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v1\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blocKHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"NeuRC2+W45lMky6WSGtRQyuBn9GTn0WNsNbfCsl44m4=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v1\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"Bc+wpUZ0at5hb7kmPQDFqQ6z6tLLsCswXX6lC17zBtxZQ/SzxXbnmfXilIafONE6XLlSLizTw/NSO4EwbzDfZAA=\"}",
      "go": "OK"
    },
    {
      "nom": "cle_dupliquee_derniere_gagne",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"autre\",\"Domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v1\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"NeuRC2+W45lMky6WSGtRQyuBn9GTn0WNsNbfCsl44m4=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v1\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"Bc+wpUZ0at5hb7kmPQDFqQ6z6tLLsCswXX6lC17zBtxZQ/SzxXbnmfXilIafONE6XLlSLizTw/NSO4EwbzDfZAA=\"}",
      "go": "OK"
    },
    {
      "nom": "cle_dupliquee_derniere_gagne_fausse",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"Domain\":\"noor/v1/bft\",\"domain\":\"autre\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v1\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"NeuRC2+W45lMky6WSGtRQyuBn9GTn0WNsNbfCsl44m4=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v1\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"Bc+wpUZ0at5hb7kmPQDFqQ6z6tLLsCswXX6lC17zBtxZQ/SzxXbnmfXilIafONE6XLlSLizTw/NSO4EwbzDfZAA=\"}",
      "go": "REJECT: verify: bad domain \"autre\""
    },
    {
      "nom": "espace_final",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v1\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"NeuRC2+W45lMky6WSGtRQyuBn9GTn0WNsNbfCsl44m4=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v1\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"Bc+wpUZ0at5hb7kmPQDFqQ6z6tLLsCswXX6lC17zBtxZQ/SzxXbnmfXilIafONE6XLlSLizTw/NSO4EwbzDfZAA=\"}\n",
      "go": "OK"
    },
    {
      "nom": "ordre_membres_sig_en_tete",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"sig\":\"Bc+wpUZ0at5hb7kmPQDFqQ6z6tLLsCswXX6lC17zBtxZQ/SzxXbnmfXilIafONE6XLlSLizTw/NSO4EwbzDfZAA=\",\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v1\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"NeuRC2+W45lMky6WSGtRQyuBn9GTn0WNsNbfCsl44m4=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v1\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null}}",
      "go": "OK"
    },
    {
      "nom": "base64_sig_non_canonique",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v1\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"NeuRC2+W45lMky6WSGtRQyuBn9GTn0WNsNbfCsl44m4=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v1\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"Bc+wpUZ0at5hb7kmPQDFqQ6z6tLLsCswXX6lC17zBtxZQ/SzxXbnmfXilIafONE6XLlSLizTw/NSO4EwbzDfZAB=\"}",
      "go": "OK"
    },
    {
      "nom": "base64_sig_avec_saut_de_ligne",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v1\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"NeuRC2+W45lMky6WSGtRQyuBn9GTn0WNsNbfCsl44m4=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v1\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"Bc+wpUZ0at\\n5hb7kmPQDFqQ6z6tLLsCswXX6lC17zBtxZQ/SzxXbnmfXilIafONE6XLlSLizTw/NSO4EwbzDfZAA=\"}",
      "go": "OK"
    },
    {
      "nom": "base64_sig_alphabet_url",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v1\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"NeuRC2+W45lMky6WSGtRQyuBn9GTn0WNsNbfCsl44m4=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v1\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"Bc-wpUZ0at5hb7kmPQDFqQ6z6tLLsCswXX6lC17zBtxZQ_SzxXbnmfXilIafONE6XLlSLizTw_NSO4EwbzDfZAA=\"}",
      "go": "REJECT: decode envelope: illegal base64 data at input byte 2"
    },
    {
      "nom": "base64_sig_sans_bourrage",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v1\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"NeuRC2+W45lMky6WSGtRQyuBn9GTn0WNsNbfCsl44m4=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v1\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"Bc+wpUZ0at5hb7kmPQDFqQ6z6tLLsCswXX6lC17zBtxZQ/SzxXbnmfXilIafONE6XLlSLizTw/NSO4EwbzDfZAA\"}",
      "go": "REJECT: decode envelope: illegal base64 data at input byte 84"
    },
    {
      "nom": "enveloppe_height_chaine",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v1\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":\"8328\",\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"NeuRC2+W45lMky6WSGtRQyuBn9GTn0WNsNbfCsl44m4=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v1\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"Bc+wpUZ0at5hb7kmPQDFqQ6z6tLLsCswXX6lC17zBtxZQ/SzxXbnmfXilIafONE6XLlSLizTw/NSO4EwbzDfZAA=\"}",
      "go": "REJECT: decode envelope: json: cannot unmarshal string into Go struct field SignedEnvelope.height of type uint64"
    },
    {
      "nom": "enveloppe_round_fraction",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v1\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1.0,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"NeuRC2+W45lMky6WSGtRQyuBn9GTn0WNsNbfCsl44m4=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v1\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"Bc+wpUZ0at5hb7kmPQDFqQ6z6tLLsCswXX6lC17zBtxZQ/SzxXbnmfXilIafONE6XLlSLizTw/NSO4EwbzDfZAA=\"}",
      "go": "REJECT: decode envelope: json: cannot unmarshal number 1.0 into Go struct field SignedEnvelope.round of type uint64"
    },
    {
      "nom": "corps_avec_espaces_et_ordre",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"2ozLovp9r2G/Lu1TxaRPybtgIho+Jgf32O1Dhiu4E4E=\",\"body\":{ \"Sig\": null, \"BlockHash\": \"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\", \"Type\": 2, \"Voter\": \"v2\", \"Round\": 1, \"Height\": 8328 },\"sig\":\"tmTpvev+ZMYNL1UrbPTdXy+59ChTc6bLPArrtT6Q1OkAtEWUWXqnty9aX3O6e5s88Dlqe41PAtoR3pgEW59mIwA=\"}",
      "go": "OK"
    },
    {
      "nom": "corps_cles_minuscules",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"g3UY8Ld9ePwYNqReGpuMHl2+0BPjEfm0Q7G9tKNjV+U=\",\"body\":{\"height\":8328,\"round\":1,\"voter\":\"v2\",\"type\":2,\"blockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"sig\":null},\"sig\":\"OeDloS4I4YNJEykScofkWSeZMjUwLAkIh8PnHI4ScKRmwB/qlPNni5lCmsBzLGK/oJg5KuPAnuTE5ReUv7AcvAA=\"}",
      "go": "OK"
    },
    {
      "nom": "corps_champ_inconnu",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"wTgwAZJIJqjvvPUtl/raTpp5uwgSw4fAIcgD7NF1rmI=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v2\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null,\"Extra\":[1,2,{\"x\":\"}\"}]},\"sig\":\"V5nusstdM5D97lL9d6/SzJB2u8PZ6qEkfnCXqkGw8aNlMMjdDA2Lm/R9/4mrTIQVj7dwr9QBNeLCG/63V8G0KAE=\"}",
      "go": "OK"
    },
    {
      "nom": "corps_cle_dupliquee_derniere_gagne",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"gNfnsnR7IFR9z3vXKw4oYxfqR0ZZiM0glX9rfq0tsk4=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v9\",\"voter\":\"v2\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"mp+dZzk0EwdpcOmpJeSk9vsTYEFvKkkNLa5dC4bBxDl5/pqhvMjZcKo2pbsxq4dYA3KhVwtFCrZdolSZ9Asi1QA=\"}",
      "go": "OK"
    },
    {
      "nom": "corps_cle_dupliquee_derniere_gagne_fausse",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"wf9yWMk2HORPrQkaLKFu8ilk9QOA6zjgWXqf4at0uRk=\",\"body\":{\"Height\":8328,\"Round\":1,\"voter\":\"v2\",\"Voter\":\"v9\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"yTARJ+QKgbiAsW6IAD8I9q7KooJoDRY7nuh89blMox5yixjoyoQMchXxUSQEQ/EZnobP3Lt2Kd4aU74nM13DrQE=\"}",
      "go": "REJECT: verify: body voter mismatch"
    },
    {
      "nom": "corps_Type_2.0",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"j4Fx5yxuJd0jmb8XSxRZETTzhGokdK+aa90xRIGyaIQ=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v2\",\"Type\":2.0,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"/OFDgzrIz6cMhbAU+Ev8XFCstgNbH2QKJdS4aSXQ8qx9HGagjvuqxKh9G9Rc92/uOEalvKdhJeYPcDxqh82mJAE=\"}",
      "go": "REJECT: verify: body parse: json: cannot unmarshal number 2.0 into Go struct field Vote.Type of type consensus.VoteType"
    },
    {
      "nom": "corps_Height_8328.0",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"QDpc1ZtVPL84Ej4q/5TaFlq6bBO2XevDS4ycjK1CvrE=\",\"body\":{\"Height\":8328.0,\"Round\":1,\"Voter\":\"v2\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"CMrypKXUhLxEMUgKL4ZLhppAHriEt+5Vw5dfdmnGR35GZU4ebWini6aOvm3qp5sSqV1+Z0SQmktuSImYfkOwzgE=\"}",
      "go": "REJECT: verify: body parse: json: cannot unmarshal number 8328.0 into Go struct field Vote.Height of type uint64"
    },
    {
      "nom": "corps_Height_chaine",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"ha2QYvXeQj2cDypA1L4AlKPjbAtxj0Nja3bGpbft1YM=\",\"body\":{\"Height\":\"8328\",\"Round\":1,\"Voter\":\"v2\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"SgvTXW73t3ITvd6EwAts4fr8MdjEsZddkYUFlB7DBVdEhcKInEyKJw0+vds3sA27MOZ7xLWS6uY3AizUe0BV5wA=\"}",
      "go": "REJECT: verify: body parse: json: cannot unmarshal string into Go struct field Vote.Height of type uint64"
    },
    {
      "nom": "corps_Height_negatif",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"OTWWA9DHguvEVR5y3lfjHlmSopGOsJORrKnHUxmRYfQ=\",\"body\":{\"Height\":-8328,\"Round\":1,\"Voter\":\"v2\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"edJuhq8LqN3jDlBXqGgzXPPg3UdRY31h9m9IOJZS4sAiDMq9GwC/I0+EcxRffU19FbfsWVVoHbjHBZkNQoMf8gE=\"}",
      "go": "REJECT: verify: body parse: json: cannot unmarshal number -8328 into Go struct field Vote.Height of type uint64"
    },
    {
      "nom": "corps_Round_null",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"KIxcmfnxeJKszRHJ66K2LbrQXvAFePLCktHNOvbVaG4=\",\"body\":{\"Height\":8328,\"Round\":null,\"Voter\":\"v2\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"oM700E0XA5g40HwaV1Nxcg+UJujL6FMGPOvWDpo6LsYN2WEh2V3hIGI2ay6DyN979PGSuUX9bD3pWF40RSMMuwE=\"}",
      "go": "REJECT: verify: body height/round mismatch"
    },
    {
      "nom": "corps_Voter_vide",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"ZPGDenUmetohsR9MsZHo/npcmoRlXX2G5Baol2UDQ1g=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"hH7Ec2Gf7GWhrLGKH2tCX+LXqqZW+ZU2ywP8c8a9qO0/ltpRcl0o8GSkitQcSnogYyGhXd2ajkMu8RauqK62TwA=\"}",
      "go": "OK"
    },
    {
      "nom": "corps_Voter_null",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"M3og0k48PePSdD8H76Goc9IJ+wJaosYQjkDWWR45D+w=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":null,\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"etsna+/mKh3+VXlCnwFzXz3RDjfk5EiQXOep2JFrsuJ7TuxlmYC1ldKJpyu0GYN5dRoIII5MNAkHYZs4YAaU3AE=\"}",
      "go": "OK"
    },
    {
      "nom": "corps_Voter_espaces",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"0a2vEXisITbU9kda/fqoAzlmkK3VperL6LYrUx6oiZQ=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"  \",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"Nsfiym7DzviagYVLB14gww38h0CVUQNTeEUFFTWOa9Vnj1n1Barc7M0Trr6g/xd2jeAErvy4Mn2sJlYIL+Y4+gA=\"}",
      "go": "REJECT: dispatch: vote voter != envelope validatorID"
    },
    {
      "nom": "corps_Voter_autre",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"NeuRC2+W45lMky6WSGtRQyuBn9GTn0WNsNbfCsl44m4=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v1\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"rqiTUdd9ZskGY5duDwkyM9GWuSsSjUOGToAlvz7hRQRrKDwSYzX4eR6e5xdYJWgp72fLf2mKw2rR6YeEob7APgE=\"}",
      "go": "REJECT: verify: body voter mismatch"
    },
    {
      "nom": "corps_Voter_nombre",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"wIJjHKhSY4yZ38zxDfaFpoaqmg6ZwnQaQ9L7Tn/jExA=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":2,\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"VR9VgbmK4J4k7K/DSPq47JTZu3eH03pZj8cfowwHMcNWINkaHsvbI2HzRW7hzzpxmskx5bKx7S11O9Mdjb5/9gA=\"}",
      "go": "REJECT: verify: body parse: json: cannot unmarshal number into Go struct field Vote.Voter of type string"
    },
    {
      "nom": "corps_Type_1_sous_enveloppe_precommit",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"QbvDk0xSd6YuJcIDlPt1hLTP2IYbMYxB5gXXWYELeeQ=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v2\",\"Type\":1,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"QX/1CWAvqxWijCWum08nPecU2SeyrBhsl7c2sxCaDAgKudgKpffMQBPdNZhJsHzh/pH8+3FCWXA2z2r/MXNf1AA=\"}",
      "go": "OK"
    },
    {
      "nom": "corps_Type_null",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"h/1WSLc8NFmWk2Yvq+MB8n2uJhRn3rij3Ybl1kQGK+0=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v2\",\"Type\":null,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"WPGyODuRHro2oxN6HTsRLR6jrl5Ef40YmYFdHQVKQBtpvb89JQQPoeWXiKIvyb3tR3rsmqy51xZcH8xoa+KmlQA=\"}",
      "go": "OK"
    },
    {
      "nom": "corps_Type_chaine",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"IN+ev+8ARH4Pyt/5e8K2EH97Qcl18nIoHVCHyqANJNA=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v2\",\"Type\":\"2\",\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"TKt5Hiz+VhiW5VQr/5lxHH7Dg8Upu6mNFyYBcFAMdzoCVAwLa7LbOKHCqjwonz2KXTjOM1kilOKJl/T4RFUHtQA=\"}",
      "go": "REJECT: verify: body parse: json: cannot unmarshal string into Go struct field Vote.Type of type consensus.VoteType"
    },
    {
      "nom": "corps_Type_256",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"JZpVb8ymtkjvqJ0vueSbHXTLCwSVpFpW79U+nkW3C1E=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v2\",\"Type\":256,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"cp4WCV2RZdcXBKKl/YHxRCmVyfQmenZN3hj+WWP+ZRNgzsnt9R2KP13YrjNelt984zSOM9XAz4g725Sy9+w4MgA=\"}",
      "go": "REJECT: verify: body parse: json: cannot unmarshal number 256 into Go struct field Vote.Type of type consensus.VoteType"
    },
    {
      "nom": "corps_BlockHash_0X",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"KOCXikobpXHrd46hjPRjue+OzvLh7OkxGcfhSH+wX2A=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v2\",\"Type\":2,\"BlockHash\":\"0X7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"RYrK0kpwtylNMXMQNcyUe8T417alcyJSm9VW3OkM6tR8hAiz+y8K4rWbqEm52VBNyOloM1UxYt/1VJUyc55iyQE=\"}",
      "go": "OK"
    },
    {
      "nom": "corps_BlockHash_majuscules",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"dlsG9U2bUR99qhG3flhN8roc461MJnIxlnf5Mv5pZfo=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v2\",\"Type\":2,\"BlockHash\":\"0x7D5A3C9E1F0B2A4C6E8D0F1A3B5C7D9E1F2A4B6C8D0E2F4A6B8C0D1E3F5A7B9C\",\"Sig\":null},\"sig\":\"+VUfWsW4hIrG/JmVvMOVxQadGM9NlPPmjE8+PzjtPu0biJJBYKmoR8oCqDWHFK0ROJ0iqlIxrfxKE9ovxcJ9sAE=\"}",
      "go": "OK"
    },
    {
      "nom": "corps_BlockHash_sans_0x",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"TDU/v0ScrIwfckC/IamO+y0nN+/41Tu/8BCflz2R8qs=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v2\",\"Type\":2,\"BlockHash\":\"7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"9zMXZ0I5dcErIXb0hW1SWx6E0bnv5DRTnJ3i3cWLUBBHhgPm3XiNGyC2BbTX915QYas7VShmbPV8WvY794cvEwA=\"}",
      "go": "REJECT: verify: body parse: json: cannot unmarshal hex string without 0x prefix into Go struct field Vote.BlockHash of type common.Hash"
    },
    {
      "nom": "corps_BlockHash_null",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"i7juy53KgAs1Al65WLHg1NOXpSlCol9+PPY5v/aRMgU=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v2\",\"Type\":2,\"BlockHash\":null,\"Sig\":null},\"sig\":\"6AGycylUBbWU+Ey+WNxlKixv1Nh+0KEeI5W0+2rUduMMXt5WluKJQfzl4hld016RrsWRO6kpKnd3dyuObkwrVQE=\"}",
      "go": "REJECT: verify: body parse: json: cannot unmarshal non-string into Go struct field Vote.BlockHash of type common.Hash"
    },
    {
      "nom": "corps_BlockHash_absent",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"lUkzvuSCEu4FXAvcVd7B4YceEhz30oIAJWiBLfTXttw=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v2\",\"Type\":2,\"Sig\":null},\"sig\":\"YeCP0iW3e8g7TZ6LxXxyQFStgfSAa7DKuy9eQiEQGzsMcYz5+7YeG0/oQeugIzhtuW2fju5DwKQ2Ll23C/wKPgA=\"}",
      "go": "REJECT: verify: blockHash envelope/body mismatch"
    },
    {
      "nom": "corps_tableau",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"SaZHF9XUyxmVLm6sKUZBXPaHmtrPmQjn2HIzLTLG5oQ=\",\"body\":[1,2],\"sig\":\"C2Bos0foJpdRRs0dSFVIbjeyY/GN1iS0ogRru857NbZK83hNepZKNi+GT7l3/F97ahnQcm+oyn+HOwmdTJ6YvwE=\"}",
      "go": "REJECT: verify: body parse: json: cannot unmarshal array into Go value of type consensus.Vote"
    },
    {
      "nom": "corps_null",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"dCNOmK/nSY+12vHzasLXiswzlGT5UHA7jAGYkvmCuQs=\",\"body\":null,\"sig\":\"KI4V5OwfdleMTsOWSbAwaOkPcec502Rv/2O3hqe3IFtErmUxn/5UvcITbeYqjz/J3JTCwb53Jo6OWuZJIEbrLgA=\"}",
      "go": "REJECT: verify: body height/round mismatch"
    },
    {
      "nom": "corps_Height_2p53_plus_1",
      "type": "CONS_PRECOMMIT",
      "height": "9007199254740993",
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":9007199254740993,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"4s9aJOnabcqbn4Xp0bkmeBNkef8pVTbY60wZu0Aofes=\",\"body\":{\"Height\":9007199254740993,\"Round\":1,\"Voter\":\"v2\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"FpwS3W/HVtZmo8fcqTXDU1kUENnshhDLGjEQx5xshIwh5hdZMeV/4UOvlJrSBcBq9p5DiWeMwu9yBp3+PdrBiAE=\"}",
      "go": "OK"
    },
    {
      "nom": "corps_Height_u64max",
      "type": "CONS_PRECOMMIT",
      "height": "18446744073709551615",
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":18446744073709551615,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"J1GGw2D4zijPAF+GfpyDvLAYNI3WFfa586XsxZaQ0VE=\",\"body\":{\"Height\":18446744073709551615,\"Round\":1,\"Voter\":\"v2\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"orqhHCmO0hQz9lRy7lXTr3Tt7iHtAFEiJsvhqEMd6pMq4v+SahWhVrte+ggqMNWFl8BtfxGad/fX1oEr1wshnQA=\"}",
      "go": "OK"
    },
    {
      "nom": "proposition_canonique_v2",
      "type": "CONS_PROPOSAL",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PROPOSAL\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"CsFUnEfi5gBgT05agS4qET8Y19IOZKf6w1fPzD7xK5A=\",\"body\":{\"height\":8328,\"round\":1,\"proposer\":\"v2\",\"blockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"parentHash\":\"0x1111111111111111111111111111111111111111111111111111111111111110\",\"timestamp\":1761050000,\"stateRoot\":\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"receiptsRoot\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"txRoot\":\"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"gasUsed\":21000,\"gasLimit\":30000000,\"baseFeeHex\":\"0x1\",\"txsRaw\":[\"+GwBAgM=\"]},\"sig\":\"s6bb6pwRLZgU6ubsTelWrMgZhrQnWdCVyqbNiBQ7tp0r/PyMhdhPPfqmhllxqdunMAJNj9IO9PdLSbYeatiiRQA=\"}",
      "go": "OK"
    },
    {
      "nom": "proposition_proposer_vide",
      "type": "CONS_PROPOSAL",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PROPOSAL\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"ieMN1OiWyqbiuS1EcQjj6G+yR86Kn7m03PeGosfOFPQ=\",\"body\":{\"height\":8328,\"round\":1,\"proposer\":\"\",\"blockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"parentHash\":\"0x1111111111111111111111111111111111111111111111111111111111111110\",\"timestamp\":1761050000,\"stateRoot\":\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"receiptsRoot\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"txRoot\":\"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"gasUsed\":21000,\"gasLimit\":30000000,\"baseFeeHex\":\"0x1\",\"txsRaw\":[\"+GwBAgM=\"]},\"sig\":\"D/+YBmH3hD0hhHMQaxFJQKJx8j4kUnWcssamZinZdctn3MAi0vtqpTwaMG6jNsZdAwqqDrf02PUZhgwEavzFswA=\"}",
      "go": "OK"
    },
    {
      "nom": "proposition_proposer_autre",
      "type": "CONS_PROPOSAL",
      "height": 8328,
      "round": 1,
      "jeu": "standard",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PROPOSAL\",\"validatorId\":\"v2\",\"valsetHash\":\"UZ1KILTsf0Zn4POnS4lTmIgqs+DTuL1bqq42KZ7A6zQ=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"3oaDI/YVxfUBgL4TXva6BBwnfK7OjqcnjKcPIhjA2cc=\",\"body\":{\"height\":8328,\"round\":1,\"proposer\":\"v1\",\"blockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"parentHash\":\"0x1111111111111111111111111111111111111111111111111111111111111110\",\"timestamp\":1761050000,\"stateRoot\":\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"receiptsRoot\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"txRoot\":\"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"gasUsed\":21000,\"gasLimit\":30000000,\"baseFeeHex\":\"0x1\",\"txsRaw\":[\"+GwBAgM=\"]},\"sig\":\"2m6K2GEGYtEgpGH/+1ME/D797M1Qp/g5cahVZoBLbBBuXzBb4OyizsmI2QhtqCsee53y5i7UCseBvd/0e8D9RwE=\"}",
      "go": "REJECT: verify: body proposer mismatch"
    },
    {
      "nom": "precommit_v1_jeu_cle_compressee",
      "type": "CONS_PRECOMMIT",
      "height": 8328,
      "round": 1,
      "jeu": "v1Compresse",
      "ligne": "{\"domain\":\"noor/v1/bft\",\"chainId\":\"noortrace-2124-dev\",\"type\":\"CONS_PRECOMMIT\",\"validatorId\":\"v1\",\"valsetHash\":\"Qjjkmu//f2Hq9CnAyX4/K8w1uhvHNW5MtOlAwsVKC5Q=\",\"height\":8328,\"round\":1,\"blockHash\":\"fVo8nh8LKkxujQ8aO1x9nh8qS2yNDi9Ka4wNHj9ae5w=\",\"bodyHash\":\"NeuRC2+W45lMky6WSGtRQyuBn9GTn0WNsNbfCsl44m4=\",\"body\":{\"Height\":8328,\"Round\":1,\"Voter\":\"v1\",\"Type\":2,\"BlockHash\":\"0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c\",\"Sig\":null},\"sig\":\"f4FdYGN82ki9yDHEwGeysiHTeTlrOHjG7pzro5NZHEJSUJCsJHEPLGXL7o0RFjfYh1Be5wDEzWmJxsJAXelazgE=\"}",
      "go": "OK"
    }
  ],
  "quorum": {
    "0": 0,
    "1": 1,
    "10": 7,
    "11": 8,
    "12": 8,
    "13": 9,
    "2": 2,
    "3": 2,
    "4": 3,
    "5": 4,
    "6": 4,
    "7": 5,
    "8": 6,
    "9": 6
  },
  "valsetHash": {
    "1_solo": "0x9de6aaba5a824861c1a3ff002250b3aa69f09d9a735b0f9d1b26b36d46764f74",
    "4_uncompressed": "0x519d4a20b4ec7f4667e0f3a74b895398882ab3e0d3b8bd5baaae36299ec0eb34",
    "4_v1_compressed": "0x4238e49aefff7f61eaf429c0c97e3f2bcc35ba1bc7356e4cb4e940c2c54a0b94",
    "compressed_v1": "0x88a0093f4a2d04c00c4f4b6d739471c75a9b8ebe7352e39f7dc5e5bd0fa001a4",
    "compressed_v1_key": "0x034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
    "fichier": "0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751",
    "idOnly_b_a_c": "0x4c56138ed8993406211cf8f62eb88c4ffab43a8dc0fe9a8daca00c5d0fdb9ab4"
  }
};

const CHAINE = "noortrace-2124-dev";
const BLOC = "0x7d5a3c9e1f0b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d1e3f5a7b9c";

/** Jeu synthétique de `n` validateurs à clés jetables, trié par identifiant. */
function jeuJetable(n = 4, prefixe = "v") {
  const cles = {};
  const validators = [];
  for (let i = 1; i <= n; i++) {
    const id = `${prefixe}${i}`;
    cles[id] = new SigningKey(hex(randomBytes(32)));
    validators.push({ id, pubKeyHex: cles[id].publicKey });
  }
  return { cles, fichier: { validators }, valsetHash: hachageJeuValidateurs(validators) };
}

/** Proposition de référence pour un bloc donné. */
function propositionPour(proposant, blockHash, hauteur = 8328, ronde = 1) {
  return {
    height: hauteur,
    round: ronde,
    proposer: proposant,
    blockHash,
    parentHash: "0x1111111111111111111111111111111111111111111111111111111111111110",
    timestamp: 1761050000,
    stateRoot: "0x" + "aa".repeat(32),
    receiptsRoot: "0x" + "bb".repeat(32),
    txRoot: "0x" + "cc".repeat(32),
    gasUsed: 21000,
    gasLimit: 30000000,
    baseFeeHex: "0x1",
    txsRaw: ["0xf86c010203"],
  };
}

/**
 * Certificat synthétique au schéma Go, signé par le jeu `jeu` : proposition de
 * `proposant`, precommits des `signataires`. Rend l'objet DecidedCert.
 */
function certificatSynthetique(jeu, { proposant = "v1", signataires = ["v1", "v2", "v3"], hauteur = 8328, ronde = 1, blockHash = BLOC, chainId = CHAINE } = {}) {
  const contexte = (id) => ({ chainId, valsetHash: jeu.valsetHash, validatorId: id });
  return {
    chainId,
    valsetHash: jeu.valsetHash,
    h: hauteur,
    r: ronde,
    hash: blockHash,
    prop: signerProposition(propositionPour(proposant, blockHash, hauteur, ronde), contexte(proposant), jeu.cles[proposant]),
    cmts: signataires.map((id) => signerVote({ height: hauteur, round: ronde, voter: id, type: VOTE_PRECOMMIT, blockHash }, contexte(id), jeu.cles[id])),
  };
}

/** Remplace, dans une ligne brute, la valeur JSON d'un membre de premier niveau. */
function remplacerMembre(ligne, cle, nouvelleValeurJSON) {
  const brut = membresBruts(ligne).get(cle);
  expect(brut, `membre ${cle} présent`).to.not.equal(undefined);
  const motif = `"${cle}":${brut}`;
  expect(ligne.includes(motif)).to.equal(true);
  return ligne.replace(motif, `"${cle}":${nouvelleValeurJSON}`);
}

/** Les contrôles en échec d'un résultat, par nom. */
const echecs = (res) => res.controles.filter((c) => !c.ok).map((c) => c.nom);
const controle = (res, nom, indice) => res.controles.find((c) => c.nom === nom && (indice === undefined || c.indice === indice));

describe("Certificat de commit — parité avec le code Go", function () {
  const G = VECTEURS_GO;
  const C = G.certificat;

  it("digestEnveloppe reproduit SigningDigest (precommit, proposition en UTF-8 accentué, champs vides, u64 maximal)", function () {
    for (const d of G.digests) expect(digestEnveloppe(d), `digest ${d.type || "(vide)"}`).to.equal(d.digest);
  });

  it("quorum reproduit Quorum2f1 pour N de 0 à 13", function () {
    for (const [n, q] of Object.entries(G.quorum)) expect(quorum(Number(n)), `N=${n}`).to.equal(q);
  });

  it("hachageJeuValidateurs reproduit ValidatorSetHash : ordre d'entrée indifférent, clés brutes non normalisées, jeu sans clés", function () {
    // validators.json du réseau de développement (copie versionnée dans test/fixtures/certificat-commit).
    const dev = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "test", "fixtures", "certificat-commit", "validators.json"), "utf8"));
    const v = dev.validators;
    expect(hachageJeuValidateurs([v[2], v[0], v[3], v[1]])).to.equal(G.valsetHash.fichier);
    expect(hachageJeuValidateurs(dev)).to.equal(G.valsetHash.fichier);
    expect(chargerJeuValidateurs(dev).hachage).to.equal(G.valsetHash.fichier);
    expect(hachageJeuValidateurs([{ id: "b" }, { id: "a" }, { id: "c" }])).to.equal(G.valsetHash.idOnly_b_a_c);
    expect(hachageJeuValidateurs([{ id: "x", pubKeyHex: G.valsetHash.compressed_v1_key }])).to.equal(G.valsetHash.compressed_v1);
    expect(hachageJeuValidateurs([{ id: "x", pubKeyHex: normaliserClePublique(G.valsetHash.compressed_v1_key) }])).to.not.equal(G.valsetHash.compressed_v1);
  });

  it("le certificat produit par Go est valide contre son jeu : 3 signataires distincts, quorum 3 sur 4, proposant v2", function () {
    const res = verifierCertificat(C.certJSON, C.validators);
    expect(echecs(res)).to.deep.equal([]);
    expect(res.valide).to.equal(true);
    expect(res.signataires).to.deep.equal(["v1", "v2", "v4"]);
    expect(res.quorum).to.equal(3);
    expect(res.tailleJeu).to.equal(4);
    expect(res.proposant).to.equal("v2");
    expect(res.hauteur).to.equal(8328);
    expect(res.ronde).to.equal(1);
    expect(res.blockHash).to.equal(C.certJSON.hash);
    expect(res.valsetHash).to.equal(C.valsetHash);
    expect(res.controles.map((c) => c.nom)).to.deep.equal(["structure", "jeu_validateurs", "hachage_jeu", "proposition", "precommit", "precommit", "precommit", "signataires_distincts", "quorum"]);
  });

  it("bodyHash, digest et clé recouvrée de chaque precommit Go sont ceux du Go", function () {
    C.precommits.forEach((p, i) => {
      const env = analyserEnveloppe(C.certJSON.cmts[i]);
      expect(env.corpsBrut).to.equal(p.body);
      expect(hex(sha256(Buffer.from(env.corpsBrut, "utf8")))).to.equal(p.bodyHash);
      expect(hex(env.bodyHash)).to.equal(p.bodyHash);
      const digest = digestEnveloppe({ ...env, bodyHash: env.bodyHash });
      expect(digest).to.equal(p.digest);
      expect(hex(env.sig)).to.equal(p.sig);
      expect(recupererClePublique(digest, env.sig)).to.equal(C.pubKeyHex[p.validatorId]);
    });
    const prop = analyserEnveloppe(C.certJSON.prop);
    expect(prop.corpsBrut).to.equal(C.propBody);
    expect(hex(prop.bodyHash)).to.equal(C.propBodyHash);
    expect(digestEnveloppe({ ...prop, bodyHash: prop.bodyHash })).to.equal(C.propDigest);
    expect(hex(prop.sig)).to.equal(C.propSig);
    expect(recupererClePublique(C.propDigest, C.propSig)).to.equal(C.pubKeyHex.v2);
  });

  it("les constructeurs JS reproduisent octet pour octet les lignes Go (clés fixes, signatures RFC 6979)", function () {
    for (const id of ["v1", "v2", "v3", "v4"]) expect(clePubliqueDe(C.privHex[id])).to.equal(C.pubKeyHex[id]);
    const contexte = (id) => ({ chainId: CHAINE, valsetHash: C.valsetHash, validatorId: id });
    expect(encoderProposition(propositionPour("v2", BLOC))).to.equal(C.propBody);
    expect(signerProposition(propositionPour("v2", BLOC), contexte("v2"), C.privHex.v2)).to.equal(C.certJSON.prop);
    ["v1", "v2", "v4"].forEach((id, i) => {
      expect(encoderVote({ height: 8328, round: 1, voter: id, type: VOTE_PRECOMMIT, blockHash: BLOC })).to.equal(C.precommits[i].body);
      expect(signerVote({ height: 8328, round: 1, voter: id, type: VOTE_PRECOMMIT, blockHash: BLOC }, contexte(id), C.privHex[id])).to.equal(C.certJSON.cmts[i]);
    });
    expect(signerVote({ height: 8328, round: 1, voter: "v3", type: VOTE_PREVOTE, blockHash: BLOC }, contexte("v3"), C.privHex.v3)).to.equal(C.prevoteLine_v3);
    expect(signerVote({ height: 8328, round: 1, voter: "v3", type: VOTE_PRECOMMIT }, contexte("v3"), C.privHex.v3)).to.equal(C.nilPrecommitLine_v3);
    expect(signerEnveloppe({ type: TYPE_PRECOMMIT, chainId: CHAINE, valsetHash: C.valsetHash, validatorId: "v3", height: 8328, round: 1, blockHash: HACHAGE_NUL, body: C.precommits[0].body.replace('"v1"', '"v3"').replace(BLOC, HACHAGE_NUL) }, C.privHex.v3)).to.equal(C.nilPrecommitLine_v3);
  });

  it("une prevote Go à la place d'un precommit, ou un precommit nul Go, est refusé", function () {
    const avecPrevote = { ...C.certJSON, cmts: [C.certJSON.cmts[0], C.certJSON.cmts[1], C.prevoteLine_v3] };
    let res = verifierCertificat(avecPrevote, C.validators);
    expect(res.valide).to.equal(false);
    expect(controle(res, "precommit", 3).detail).to.match(/type « CONS_PREVOTE »/);
    expect(echecs(res)).to.deep.equal(["precommit", "quorum"]);

    const avecNul = { ...C.certJSON, cmts: [C.certJSON.cmts[0], C.certJSON.cmts[1], C.nilPrecommitLine_v3] };
    res = verifierCertificat(avecNul, C.validators);
    expect(res.valide).to.equal(false);
    expect(controle(res, "precommit", 3).detail).to.match(/bloc du corps 0x0{64} différent/);
  });

  it("le certificat Go est refusé contre le jeu du réseau de développement (autre jeu, même chaîne)", function () {
    const dev = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "test", "fixtures", "certificat-commit", "validators.json"), "utf8"));
    const res = verifierCertificat(C.certJSON, dev);
    expect(res.valide).to.equal(false);
    expect(echecs(res)).to.deep.equal(["hachage_jeu"]);
    expect(res.controles).to.have.length(3);
  });
});

describe("Certificat de commit — parité avec le décodeur du nœud (vecteurs « lignes » et « fichiers » du Go)", function () {
  const G = VECTEURS_GO;
  const jeux = Object.fromEntries(Object.entries(G.jeux).map(([nom, j]) => [nom, chargerJeuValidateurs(j.validators)]));

  it("chaque jeu des vecteurs se charge et hache comme en Go (v1 compressée comprise)", function () {
    for (const [nom, j] of Object.entries(G.jeux)) expect(jeux[nom].hachage, nom).to.equal(j.valsetHash);
    expect(jeux.v1Compresse.validateurs[0].pubKey).to.have.length(33);
    expect(jeux.v1Compresse.validateurs[0].cle).to.equal(jeux.standard.validateurs[0].cle);
  });

  it("chaque ligne reçoit ici le verdict que le nœud lui donne (DecodeSignedEnvelope, VerifyEnvelope, règle Voter du dispatcher)", function () {
    expect(G.lignes.length).to.be.greaterThan(40);
    const divergences = [];
    for (const l of G.lignes) {
      const jeu = jeux[l.jeu];
      const att = { type: l.type, chainId: G.certificat.certJSON.chainId, valsetHash: octets(jeu.hachage), hauteur: u64(l.height), ronde: u64(l.round), blockHash: octets(G.certificat.certJSON.hash), jeu };
      const r = verifierLigne(l.ligne, att);
      if (r.ok !== (l.go === "OK")) divergences.push(`${l.nom} : Go « ${l.go} », JS ${r.ok ? "accepte" : `refuse (${r.detail})`}`);
    }
    expect(divergences, divergences.join("\n")).to.deep.equal([]);
  });

  it("les formes non canoniques acceptées sont signalées, les canoniques ne le sont pas", function () {
    const parNom = Object.fromEntries(G.lignes.map((l) => [l.nom, l]));
    const verifier = (nom) => {
      const l = parNom[nom];
      const jeu = jeux[l.jeu];
      return verifierLigne(l.ligne, { type: l.type, chainId: G.certificat.certJSON.chainId, valsetHash: octets(jeu.hachage), hauteur: u64(l.height), ronde: u64(l.round), blockHash: octets(G.certificat.certJSON.hash), jeu });
    };
    for (const nom of ["canonique_v1", "proposition_canonique_v2", "espace_final", "ordre_membres_sig_en_tete", "corps_champ_inconnu", "precommit_v1_jeu_cle_compressee"]) {
      expect(verifier(nom).remarques, nom).to.deep.equal([]);
    }
    expect(verifier("cle_Domain_majuscule").remarques).to.deep.equal(["membre « Domain » pour « domain »"]);
    expect(verifier("cle_ſig_s_long").remarques).to.deep.equal(["membre « ſig » pour « sig »"]);
    expect(verifier("cle_blocKHash_kelvin").remarques).to.deep.equal(["membre « blocKHash » pour « blockHash »"]);
    expect(verifier("base64_sig_non_canonique").remarques).to.deep.equal(["base64 non canonique pour « sig »"]);
    expect(verifier("base64_sig_avec_saut_de_ligne").remarques).to.deep.equal(["base64 non canonique pour « sig »"]);
    expect(verifier("corps_cles_minuscules").remarques).to.include.members(["membre « height » pour « Height »", "membre « voter » pour « Voter »"]);
    expect(verifier("corps_Voter_vide").remarques).to.deep.equal(["Vote.Voter vide"]);
    expect(verifier("corps_Voter_null").remarques).to.deep.equal(["Vote.Voter vide"]);
    expect(verifier("corps_Type_1_sous_enveloppe_precommit").remarques).to.deep.equal(["Vote.Type 1 sous une enveloppe CONS_PRECOMMIT"]);
    expect(verifier("corps_Type_null").remarques).to.deep.equal(["Vote.Type absent"]);
    expect(verifier("corps_BlockHash_0X").remarques).to.deep.equal(["hachage non canonique pour « Vote.BlockHash »"]);
    expect(verifier("corps_BlockHash_majuscules").remarques).to.deep.equal(["hachage non canonique pour « Vote.BlockHash »"]);
    expect(verifier("proposition_proposer_vide").remarques).to.deep.equal(["Proposal.proposer vide"]);
    // Les motifs de refus restent nommés.
    expect(verifier("corps_Type_2.0").detail).to.match(/Vote\.Type : entier non signé attendu/);
    expect(verifier("corps_Height_8328.0").detail).to.match(/Vote\.Height : entier non signé attendu/);
    expect(verifier("corps_Voter_espaces").detail).to.match(/Vote\.Voter «\s+» différent du signataire/);
    expect(verifier("corps_Voter_autre").detail).to.match(/Vote\.Voter « v1 » différent du signataire « v2 »/);
    expect(verifier("cle_dupliquee_derniere_gagne_fausse").detail).to.match(/domaine « autre »/);
    expect(verifier("base64_sig_alphabet_url").detail).to.match(/sig : base64 invalide/);
    expect(verifier("proposition_proposer_autre").detail).to.match(/Proposal\.proposer « v1 » différent du signataire « v2 »/);
    // Un certificat entier dont les lignes sont non canoniques est VALIDE, remarques à l'appui.
    const nonCanonique = { ...G.certificat.certJSON, cmts: [parNom.cle_Domain_majuscule.ligne, parNom.corps_cles_minuscules.ligne, parNom.corps_BlockHash_0X.ligne.replace('"validatorId":"v2"', '"validatorId":"v2"')] };
    const res = verifierCertificat({ ...nonCanonique, cmts: [parNom.cle_Domain_majuscule.ligne, parNom.base64_sig_non_canonique.ligne, G.certificat.certJSON.cmts[1], G.certificat.certJSON.cmts[2]] }, G.certificat.validators);
    expect(res.valide).to.equal(false); // v1 deux fois (lignes 1 et 2) : signataires en double
    expect(echecs(res)).to.deep.equal(["signataires_distincts"]);
    const res2 = verifierCertificat({ ...G.certificat.certJSON, cmts: [parNom.cle_Domain_majuscule.ligne, parNom.corps_Voter_vide.ligne, G.certificat.certJSON.cmts[2]] }, G.certificat.validators);
    expect(res2.valide).to.equal(true);
    expect(res2.signataires).to.deep.equal(["v1", "v2", "v4"]);
    expect(controle(res2, "precommit", 1).remarques).to.deep.equal(["membre « Domain » pour « domain »"]);
    expect(controle(res2, "precommit", 2).remarques).to.deep.equal(["Vote.Voter vide"]);
  });

  it("chaque validators.json des vecteurs se charge comme LoadValidatorSetFile (nettoyage Unicode, casse des membres, dernier doublon, 0X refusé, types)", function () {
    expect(G.fichiers.length).to.be.greaterThan(5);
    for (const f of G.fichiers) {
      if (f.erreur) {
        expect(() => chargerJeuValidateurs(JSON.parse(f.contenu)), f.nom).to.throw();
      } else {
        const jeu = chargerJeuValidateurs(JSON.parse(f.contenu));
        expect(jeu.validateurs.map((v) => v.id), f.nom).to.deep.equal(f.ids);
        expect(jeu.hachage, f.nom).to.equal(f.hachage);
      }
    }
  });
});

describe("Certificat de commit — vecteurs synthétiques et altérations", function () {
  const jeu = jeuJetable(4);
  const certificat = certificatSynthetique(jeu);

  it("un certificat valide à 3 precommits sur 4 est accepté ; à 4 aussi ; à 2 non (quorum)", function () {
    let res = verifierCertificat(certificat, jeu.fichier);
    expect(echecs(res)).to.deep.equal([]);
    expect(res.valide).to.equal(true);
    expect(res.signataires).to.deep.equal(["v1", "v2", "v3"]);
    expect(res.proposant).to.equal("v1");

    res = verifierCertificat(certificatSynthetique(jeu, { signataires: ["v4", "v3", "v2", "v1"] }), jeu.fichier);
    expect(res.valide).to.equal(true);
    expect(res.signataires).to.deep.equal(["v1", "v2", "v3", "v4"]);

    res = verifierCertificat({ ...certificat, cmts: certificat.cmts.slice(0, 2) }, jeu.fichier);
    expect(res.valide).to.equal(false);
    expect(echecs(res)).to.deep.equal(["quorum"]);
    expect(res.signataires).to.deep.equal(["v1", "v2"]);
    expect(controle(res, "quorum").detail).to.match(/2 signataire\(s\) distinct\(s\) valide\(s\) pour un quorum de 3 sur 4 : insuffisant/);
  });

  it("le jeu déjà chargé (chargerJeuValidateurs) et le texte JSON du fichier sont acceptés comme jeu", function () {
    expect(verifierCertificat(certificat, chargerJeuValidateurs(jeu.fichier)).valide).to.equal(true);
    expect(verifierCertificat(certificat, JSON.stringify(jeu.fichier)).valide).to.equal(true);
    expect(verifierCertificat(JSON.stringify(certificat), jeu.fichier).valide).to.equal(true);
  });

  it("signature modifiée : la clé recouvrée n'est plus celle du validateur", function () {
    const sig = analyserEnveloppe(certificat.cmts[1]).sig;
    sig[10] ^= 0x01;
    const alteree = remplacerMembre(certificat.cmts[1], "sig", JSON.stringify(sig.toString("base64")));
    const res = verifierCertificat({ ...certificat, cmts: [certificat.cmts[0], alteree, certificat.cmts[2]] }, jeu.fichier);
    expect(res.valide).to.equal(false);
    expect(echecs(res)).to.deep.equal(["precommit", "quorum"]);
    expect(controle(res, "precommit", 2).detail).to.match(/recouvre 0x04[0-9a-f]{128}, pas la clé de « v2 »|recouvrement de la clé impossible/);
    expect(res.signataires).to.deep.equal(["v1", "v3"]);
  });

  it("blockHash du certificat modifié : proposition et precommits ne désignent plus ce bloc", function () {
    const autre = "0x" + "9".repeat(64);
    const res = verifierCertificat({ ...certificat, hash: autre }, jeu.fichier);
    expect(res.valide).to.equal(false);
    expect(echecs(res)).to.deep.equal(["proposition", "precommit", "precommit", "precommit", "quorum"]);
    expect(controle(res, "proposition").detail).to.match(/bloc du corps .* différent du certificat/);
    expect(res.signataires).to.deep.equal([]);
  });

  it("blockHash d'enveloppe substitué sans toucher au corps : refusé (puis la signature ne tiendrait plus de toute façon)", function () {
    const autre = Buffer.from("9".repeat(64), "hex").toString("base64");
    const alteree = remplacerMembre(certificat.cmts[0], "blockHash", JSON.stringify(autre));
    const res = verifierCertificat({ ...certificat, cmts: [alteree, certificat.cmts[1], certificat.cmts[2]] }, jeu.fichier);
    expect(controle(res, "precommit", 1).ok).to.equal(false);
    expect(controle(res, "precommit", 1).detail).to.match(/blockHash d'enveloppe .* différent du certificat/);
  });

  it("signataire dupliqué : refusé, qu'il fasse ou non tomber le compte sous le quorum", function () {
    let res = verifierCertificat({ ...certificat, cmts: [certificat.cmts[0], certificat.cmts[1], certificat.cmts[0]] }, jeu.fichier);
    expect(res.valide).to.equal(false);
    expect(echecs(res)).to.deep.equal(["signataires_distincts", "quorum"]);
    expect(controle(res, "signataires_distincts").detail).to.match(/« v1 » \(lignes 1 et 3\)/);
    expect(res.signataires).to.deep.equal(["v1", "v2"]);

    res = verifierCertificat({ ...certificat, cmts: [...certificat.cmts, certificat.cmts[2]] }, jeu.fichier);
    expect(res.valide).to.equal(false);
    expect(echecs(res)).to.deep.equal(["signataires_distincts"]);
    expect(res.signataires).to.deep.equal(["v1", "v2", "v3"]);
  });

  it("validateur hors jeu : identifiant inconnu, ou identifiant connu signé par une autre clé", function () {
    const intrus = new SigningKey(hex(randomBytes(32)));
    const contexte = (id) => ({ chainId: CHAINE, valsetHash: jeu.valsetHash, validatorId: id });
    const vote = (id) => ({ height: 8328, round: 1, voter: id, type: VOTE_PRECOMMIT, blockHash: BLOC });
    const inconnu = signerVote(vote("v9"), contexte("v9"), intrus);
    const usurpe = signerVote(vote("v4"), contexte("v4"), intrus);
    const res = verifierCertificat({ ...certificat, cmts: [certificat.cmts[0], certificat.cmts[1], inconnu, usurpe] }, jeu.fichier);
    expect(res.valide).to.equal(false);
    expect(controle(res, "precommit", 3).detail).to.match(/validateur « v9 » absent du jeu fourni/);
    expect(controle(res, "precommit", 4).detail).to.match(/pas la clé de « v4 »/);
    expect(res.signataires).to.deep.equal(["v1", "v2"]);
  });

  it("mauvais fichier de validateurs : le hachage du jeu ne correspond pas et la vérification s'arrête là", function () {
    const autre = jeuJetable(4);
    let res = verifierCertificat(certificat, autre.fichier);
    expect(res.valide).to.equal(false);
    expect(echecs(res)).to.deep.equal(["hachage_jeu"]);
    expect(res.controles).to.have.length(3);
    expect(res.signataires).to.deep.equal([]);
    // Mêmes clés, un identifiant renommé : autre jeu.
    const renomme = { validators: jeu.fichier.validators.map((v) => (v.id === "v4" ? { ...v, id: "v5" } : v)) };
    res = verifierCertificat(certificat, renomme);
    expect(echecs(res)).to.deep.equal(["hachage_jeu"]);
    // Un fichier de validateurs inexploitable est un échec de contrôle, pas une exception.
    res = verifierCertificat(certificat, { validators: [] });
    expect(echecs(res)).to.deep.equal(["jeu_validateurs"]);
    res = verifierCertificat(certificat, { validators: [{ id: "v1", pubKeyHex: "0x01" }] });
    expect(controle(res, "jeu_validateurs").detail).to.match(/inexploitable/);
  });

  it("type prevote au lieu de precommit : enveloppe CONS_PREVOTE, ou enveloppe CONS_PRECOMMIT dont le corps a Type 1", function () {
    const contexte = { chainId: CHAINE, valsetHash: jeu.valsetHash, validatorId: "v3" };
    const prevote = signerVote({ height: 8328, round: 1, voter: "v3", type: VOTE_PREVOTE, blockHash: BLOC }, contexte, jeu.cles.v3);
    let res = verifierCertificat({ ...certificat, cmts: [certificat.cmts[0], certificat.cmts[1], prevote] }, jeu.fichier);
    expect(res.valide).to.equal(false);
    expect(controle(res, "precommit", 3).detail).to.match(/type « CONS_PREVOTE » au lieu de « CONS_PRECOMMIT »/);

    // Une enveloppe CONS_PRECOMMIT dont le corps porte Type 1 : le nœud ne compare
    // pas Vote.Type au type de l'enveloppe (VerifyEnvelope) et son dispatcher
    // impose celui de l'enveloppe ; la ligne compte donc comme precommit, et le
    // rapport signale la forme non canonique.
    const corpsPrevote = encoderVote({ height: 8328, round: 1, voter: "v3", type: VOTE_PREVOTE, blockHash: BLOC });
    const deguise = signerEnveloppe({ ...contexte, type: TYPE_PRECOMMIT, height: 8328, round: 1, blockHash: BLOC, body: corpsPrevote }, jeu.cles.v3);
    res = verifierCertificat({ ...certificat, cmts: [certificat.cmts[0], certificat.cmts[1], deguise] }, jeu.fichier);
    expect(res.valide).to.equal(true);
    expect(controle(res, "precommit", 3).ok).to.equal(true);
    expect(controle(res, "precommit", 3).remarques).to.deep.equal(["Vote.Type 1 sous une enveloppe CONS_PRECOMMIT"]);
    expect(controle(res, "precommit", 3).detail).to.match(/forme non canonique acceptée comme par le nœud : Vote\.Type 1 sous une enveloppe CONS_PRECOMMIT/);
    expect(controle(res, "precommit", 1).remarques).to.equal(undefined);
  });

  it("bodyHash incohérent : bodyHash déclaré faux, ou corps modifié sous un bodyHash intact", function () {
    const faux = Buffer.alloc(32, 7).toString("base64");
    let alteree = remplacerMembre(certificat.cmts[0], "bodyHash", JSON.stringify(faux));
    let res = verifierCertificat({ ...certificat, cmts: [alteree, certificat.cmts[1], certificat.cmts[2]] }, jeu.fichier);
    expect(res.valide).to.equal(false);
    expect(controle(res, "precommit", 1).detail).to.match(/bodyHash déclaré 0x0707.* ≠ sha256\(corps\)/);

    const corps = membresBruts(certificat.cmts[0]).get("body");
    alteree = remplacerMembre(certificat.cmts[0], "body", corps.replace('"Voter":"v1"', '"Voter":"v1 "'));
    res = verifierCertificat({ ...certificat, cmts: [alteree, certificat.cmts[1], certificat.cmts[2]] }, jeu.fichier);
    expect(controle(res, "precommit", 1).detail).to.match(/bodyHash déclaré .* ≠ sha256\(corps\)/);

    // Le corps est haché sur ses octets d'origine : un espace ajouté dans le JSON du corps suffit.
    alteree = remplacerMembre(certificat.cmts[0], "body", corps.replace('"Round":1,', '"Round":1, '));
    res = verifierCertificat({ ...certificat, cmts: [alteree, certificat.cmts[1], certificat.cmts[2]] }, jeu.fichier);
    expect(controle(res, "precommit", 1).detail).to.match(/bodyHash déclaré .* ≠ sha256\(corps\)/);
  });

  it("S haut : la signature malléée recouvre la même clé mais n'est pas canonique, donc refusée", function () {
    const env = analyserEnveloppe(certificat.cmts[2]);
    const s = BigInt(hex(env.sig.subarray(32, 64)));
    expect(s <= MOITIE_N_SECP256K1).to.equal(true);
    const sHaut = N_SECP256K1 - s;
    const haute = Buffer.concat([env.sig.subarray(0, 32), Buffer.from(sHaut.toString(16).padStart(64, "0"), "hex"), Buffer.from([env.sig[64] ^ 1])]);
    expect(signatureCanonique(env.sig)).to.equal(true);
    expect(signatureCanonique(haute)).to.equal(false);
    const digest = digestEnveloppe({ ...env, bodyHash: env.bodyHash });
    // (r, N − s, V ^ 1) est une seconde signature ECDSA valide du même digest par la même clé : c'est la
    // malléabilité que le contrôle de forme ferme, avec un motif explicite (ethers refuse aussi un S haut,
    // mais par une erreur d'argument interne).
    expect(s + sHaut).to.equal(N_SECP256K1);
    expect(() => recupererClePublique(digest, haute)).to.throw(/non canonique/);
    expect(() => SigningKey.recoverPublicKey(digest, { r: hex(haute.subarray(0, 32)), s: hex(haute.subarray(32, 64)), v: 27 + haute[64] })).to.throw(/non-canonical s/);

    const alteree = remplacerMembre(certificat.cmts[2], "sig", JSON.stringify(haute.toString("base64")));
    const res = verifierCertificat({ ...certificat, cmts: [certificat.cmts[0], certificat.cmts[1], alteree] }, jeu.fichier);
    expect(res.valide).to.equal(false);
    expect(controle(res, "precommit", 3).detail).to.match(/signature non canonique/);
    // V hors {0, 1} est refusé de même.
    const vFaux = Buffer.concat([env.sig.subarray(0, 64), Buffer.from([27 + env.sig[64]])]);
    expect(signatureCanonique(vFaux)).to.equal(false);
  });

  it("proposition : proposant différent du signataire, autre bloc, signataire hors jeu, ligne absente", function () {
    const contexte = (id) => ({ chainId: CHAINE, valsetHash: jeu.valsetHash, validatorId: id });
    const mauvaisProposant = signerProposition(propositionPour("v2", BLOC), contexte("v1"), jeu.cles.v1);
    let res = verifierCertificat({ ...certificat, prop: mauvaisProposant }, jeu.fichier);
    expect(res.valide).to.equal(false);
    expect(echecs(res)).to.deep.equal(["proposition"]);
    expect(controle(res, "proposition").detail).to.match(/Proposal\.proposer « v2 » différent du signataire « v1 »/);
    expect(res.proposant).to.equal(null);

    const autreBloc = signerProposition(propositionPour("v1", "0x" + "8".repeat(64)), contexte("v1"), jeu.cles.v1);
    res = verifierCertificat({ ...certificat, prop: autreBloc }, jeu.fichier);
    expect(controle(res, "proposition").detail).to.match(/bloc du corps .* différent du certificat/);

    const intrus = new SigningKey(hex(randomBytes(32)));
    const horsJeu = signerProposition(propositionPour("v7", BLOC), contexte("v7"), intrus);
    res = verifierCertificat({ ...certificat, prop: horsJeu }, jeu.fichier);
    expect(controle(res, "proposition").detail).to.match(/« v7 » absent du jeu fourni/);

    res = verifierCertificat({ ...certificat, prop: "" }, jeu.fichier);
    expect(echecs(res)).to.deep.equal(["structure"]);
    expect(controle(res, "structure").detail).to.match(/prop/);

    // Un precommit à la place de la proposition : type refusé.
    res = verifierCertificat({ ...certificat, prop: certificat.cmts[0] }, jeu.fichier);
    expect(controle(res, "proposition").detail).to.match(/type « CONS_PRECOMMIT » au lieu de « CONS_PROPOSAL »/);
  });

  it("chainId, hauteur, tour ou valsetHash du certificat modifiés : chaque ligne contredit le certificat", function () {
    let res = verifierCertificat({ ...certificat, chainId: "autre-chaine" }, jeu.fichier);
    expect(res.valide).to.equal(false);
    expect(controle(res, "precommit", 1).detail).to.match(/chainId « noortrace-2124-dev » au lieu de « autre-chaine »/);

    res = verifierCertificat({ ...certificat, h: 8329 }, jeu.fichier);
    expect(controle(res, "precommit", 1).detail).to.match(/hauteur 8328 au lieu de 8329/);

    res = verifierCertificat({ ...certificat, r: 0 }, jeu.fichier);
    expect(controle(res, "proposition").detail).to.match(/tour 1 au lieu de 0/);

    // valsetHash du certificat remplacé par celui d'un autre jeu : refusé avant même les lignes.
    const autre = jeuJetable(4);
    res = verifierCertificat({ ...certificat, valsetHash: autre.valsetHash }, jeu.fichier);
    expect(echecs(res)).to.deep.equal(["hachage_jeu"]);
    // … et si l'on fournit cet autre jeu, les lignes portent toujours l'ancien hachage.
    res = verifierCertificat({ ...certificat, valsetHash: autre.valsetHash }, autre.fichier);
    expect(controle(res, "precommit", 1).detail).to.match(/valsetHash .* différent de celui du certificat/);
  });

  it("options : bloc canonique, bloc demandé, hauteur et chaîne attendues", function () {
    let res = verifierCertificat(certificat, jeu.fichier, { blockHashCanonique: BLOC, blockHashAttendu: BLOC.toUpperCase().replace("0X", "0x"), hauteurAttendue: 8328, chainIdAttendu: CHAINE });
    expect(res.valide).to.equal(true);
    expect(res.controles.map((c) => c.nom)).to.include.members(["chaine", "hauteur", "bloc_demande", "bloc_canonique"]);

    res = verifierCertificat(certificat, jeu.fichier, { blockHashCanonique: "0x" + "5".repeat(64) });
    expect(res.valide).to.equal(false);
    expect(echecs(res)).to.deep.equal(["bloc_canonique"]);
    expect(controle(res, "bloc_canonique").detail).to.match(/≠ bloc canonique 0x5{64}/);

    res = verifierCertificat(certificat, jeu.fichier, { hauteurAttendue: "8300", chainIdAttendu: "noortrace-2124", blockHashAttendu: "0x" + "6".repeat(64) });
    expect(echecs(res)).to.deep.equal(["chaine", "hauteur", "bloc_demande"]);

    res = verifierCertificat(certificat, jeu.fichier, { blockHashCanonique: "pas-un-hachage" });
    expect(echecs(res)).to.deep.equal(["bloc_canonique"]);
  });

  it("structure : enveloppes RPC acceptées, champs manquants ou mal formés refusés, entrée qui n'est pas un certificat rejetée", function () {
    expect(verifierCertificat({ jsonrpc: "2.0", id: 1, result: certificat }, jeu.fichier).valide).to.equal(true);
    expect(verifierCertificat({ result: { certificate: certificat } }, jeu.fichier).valide).to.equal(true);
    const long = { chainId: certificat.chainId, valsetHash: certificat.valsetHash, height: 8328, round: 1, blockHash: certificat.hash, proposal: certificat.prop, precommits: certificat.cmts };
    expect(verifierCertificat(long, jeu.fichier).valide).to.equal(true);

    const structure = (c) => {
      const res = verifierCertificat(c, jeu.fichier);
      expect(res.valide).to.equal(false);
      expect(echecs(res)).to.deep.equal(["structure"]);
      return controle(res, "structure").detail;
    };
    expect(structure({ ...certificat, h: 0 })).to.match(/hauteur 0/);
    expect(structure({ ...certificat, h: -1 })).to.match(/hauteur/);
    expect(structure({ ...certificat, h: 1.5 })).to.match(/hauteur/);
    expect(structure({ ...certificat, r: "x" })).to.match(/tour/);
    expect(structure({ ...certificat, chainId: " " })).to.match(/chainId/);
    expect(structure({ ...certificat, valsetHash: "0x1234" })).to.match(/valsetHash : 32 octets attendus/);
    expect(structure({ ...certificat, hash: HACHAGE_NUL })).to.match(/hash \(bloc\) nul/);
    expect(structure({ ...certificat, hash: 12 })).to.match(/hash \(bloc\) absent/);
    expect(structure({ ...certificat, cmts: [] })).to.match(/cmts/);
    expect(structure({ ...certificat, cmts: [certificat.cmts[0], 5] })).to.match(/cmts\[1\]/);
    expect(structure({ ...certificat, prop: 42 })).to.match(/prop/);

    expect(() => normaliserCertificat(null)).to.throw(/objet JSON attendu/);
    expect(() => normaliserCertificat([1, 2])).to.throw(/objet JSON attendu/);
    expect(() => normaliserCertificat({ foo: 1 })).to.throw(/aucun des champs attendus/);
    expect(() => normaliserCertificat({ jsonrpc: "2.0", id: 1, result: null })).to.throw(/absent/);
    expect(() => normaliserCertificat({ jsonrpc: "2.0", id: 1, error: { code: -32601, message: "method not found" } })).to.throw(/method not found/);
    const res = verifierCertificat({ foo: 1 }, jeu.fichier);
    expect(echecs(res)).to.deep.equal(["structure"]);
  });

  it("une ligne illisible (JSON invalide, base64 invalide, entier non canonique, clé absente) est refusée avec le motif ; une graphie non canonique est acceptée et signalée", function () {
    const att = { type: TYPE_PRECOMMIT, chainId: CHAINE, valsetHash: octets(jeu.valsetHash), hauteur: 8328n, ronde: 1n, blockHash: octets(BLOC), jeu: chargerJeuValidateurs(jeu.fichier) };
    expect(verifierLigne("pas du json", att).detail).to.match(/enveloppe illisible/);
    expect(verifierLigne(certificat.cmts[0] + " x", att).detail).to.match(/texte après la fin/);
    expect(verifierLigne(remplacerMembre(certificat.cmts[0], "height", "8328.0"), att).detail).to.match(/height : entier non signé attendu/);
    expect(verifierLigne(remplacerMembre(certificat.cmts[0], "round", '"1"'), att).detail).to.match(/round : entier non signé attendu/);
    const sig = membresBruts(certificat.cmts[0]).get("sig");
    expect(verifierLigne(remplacerMembre(certificat.cmts[0], "sig", sig.replace(/=*"$/, '"')), att).detail).to.match(/sig : base64 invalide/);
    expect(verifierLigne(remplacerMembre(certificat.cmts[0], "sig", JSON.stringify(Buffer.alloc(64).toString("base64"))), att).detail).to.match(/signature de 64 octets/);
    expect(verifierLigne(certificat.cmts[0].replace('"domain"', '"domaine"'), att).detail).to.match(/domaine «  » au lieu de « noor\/v1\/bft »/);
    // « Domain » désigne le champ domain pour encoding/json : accepté, signalé.
    const casse = verifierLigne(certificat.cmts[0].replace('"domain"', '"Domain"'), att);
    expect(casse.ok).to.equal(true);
    expect(casse.remarques).to.deep.equal(["membre « Domain » pour « domain »"]);
    expect(verifierLigne(remplacerMembre(certificat.cmts[0], "domain", '"noor/v2/bft"'), att).detail).to.match(/domaine « noor\/v2\/bft »/);
    expect(verifierLigne(remplacerMembre(certificat.cmts[0], "body", "[1,2]"), att).detail).to.match(/bodyHash déclaré/);
    expect(verifierLigne(certificat.cmts[0], { ...att, type: "AUTRE" }).detail).to.match(/type « CONS_PRECOMMIT » au lieu de « AUTRE »/);
    // Un vote dont le Voter n'est pas le signataire, signé de façon cohérente par ce signataire.
    const contexte = { chainId: CHAINE, valsetHash: jeu.valsetHash, validatorId: "v1" };
    const corps = encoderVote({ height: 8328, round: 1, voter: "v2", type: VOTE_PRECOMMIT, blockHash: BLOC });
    const ligne = signerEnveloppe({ ...contexte, type: TYPE_PRECOMMIT, height: 8328, round: 1, blockHash: BLOC, body: corps }, jeu.cles.v1);
    expect(verifierLigne(ligne, att).detail).to.match(/Vote\.Voter « v2 » différent du signataire « v1 »/);
  });
});

describe("Certificat de commit — briques", function () {
  it("membresBruts découpe exactement les valeurs de premier niveau (imbrication, accolades et guillemets dans les chaînes, clé répétée)", function () {
    const texte = ' {"a" : {"x":"}{\\"", "y":[1,{"z":null}]} ,"b":"\\u00e9{", "c" : 12.5e3,"d":true,"a":[] } ';
    const m = membresBruts(texte);
    expect([...m.keys()]).to.deep.equal(["a", "b", "c", "d"]);
    expect(m.get("a")).to.equal("[]");
    expect(m.get("b")).to.equal('"\\u00e9{"');
    expect(m.get("c")).to.equal("12.5e3");
    expect(m.get("d")).to.equal("true");
    expect([...membresBruts("{}").keys()]).to.deep.equal([]);
    expect(() => membresBruts('{"a":1} x')).to.throw(/texte après la fin/);
    expect(() => membresBruts('{"a":1,}')).to.throw();
    expect(() => membresBruts('{"a":1 "b":2}')).to.throw(/« , » ou « } »/);
    expect(() => membresBruts('{"a":"ouvert}')).to.throw(/non terminée/);
    expect(() => membresBruts("[1]")).to.throw(/objet JSON attendu/);
    expect(() => membresBruts(12)).to.throw(/chaîne attendue/);
    // La proposition Go : le corps extrait est exactement le texte JSON du corps.
    const prop = VECTEURS_GO.certificat.certJSON.prop;
    expect(membresBruts(prop).get("body")).to.equal(VECTEURS_GO.certificat.propBody);
  });

  it("base64Strict refuse l'alphabet URL, le bourrage absent et les encodages non canoniques", function () {
    expect(base64Strict("AQID").toString("hex")).to.equal("010203");
    expect(() => base64Strict("AQI")).to.throw(/base64 invalide/);
    expect(() => base64Strict("AQ-D")).to.throw(/base64 invalide/);
    expect(() => base64Strict("AQIE=")).to.throw(/base64/);
    expect(() => base64Strict("AQJ=")).to.throw(/non canonique/);
  });

  it("base64Go décode comme base64.StdEncoding : bits de bourrage non nuls et sauts de ligne tolérés (signalés), alphabet URL, bourrage absent ou mal placé refusés", function () {
    expect(base64Go("AQID")).to.deep.equal({ octets: Buffer.from("010203", "hex"), canonique: true });
    expect(base64Go("AQJ=")).to.deep.equal({ octets: Buffer.from("0102", "hex"), canonique: false });
    expect(base64Go("AQ\nID")).to.deep.equal({ octets: Buffer.from("010203", "hex"), canonique: false });
    expect(base64Go("AQ\r\nID\n")).to.deep.equal({ octets: Buffer.from("010203", "hex"), canonique: false });
    expect(base64Go("")).to.deep.equal({ octets: Buffer.alloc(0), canonique: true });
    expect(() => base64Go("AQI")).to.throw(/base64 invalide/);
    expect(() => base64Go("AQ-D")).to.throw(/base64 invalide/);
    expect(() => base64Go("AQIE=")).to.throw(/base64 invalide/);
    expect(() => base64Go("A===")).to.throw(/base64 invalide/);
    expect(() => base64Go("AQ==ID")).to.throw(/base64 invalide/);
    expect(() => base64Go("AQ ID")).to.throw(/base64 invalide/);
    expect(() => base64Go(12)).to.throw(/chaîne base64 attendue/);
  });

  it("plierNomGo plie comme encoding/json : casse ASCII, ſ → S, signe Kelvin → K, le reste intact", function () {
    expect(plierNomGo("domain")).to.equal(plierNomGo("Domain"));
    expect(plierNomGo("BODY")).to.equal(plierNomGo("body"));
    expect(plierNomGo("ſig")).to.equal(plierNomGo("sig"));
    expect(plierNomGo("bloc\u212aHash")).to.equal(plierNomGo("blockHash"));
    expect(plierNomGo("domaine")).to.not.equal(plierNomGo("domain"));
    expect(plierNomGo("ıd")).to.not.equal(plierNomGo("id")); // ı (U+0131) a une orbite à elle seule en Go
    expect(plierNomGo("İd")).to.not.equal(plierNomGo("id"));
    expect(plierNomGo("é")).to.equal("é");
  });

  it("trimSpaceGo reproduit strings.TrimSpace : U+0085 retiré, U+FEFF conservé, espaces Unicode usuels retirés", function () {
    expect(trimSpaceGo(" \t v1 \n")).to.equal("v1");
    expect(trimSpaceGo("v1\u0085")).to.equal("v1");
    expect(" v1\u0085".trim()).to.equal("v1\u0085");
    expect(trimSpaceGo("\ufeffv2\ufeff")).to.equal("\ufeffv2\ufeff");
    expect("\ufeffv2".trim()).to.equal("v2");
    expect(trimSpaceGo("\u3000\u00a0x\u2028")).to.equal("x");
    expect(trimSpaceGo("")).to.equal("");
  });

  it("membresBrutsGo plie les noms et laisse gagner la dernière occurrence dans l'ordre du texte", function () {
    const m = membresBrutsGo('{"domain":"a","Domain":"b","x":1,"DOMAIN":"c","ſig":"s"}');
    expect(m.get(plierNomGo("domain"))).to.deep.equal({ brut: '"c"', cle: "DOMAIN" });
    expect(m.get(plierNomGo("sig"))).to.deep.equal({ brut: '"s"', cle: "ſig" });
    expect(m.get(plierNomGo("x"))).to.deep.equal({ brut: "1", cle: "x" });
    expect([...m.keys()]).to.deep.equal(["DOMAIN", "X", "SIG"]);
    // membresBruts (clés exactes) n'a pas changé de contrat.
    expect([...membresBruts('{"domain":"a","Domain":"b"}').keys()]).to.deep.equal(["domain", "Domain"]);
  });

  it("u64 et digestEnveloppe : bornes des entiers et longueurs des hachages", function () {
    expect(u64(0)).to.equal(0n);
    expect(u64("18446744073709551615")).to.equal(2n ** 64n - 1n);
    expect(() => u64(2n ** 64n)).to.throw(/hors de/);
    expect(() => u64(-1)).to.throw(/hors de/);
    expect(() => u64(1.5)).to.throw(/entier sûr/);
    expect(() => u64("0x10")).to.throw(/entier non signé/);
    expect(() => u64("007")).to.throw(/entier non signé/);
    const base = { domain: DOMAINE_SIGNATURE, chainId: CHAINE, type: TYPE_PROPOSITION, validatorId: "v1", valsetHash: "0x" + "01".repeat(32), height: 1, round: 0, blockHash: HACHAGE_NUL, bodyHash: "0x" + "02".repeat(32) };
    expect(digestEnveloppe(base)).to.equal(digestEnveloppe({ ...base, blockHash: undefined }));
    expect(() => digestEnveloppe({ ...base, valsetHash: "0x0102" })).to.throw(/valsetHash : 32 octets attendus/);
    expect(() => digestEnveloppe({ ...base, bodyHash: "0x" + "02".repeat(31) })).to.throw(/bodyHash : 32 octets/);
    expect(() => digestEnveloppe({ ...base, height: -1 })).to.throw(/height/);
    // Chaque champ compte : changer un seul octet change le digest.
    expect(digestEnveloppe({ ...base, validatorId: "v2" })).to.not.equal(digestEnveloppe(base));
    expect(digestEnveloppe({ ...base, type: TYPE_PREVOTE })).to.not.equal(digestEnveloppe(base));
    expect(digestEnveloppe({ ...base, round: 1 })).to.not.equal(digestEnveloppe(base));
  });

  it("chargerJeuValidateurs : nettoyage, tri, doublons d'identifiant et de clé (même compressée), clé vide ou invalide, hexadécimal strict", function () {
    const k1 = new SigningKey(hex(randomBytes(32)));
    const k2 = new SigningKey(hex(randomBytes(32)));
    const jeu = chargerJeuValidateurs({ validators: [{ id: " vb ", pubKeyHex: ` ${k2.publicKey} ` }, { id: "va", pubKeyHex: k1.publicKey.slice(2).toUpperCase() }] });
    expect(jeu.validateurs.map((v) => v.id)).to.deep.equal(["va", "vb"]);
    expect(jeu.validateurs[0].cle).to.equal(k1.publicKey.toLowerCase());
    expect(jeu.taille).to.equal(2);
    expect(jeu.quorum).to.equal(2);
    expect(jeu.hachage).to.equal(hachageJeuValidateurs([{ id: "va", pubKeyHex: k1.publicKey }, { id: "vb", pubKeyHex: k2.publicKey }]));

    expect(() => chargerJeuValidateurs({ validators: [] })).to.throw(/vide/);
    expect(() => chargerJeuValidateurs({ validators: [{ id: "", pubKeyHex: k1.publicKey }] })).to.throw(/identifiant de validateur vide/);
    expect(() => chargerJeuValidateurs([{ id: "a", pubKeyHex: k1.publicKey }, { id: "a", pubKeyHex: k2.publicKey }])).to.throw(/en double : a/);
    expect(() => chargerJeuValidateurs([{ id: "a", pubKeyHex: k1.publicKey }, { id: "b", pubKeyHex: k1.compressedPublicKey }])).to.throw(/validateurs a et b : même clé publique/);
    expect(() => chargerJeuValidateurs([{ id: "a", pubKeyHex: "" }])).to.throw(/clé publique vide/);
    expect(() => chargerJeuValidateurs([{ id: "a", pubKeyHex: "0x0102" }])).to.throw(/inexploitable .*longueur 2/);
    expect(() => chargerJeuValidateurs([{ id: "a", pubKeyHex: "0xzz" }])).to.throw(/hexadécimal invalide/);
    expect(() => chargerJeuValidateurs([{ id: "a", pubKeyHex: "0x123" }])).to.throw(/hexadécimal invalide/);
    expect(() => chargerJeuValidateurs("oui")).to.throw();
    // Le tri est celui de Go (octets UTF-8), pas celui des unités UTF-16 de JavaScript.
    const tri = chargerJeuValidateurs([{ id: "！", pubKeyHex: k1.publicKey }, { id: "\u{1F600}", pubKeyHex: k2.publicKey }]);
    expect(tri.validateurs.map((v) => v.id)).to.deep.equal(["！", "\u{1F600}"]);
    expect(["！", "\u{1F600}"].sort()).to.deep.equal(["\u{1F600}", "！"]);
  });

  it("normaliserClePublique : 65 octets avec 0x04, 64 octets bruts, 33 octets compressés ; le reste refusé", function () {
    const k = new SigningKey(hex(randomBytes(32)));
    const pub = k.publicKey.toLowerCase();
    expect(normaliserClePublique(pub)).to.equal(pub);
    expect(normaliserClePublique("0x" + pub.slice(4))).to.equal(pub);
    expect(normaliserClePublique(k.compressedPublicKey)).to.equal(pub);
    expect(normaliserClePublique(octets(pub))).to.equal(pub);
    expect(() => normaliserClePublique("0x05" + pub.slice(4))).to.throw(/préfixe 0x04/);
    expect(() => normaliserClePublique("0x0102")).to.throw(/longueur 2/);
    expect(() => normaliserClePublique("0x02" + "00".repeat(32))).to.throw();
  });

  it("recupererClePublique et signerDigest : V dans {0, 1}, forme canonique exigée, longueur contrôlée", function () {
    const k = new SigningKey(hex(randomBytes(32)));
    const digest = hex(sha256(Buffer.from("un digest quelconque")));
    const sig = signerDigest(digest, k);
    expect(sig).to.have.length(65);
    expect(sig[64]).to.be.oneOf([0, 1]);
    expect(signatureCanonique(sig)).to.equal(true);
    expect(recupererClePublique(digest, sig)).to.equal(k.publicKey.toLowerCase());
    expect(recupererClePublique(octets(digest), hex(sig))).to.equal(k.publicKey.toLowerCase());
    expect(() => recupererClePublique(digest, sig.subarray(0, 64))).to.throw(/65 octets attendus, 64 reçus/);
    expect(() => recupererClePublique("0x01", sig)).to.throw(/digest : 32 octets/);
    expect(signatureCanonique("0x" + "00".repeat(65))).to.equal(false);
    expect(signatureCanonique("zz")).to.equal(false);
    // Clé privée donnée en hexadécimal, avec ou sans 0x.
    expect(signerDigest(digest, k.privateKey)).to.deep.equal(sig);
    expect(signerDigest(digest, k.privateKey.slice(2))).to.deep.equal(sig);
  });

  it("encoderProposition suit omitempty : hachages toujours présents, entiers nuls, chaînes vides et tableaux vides omis", function () {
    const minimal = encoderProposition({ height: 1, round: 0, proposer: "v1", blockHash: BLOC });
    expect(minimal).to.equal(`{"height":1,"round":0,"proposer":"v1","blockHash":"${BLOC}","parentHash":"${HACHAGE_NUL}","stateRoot":"${HACHAGE_NUL}","receiptsRoot":"${HACHAGE_NUL}","txRoot":"${HACHAGE_NUL}"}`);
    const complet = encoderProposition({ ...propositionPour("v1", BLOC), polkaRound: 2, polkaLines: ['{"a":"<b>"}'], sig: "0x0102" });
    expect(complet).to.match(/"polkaRound":2,"polkaLines":\["\{\\"a\\":\\"\\u003cb\\u003e\\"\}"\],"sig":"AQI="\}$/);
    expect(encoderVote({ height: 3, round: 2, voter: "v&", type: VOTE_PRECOMMIT })).to.equal(`{"Height":3,"Round":2,"Voter":"v\\u0026","Type":2,"BlockHash":"${HACHAGE_NUL}","Sig":null}`);
  });
});

describe("Certificat de commit — ligne de commande", function () {
  this.timeout(60_000);
  const script = path.join(PROJECT_ROOT, "scripts", "verify", "certificat-commit.mjs");
  let dossier;
  const jeu = jeuJetable(4);
  const certificat = certificatSynthetique(jeu);
  const fichiers = {};

  before(function () {
    dossier = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-certificat-"));
    const ecrire = (nom, contenu) => {
      const f = path.join(dossier, nom);
      fs.writeFileSync(f, typeof contenu === "string" ? contenu : JSON.stringify(contenu, null, 2));
      return f;
    };
    fichiers.validateurs = ecrire("validators.json", jeu.fichier);
    fichiers.autresValidateurs = ecrire("autres-validators.json", jeuJetable(4).fichier);
    fichiers.certificat = ecrire("certificat.json", certificat);
    fichiers.reponseRpc = ecrire("reponse-rpc.json", { jsonrpc: "2.0", id: 1, result: certificat });
    fichiers.altere = ecrire("certificat-altere.json", { ...certificat, cmts: certificat.cmts.slice(0, 2) });
    fichiers.pasJson = ecrire("pas-json.json", "{ceci n'est pas du JSON");
    fichiers.pasCertificat = ecrire("pas-certificat.json", { bonjour: "monde" });
    fichiers.tronque = ecrire("certificat-tronque.json", { h: 5 });
    fichiers.malForme = ecrire("certificat-mal-forme.json", { ...certificat, hash: HACHAGE_NUL });
    fichiers.certificatGo = ecrire("certificat-go.json", VECTEURS_GO.certificat.certJSON);
    fichiers.validateursGo = ecrire("validators-go.json", VECTEURS_GO.certificat.validators);
  });

  after(function () {
    if (dossier) fs.rmSync(dossier, { recursive: true, force: true });
  });

  /** Lance la ligne de commande sans bloquer la boucle d'événements (le nœud simulé tourne dans ce processus). */
  function lancer(...args) {
    return new Promise((resolve, reject) => {
      const enfant = spawn(process.execPath, [script, ...args], { cwd: PROJECT_ROOT, stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "";
      let stderr = "";
      enfant.stdout.setEncoding("utf8").on("data", (d) => (stdout += d));
      enfant.stderr.setEncoding("utf8").on("data", (d) => (stderr += d));
      const minuterie = setTimeout(() => enfant.kill("SIGKILL"), 30_000);
      enfant.on("error", reject);
      enfant.on("close", (status) => {
        clearTimeout(minuterie);
        resolve({ status, stdout, stderr });
      });
    });
  }

  it("code 0 sur un certificat valide, rapport lisible en français, sans avertissement quand --chaine est donné", async function () {
    const r = await lancer(fichiers.certificat, "--validateurs", fichiers.validateurs, "--chaine", CHAINE);
    expect(r.status, r.stderr).to.equal(0);
    expect(r.stdout).to.match(/Résultat\s+: VALIDE/);
    expect(r.stdout).to.match(/Quorum\s+: 3 sur 4/);
    expect(r.stdout).to.match(/\[ok\]\s+precommit 3/);
    expect(r.stdout).to.match(/\[ok\]\s+chaine/);
    expect(r.stdout).to.match(/Signataires\s+: v1, v2, v3 ; proposant v1/);
    expect(r.stdout).to.match(/jeu de validateurs FOURNI/);
    expect(r.stdout).to.not.match(/Avertissement/);
    expect(r.stderr).to.equal("");
  });

  it("sans --chaine : code 0 mais un avertissement nomme la chaîne déclarée par le certificat (rapport lisible et --json)", async function () {
    let r = await lancer(fichiers.certificat, "--validateurs", fichiers.validateurs);
    expect(r.status, r.stderr).to.equal(0);
    expect(r.stdout).to.match(new RegExp(`Avertissement : aucun identifiant de chaîne attendu \\(--chaine\\) : la preuve vaut pour la chaîne « ${CHAINE} »`));
    r = await lancer(fichiers.certificat, "--validateurs", fichiers.validateurs, "--json");
    expect(r.status).to.equal(0);
    const rapport = JSON.parse(r.stdout);
    expect(rapport.avertissements).to.have.length(1);
    expect(rapport.avertissements[0]).to.match(/--chaine/);
    r = await lancer(fichiers.certificat, "--validateurs", fichiers.validateurs, "--chaine", CHAINE, "--json");
    expect(JSON.parse(r.stdout).avertissements).to.deep.equal([]);
  });

  it("code 0 et rapport --json complet ; la réponse JSON-RPC entière est acceptée comme fichier", async function () {
    const r = await lancer(fichiers.reponseRpc, "--validateurs", fichiers.validateurs, "--json");
    expect(r.status, r.stderr).to.equal(0);
    const rapport = JSON.parse(r.stdout);
    expect(rapport.valide).to.equal(true);
    expect(rapport.signataires).to.deep.equal(["v1", "v2", "v3"]);
    expect(rapport.quorum).to.equal(3);
    expect(rapport.controles.every((c) => c.ok)).to.equal(true);
    expect(rapport.source.fichier).to.equal(fichiers.reponseRpc);
    expect(rapport.enLigne).to.equal(null);
    expect(rapport.fichierValidateurs).to.equal(fichiers.validateurs);
  });

  it("le certificat produit par Go passe la ligne de commande", async function () {
    const r = await lancer(fichiers.certificatGo, "--validateurs", fichiers.validateursGo);
    expect(r.status, r.stderr).to.equal(0);
    expect(r.stdout).to.match(/proposant v2/);
  });

  it("code 1 sur un certificat invalide (quorum manquant, mauvais jeu, chaîne attendue différente), avec le motif", async function () {
    let r = await lancer(fichiers.altere, "--validateurs", fichiers.validateurs);
    expect(r.status).to.equal(1);
    expect(r.stdout).to.match(/\[ÉCHEC\] quorum\s+2 signataire\(s\) distinct\(s\) valide\(s\) pour un quorum de 3 sur 4 : insuffisant/);
    expect(r.stdout).to.match(/Résultat\s+: INVALIDE/);

    r = await lancer(fichiers.certificat, "--validateurs", fichiers.autresValidateurs, "--json");
    expect(r.status).to.equal(1);
    const rapport = JSON.parse(r.stdout);
    expect(rapport.valide).to.equal(false);
    expect(rapport.controles.filter((c) => !c.ok).map((c) => c.nom)).to.deep.equal(["hachage_jeu"]);

    r = await lancer(fichiers.certificat, "--validateurs", fichiers.validateurs, "--chaine", "autre");
    expect(r.status).to.equal(1);
    expect(r.stdout).to.match(/\[ÉCHEC\] chaine/);
  });

  it("code 2 sur une entrée inutilisable : --validateurs absent, fichier absent, JSON invalide, JSON qui n'est pas un certificat, options incohérentes", async function () {
    const cas = [
      [[fichiers.certificat], /--validateurs .* obligatoire/],
      [[path.join(dossier, "absent.json"), "--validateurs", fichiers.validateurs], /fichier de certificat illisible/],
      [[fichiers.pasJson, "--validateurs", fichiers.validateurs], /n'est pas du JSON/],
      [[fichiers.pasCertificat, "--validateurs", fichiers.validateurs], /n'est pas un certificat de commit/],
      // Un JSON qui porte h, prop ou cmts mais n'est pas un certificat bien formé : code 2, pas un verdict « INVALIDE ».
      [[fichiers.tronque, "--validateurs", fichiers.validateurs], /n'est pas un certificat de commit bien formé : chainId absent ou vide/],
      [[fichiers.malForme, "--validateurs", fichiers.validateurs], /n'est pas un certificat de commit bien formé : hash \(bloc\) nul/],
      [[fichiers.certificat, "--validateurs", fichiers.pasCertificat], /fichier de validateurs .* inexploitable/],
      [[fichiers.certificat, "--validateurs", path.join(dossier, "absent.json")], /fichier de validateurs illisible/],
      [["--validateurs", fichiers.validateurs], /donner un fichier de certificat, ou --rpc/],
      [["--bloc", "12", "--validateurs", fichiers.validateurs], /--rpc <url> est requis/],
      [[fichiers.certificat, "--en-ligne", "--validateurs", fichiers.validateurs], /--rpc <url> est requis/],
      [[fichiers.certificat, "--bloc", "12", "--rpc", "http://127.0.0.1:1", "--validateurs", fichiers.validateurs], /soit un fichier de certificat, soit --bloc/],
      [[fichiers.certificat, "--validateurs", fichiers.validateurs, "--inconnue"], /option inconnue/],
      [[fichiers.certificat, "--validateurs"], /attend une valeur/],
      [["--rpc", "http://127.0.0.1:1", "--bloc", "abc", "--validateurs", fichiers.validateurs], /--bloc : hauteur/],
    ];
    for (const [args, motif] of cas) {
      const r = await lancer(...args);
      expect(r.status, `${args.join(" ")}\n${r.stdout}${r.stderr}`).to.equal(2);
      expect(r.stderr, args.join(" ")).to.match(/^Erreur : /);
      expect(r.stderr, args.join(" ")).to.match(motif);
    }
    // En --json, l'erreur est aussi rendue sur la sortie standard.
    let r = await lancer(fichiers.pasCertificat, "--validateurs", fichiers.validateurs, "--json");
    expect(r.status).to.equal(2);
    expect(JSON.parse(r.stdout)).to.deep.include({ valide: null });
    r = await lancer(fichiers.tronque, "--validateurs", fichiers.validateurs, "--json");
    expect(r.status).to.equal(2);
    expect(JSON.parse(r.stdout).valide).to.equal(null);
    expect(r.stdout).to.not.match(/INVALIDE/);
  });

  it("code 2 quand le nœud est injoignable", async function () {
    const r = await lancer("--rpc", "http://127.0.0.1:1", "--bloc", "8328", "--validateurs", fichiers.validateurs);
    expect(r.status).to.equal(2);
    expect(r.stderr).to.match(/nœud injoignable/);
  });

  describe("avec un nœud JSON-RPC simulé", function () {
    let serveur;
    let url;
    let comportement;
    const requetes = [];

    before(async function () {
      serveur = http.createServer((req, res) => {
        let corps = "";
        req.on("data", (d) => (corps += d));
        req.on("end", () => {
          const demande = JSON.parse(corps);
          requetes.push(demande);
          const reponse = { jsonrpc: "2.0", id: demande.id };
          const r = comportement(demande.method, demande.params);
          if (r && r.erreur) reponse.error = r.erreur;
          else reponse.result = r === undefined ? null : r;
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify(reponse));
        });
      });
      await new Promise((resolve) => serveur.listen(0, "127.0.0.1", resolve));
      url = `http://127.0.0.1:${serveur.address().port}`;
    });

    after(function () {
      serveur?.close();
    });

    /** Nœud qui sert le certificat et un bloc canonique de hachage `hashCanonique`. */
    const noeud = (hashCanonique, { methodeAbsente = false } = {}) => (methode, params) => {
      if (methode === "noor_getCommitCertificate") {
        if (methodeAbsente) return { erreur: { code: -32601, message: "method not found" } };
        if (params[0] === "0x" + (8328).toString(16) || params[0] === BLOC) return certificat;
        return null;
      }
      if (methode === "eth_getBlockByNumber") return params[0] === "0x" + (8328).toString(16) ? { number: params[0], hash: hashCanonique } : null;
      return { erreur: { code: -32601, message: "method not found" } };
    };

    it("--rpc --bloc <hauteur> --en-ligne : certificat obtenu, bloc canonique comparé, certificat enregistré, code 0", async function () {
      comportement = noeud(BLOC);
      requetes.length = 0;
      const enregistre = path.join(dossier, "sortie", "certificat-8328.json");
      const r = await lancer("--rpc", url, "--bloc", "8328", "--validateurs", fichiers.validateurs, "--en-ligne", "--enregistrer", enregistre, "--json");
      expect(r.status, r.stderr).to.equal(0);
      const rapport = JSON.parse(r.stdout);
      expect(rapport.valide).to.equal(true);
      expect(rapport.controles.map((c) => c.nom)).to.include.members(["hauteur", "bloc_canonique"]);
      expect(rapport.enLigne).to.deep.include({ rpc: url, hauteur: "8328", blockHashCanonique: BLOC });
      expect(rapport.source).to.deep.include({ rpc: url, bloc: "8328", enregistre });
      expect(JSON.parse(fs.readFileSync(enregistre, "utf8"))).to.deep.equal(certificat);
      expect(requetes.map((q) => q.method)).to.deep.equal(["noor_getCommitCertificate", "eth_getBlockByNumber"]);
      expect(requetes[0].params).to.deep.equal(["0x2088"]);
      expect(requetes[1].params).to.deep.equal(["0x2088", false]);
    });

    it("--bloc <hash> : le certificat doit être celui du bloc demandé", async function () {
      comportement = noeud(BLOC);
      let r = await lancer("--rpc", url, "--bloc", BLOC, "--validateurs", fichiers.validateurs, "--json");
      expect(r.status, r.stderr).to.equal(0);
      expect(JSON.parse(r.stdout).controles.find((c) => c.nom === "bloc_demande").ok).to.equal(true);

      comportement = (methode) => (methode === "noor_getCommitCertificate" ? certificat : null);
      r = await lancer("--rpc", url, "--bloc", "0x" + "4".repeat(64), "--validateurs", fichiers.validateurs);
      expect(r.status).to.equal(1);
      expect(r.stdout).to.match(/\[ÉCHEC\] bloc_demande/);
    });

    it("--en-ligne avec un bloc canonique différent : code 1 sur le contrôle bloc_canonique", async function () {
      comportement = noeud("0x" + "5".repeat(64));
      const r = await lancer("--rpc", url, "--bloc", "8328", "--validateurs", fichiers.validateurs, "--en-ligne");
      expect(r.status).to.equal(1);
      expect(r.stdout).to.match(/\[ÉCHEC\] bloc_canonique\s+bloc du certificat 0x7d5a.* ≠ bloc canonique 0x5{64}/);
      expect(r.stdout).to.match(/Résultat\s+: INVALIDE/);
    });

    it("fichier + --en-ligne --rpc : le fichier est vérifié, le bloc canonique interrogé à la hauteur du certificat", async function () {
      comportement = noeud(BLOC);
      requetes.length = 0;
      const r = await lancer(fichiers.certificat, "--validateurs", fichiers.validateurs, "--en-ligne", "--rpc", url);
      expect(r.status, r.stderr).to.equal(0);
      expect(r.stdout).to.match(/\[ok\]\s+bloc_canonique/);
      expect(requetes.map((q) => q.method)).to.deep.equal(["eth_getBlockByNumber"]);
    });

    it("code 2 : méthode inconnue du nœud, bloc sans certificat, bloc canonique absent", async function () {
      comportement = noeud(BLOC, { methodeAbsente: true });
      let r = await lancer("--rpc", url, "--bloc", "8328", "--validateurs", fichiers.validateurs);
      expect(r.status).to.equal(2);
      expect(r.stderr).to.match(/method not found .*binaire antérieur à noor_getCommitCertificate/);

      comportement = noeud(BLOC);
      r = await lancer("--rpc", url, "--bloc", "99", "--validateurs", fichiers.validateurs);
      expect(r.status).to.equal(2);
      expect(r.stderr).to.match(/aucun certificat pour le bloc 99/);

      comportement = (methode) => (methode === "noor_getCommitCertificate" ? certificat : null);
      r = await lancer("--rpc", url, "--bloc", "8328", "--validateurs", fichiers.validateurs, "--en-ligne");
      expect(r.status).to.equal(2);
      expect(r.stderr).to.match(/n'a pas de bloc à la hauteur 8328/);
    });
  });
});

describe("Certificat de commit — fixture du réseau de développement (test/fixtures/certificat-commit)", function () {
  this.timeout(60_000);
  const dossier = path.join(PROJECT_ROOT, "test", "fixtures", "certificat-commit");
  const lire = (nom) => JSON.parse(fs.readFileSync(path.join(dossier, nom), "utf8"));
  const certificat = lire("certificat-8316.json");
  const bloc = lire("bloc-8316.json");
  const validateurs = lire("validators.json");

  it("la réponse réelle de noor_getCommitCertificate (hauteur 8316) est valide contre validators.json : v1, v3, v4 ont signé, proposant v1", function () {
    const res = verifierCertificat(certificat, validateurs, { chainIdAttendu: CHAINE, hauteurAttendue: 8316 });
    expect(echecs(res)).to.deep.equal([]);
    expect(res.valide).to.equal(true);
    expect(res.hauteur).to.equal(8316);
    expect(res.ronde).to.equal(0);
    expect(res.signataires).to.deep.equal(["v1", "v3", "v4"]);
    expect(res.proposant).to.equal("v1");
    expect(res.quorum).to.equal(3);
    expect(res.tailleJeu).to.equal(4);
    expect(res.blockHash).to.equal(certificat.result.blockHash);
    // Le nœud sert son jeu courant avec son hachage et dit s'il est celui du certificat ; ici oui.
    expect(certificat.result.validatorSetHash).to.equal(certificat.result.valsetHash);
    expect(certificat.result.validatorSetMatchesCertificate).to.equal(true);
    expect(hachageJeuValidateurs(certificat.result.validatorSet)).to.equal(certificat.result.validatorSetHash);
    // Seules les lignes brutes comptent : le résultat RPC et le DecidedCert reconstruit donnent le même verdict.
    const brut = { chainId: certificat.result.chainId, valsetHash: certificat.result.valsetHash, h: 8316, r: 0, hash: certificat.result.blockHash, prop: certificat.result.proposal.line, cmts: certificat.result.precommits.map((p) => p.line) };
    expect(verifierCertificat(brut, validateurs)).to.deep.equal(verifierCertificat(certificat.result, validateurs));
  });

  it("le bloc du certificat est le bloc canonique 8316 rendu par eth_getBlockByNumber (bloc-8316.json), et le jeu est celui du réseau", function () {
    expect(bloc.result.number).to.equal("0x207c");
    expect(BigInt(bloc.result.number)).to.equal(8316n);
    expect(bloc.result.hash).to.equal(certificat.result.blockHash);
    const res = verifierCertificat(certificat, validateurs, { blockHashCanonique: bloc.result.hash });
    expect(res.valide).to.equal(true);
    expect(controle(res, "bloc_canonique").ok).to.equal(true);
    // Le hachage du jeu du fixture est celui que le code Go calcule pour validators.json du réseau de développement.
    expect(hachageJeuValidateurs(validateurs)).to.equal(VECTEURS_GO.valsetHash.fichier);
    expect(certificat.result.valsetHash).to.equal(VECTEURS_GO.valsetHash.fichier);
    // Les champs décodés fournis par le nœud coïncident avec ce que l'on recalcule des lignes (sans leur faire confiance).
    certificat.result.precommits.forEach((p) => {
      const env = analyserEnveloppe(p.line);
      expect(env.validatorId).to.equal(p.validatorId);
      expect(hex(env.bodyHash)).to.equal(p.bodyHash);
      expect(hex(sha256(Buffer.from(env.corpsBrut, "utf8")))).to.equal(p.bodyHash);
      expect(hex(env.sig)).to.equal(p.sig);
    });
  });

  it("le fixture est refusé contre un autre jeu, et sans l'un de ses precommits", function () {
    let res = verifierCertificat(certificat, VECTEURS_GO.certificat.validators);
    expect(echecs(res)).to.deep.equal(["hachage_jeu"]);
    const ampute = { ...certificat.result, precommits: certificat.result.precommits.slice(1) };
    res = verifierCertificat(ampute, validateurs);
    expect(echecs(res)).to.deep.equal(["quorum"]);
    expect(res.signataires).to.deep.equal(["v1", "v3"]);
  });

  it("la ligne de commande accepte le fixture (code 0) et le refuse contre le jeu des vecteurs Go (code 1)", async function () {
    const script = path.join(PROJECT_ROOT, "scripts", "verify", "certificat-commit.mjs");
    const lancer = (...args) =>
      new Promise((resolve, reject) => {
        const enfant = spawn(process.execPath, [script, ...args], { cwd: PROJECT_ROOT, stdio: ["ignore", "pipe", "pipe"] });
        let stdout = "";
        let stderr = "";
        enfant.stdout.setEncoding("utf8").on("data", (d) => (stdout += d));
        enfant.stderr.setEncoding("utf8").on("data", (d) => (stderr += d));
        enfant.on("error", reject);
        enfant.on("close", (status) => resolve({ status, stdout, stderr }));
      });
    let r = await lancer(path.join(dossier, "certificat-8316.json"), "--validateurs", path.join(dossier, "validators.json"), "--chaine", CHAINE, "--json");
    expect(r.status, r.stderr).to.equal(0);
    const rapport = JSON.parse(r.stdout);
    expect(rapport.valide).to.equal(true);
    expect(rapport.signataires).to.deep.equal(["v1", "v3", "v4"]);
    expect(rapport.hauteur).to.equal(8316);

    const autre = path.join(os.tmpdir(), `validators-go-${process.pid}.json`);
    fs.writeFileSync(autre, JSON.stringify(VECTEURS_GO.certificat.validators));
    try {
      r = await lancer(path.join(dossier, "certificat-8316.json"), "--validateurs", autre);
      expect(r.status).to.equal(1);
      expect(r.stdout).to.match(/\[ÉCHEC\] hachage_jeu/);
    } finally {
      fs.rmSync(autre, { force: true });
    }
  });
});
