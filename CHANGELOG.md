# Changelog

All notable changes to noortrace are recorded here. The format follows
Keep a Changelog; versions follow semantic versioning once the first release
is tagged.

## Unreleased

- CT-6, the verifier, version 0.1: trust model (the evidence folder is
  declarative, only the reviewer's trust anchors are trusted), the eight checks
  with numbered verifications (T- for RFC 3161, O- for OpenTimestamps, R- for the
  registry, N- for anchors, V- for verdicts), verdicts and the one-sentence
  statement that asserts only what was proven, what each verdict proves and does
  not prove, human and JSON output, reproducible network-free Go build of the
  future binary, requirements on CT-4 and CT-5. The three anchors now bind the
  period manifest hash (`periodHash`), which commits to the Merkle root.
- Schemas: `rapport-verification-v0`, `ancres-confiance-v0`,
  `entetes-bitcoin-v0`, `registre-v0`, `validateurs-v0`.
- Verifier (`scripts/verify/dossier.mjs`): checks 4, 5 and 8 implemented in
  JavaScript (`scripts/lib/horodatage.mjs`, `ots.mjs`, `registre.mjs`,
  `verificateur.mjs`); new options `--ancres`, `--entetes-bitcoin`, `--pieces`,
  `--second-manifeste`, `--exiger`, `--langue`, `--detail`; new exit code 3
  (required check not executed).
- Breaking: the `--json` output of `scripts/verify/dossier.mjs` now follows the
  `rapport-verification-v0` schema (`valide` becomes `verdict`,
  `controlesEnEchec` becomes `failed_checks`, `nonExecutesBloquants` becomes
  `blocking_unexecuted`, `controles` becomes `checks`, `evenement` becomes
  `event`). Exit codes and failed checks of the 40 CT-1 folders are unchanged.
- CT-6 test vectors: RFC 3161 tokens from a test authority, OpenTimestamps proofs
  on a synthetic Bitcoin header chain, registry data captured once on the
  development network, 50 complete evidence folders, 12 trust-anchor files;
  recomputed without discrepancy by OpenSSL 3.0.13, python-opentimestamps 0.4.5
  and go-ethereum v1.17.0 with the noorcore block hash.
- Continuous integration: deterministic regeneration of the CT-6 vectors and a
  third-party confrontation job (OpenSSL, python-opentimestamps).
- Text only: CT-1 §14 (decision 5) and `ARCHITECTURE.md` (open decision 5) no
  longer tie a revision of the export format to reviewer interviews; a revision
  from the gate 1 review or from the prototype produces version 1.
- CT-2, the recorder, version 0.2: MCP proxy (tool aggregation, `tools/call`
  relayed byte by byte over stdio and Streamable HTTP, no token passthrough),
  model API gateway as the nominal capture mode with ICAP and passive mirroring
  as alternatives (Anthropic Messages, OpenAI Chat Completions and Responses,
  streamed and not), SDK limits, full RFC 8785 canonical form for payloads,
  redaction before hashing with a versioned policy and checksum-backed detectors
  (`pii-v1` published), recorder key custody classes A to D, append-only NDJSON
  storage with an intent log, single-writer lease with fencing, a failure matrix,
  configuration and redaction-policy JSON schemas. Closes open decisions 2 and 3
  of the architecture.
- CT-2 test vectors, JavaScript implementation of the computable parts and a
  second clean-room Go verifier: every value of the vectors is recomputed by both
  implementations with no discrepancy.
- CT-1: a note in §5.5 on payload serialisation (CT-2 §8); the link to the
  internal project plan is replaced by a plain mention.
- CT-1: event model v0, canonical form (RFC 8785 with integer-only numbers),
  SHA-256 hashing and Ed25519 signing with domain prefixes, hash-chained
  journal, RFC 6962 Merkle periods with the zero root for empty periods,
  period manifests, evidence folder v0, offline verifier (checks 1, 2, 3, 6, 7),
  deterministic test vectors, JavaScript reference and clean-room Go verifier.
- Registry contracts: PeriodRegistry (derived from noorchain-core's
  PoSSRegistry, with continuity per journal and per-organisation uniqueness),
  RecorderRegistry, ThresholdSignatures (its signature loop follows
  PoSSRegistry's); AttestationRegistry, CuratorSet and CuratorSetRegistry reused
  unchanged from noorchain-core.
- Offline verifier of BFT commit certificates (`noor_getCommitCertificate`),
  byte-for-byte parity with the node's signing scheme.
- Dedicated development instance of the registry node, container image, study of
  what a follower node provides.
- Apache-2.0 licence, English README, contribution and security policies.
- Continuous integration: full test suite, deterministic regeneration of the CT-1
  and CT-2 vectors, and both clean-room Go verifiers run against them on every
  push.
