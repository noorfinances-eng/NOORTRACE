# Changelog

All notable changes to noortrace are recorded here. The format follows
Keep a Changelog; versions follow semantic versioning once the first release
is tagged.

## Unreleased

- CT-4, the registry, version 0.2: the dedicated noorcore instance (genesis
  rules checked at start-up, identifiers, validators and quorum, pinned versions,
  instance manifest), fee-less gas and the admission guard that production
  validators must put in front of their RPC (per-client authentication and
  quota, balance and nonce checks) against mempool poisoning by balance-less
  senders, the contracts and their conventions (`docType`, signed digests and
  signature ordering, anchor fingerprints, ABI and transaction encoding),
  client onboarding step by step, day-to-day operations, the commit
  certificate and its capture (CP-1 to CP-6) for `registre.json`,
  `certificat-commit.json` and `validateurs.json`, container topologies, and
  the substitution rule (SU-1 to SU-7) that decides at gate 4 between partner
  validators and a signed database journal. Schemas `instance-registre-v0`,
  `inscription-client-v0` and `operations-registre-v0`.
- CT-4 reference tool (`scripts/registre/noortrace-registre.mjs`, `npm run
  registre`) and conventions library (`scripts/lib/conventions-registre.mjs`),
  deterministic vectors (`spec/vecteurs/ct-4`, `npm run vecteurs:ct4`), and a
  Go verifier written from the specification alone: 2,147 values recomputed,
  all matching, 158 outside its scope. Continuous integration regenerates the
  CT-4 vectors and runs that verifier. The acceptance criterion was met three
  times: a reader with only the specification onboarded a client, anchored a
  root and closed a period on the development network.
- Text only: CT-1 §8 and §10.4, CT-2 EX-11.13 point control 8 to CT-6 instead
  of CT-4; `scripts/lib/noortrace.mjs` gains an optional `setAdmin` for
  `bootstrapOrg` (default unchanged) and `scripts/lib/journal.mjs` an
  inventory of schema keywords outside its validator's subset.
- CT-2, the recorder, version 0.3: aligned with CT-3. The approval service
  interface (`charger`, `evaluer`, `ouvrir`, `decisions`, `acquitter`,
  `consommer`, `expiration`), the refusal to seal a held call for a ticket
  already decided, relay checks RL-1 to RL-4 with a keyed relay MAC over the
  plain arguments, SG-7 (no self-approval), validation of
  `policy.approval.rules` against `politique-approbation-v0` before sealing,
  and the approver set kept and exported in `approbations.json`.
- Breaking: following the MCP 2026-07-28 error code policy, the recorder's
  JSON-RPC error codes move from `-32010`…`-32017` to `-31010`…`-31017`, and
  `-32015` is withdrawn: a pending, refused or expired approval is now a tool
  error result (`isError: true`) carrying the ticket and its state in its text
  and in `_meta["noortrace/approval"]`.
- CT-2 redaction patterns: a structural check refuses the patterns with
  exponential backtracking, and `limits.redaction_budget_ms` now bounds every
  pattern evaluation; a write or approval-bound call whose arguments exceed it
  is refused before relay.
- CT-2 vectors updated accordingly (`pieces-mcp`, `journal-demo` rendered
  signal, `redaction/motifs.json`); the CT-2 Go verifier recomputes 2,512
  values, 2,506 matching, none discordant, 6 outside its scope.
- CT-3, approvals, version 0.2: a JSON rule language (`politique-approbation-v0`)
  selecting a tool and typed predicates on its arguments by JSON Pointer, with
  exact decimal comparison and no floating point; three levels, automatic,
  time-boxed window and per-call review, projected on the CT-1 values without
  any new one; a contest window before an approval is delivered; the ticket
  lifecycle (`ticket-v0`), escalation, expiry and recognised re-issue; the
  approver set pinned by the policy, read from the client's CuratorSet when the
  ticket opens and confirmed again before the decision, with a threshold that
  cannot drop while waiting; what the approver sees before signing; separation
  of duties; the approval service interface and the console requirements.
  Closes open decision 4: the proxy answers at once with a tool error result
  (`isError`) carrying the ticket and its state (`erreur` mode) by default.
- CT-3 reference implementation (`scripts/lib/approbation.mjs`), deterministic
  vectors (`spec/vecteurs/ct-3`, `npm run vecteurs:ct3`) with ten acceptance
  cases, and a Go verifier written from the specification alone: 4,718 values
  recomputed, all matching, 83 outside its scope. Continuous integration regenerates the CT-3 vectors
  and runs that verifier.
- CT-6 vector generator: it now deletes only the entries it writes and refuses
  an output directory that holds anything else, or `--sortie` without a value.
- Text only: `ARCHITECTURE.md` 0.5 (approval levels, pinned approver set,
  open decision 4 closed; the AI Act asks at least six months for logs,
  art. 19(1) and 26(6), its art. 18 ten years being for provider
  documentation); CT-1 §8 points `policy_sha256` to CT-2 EX-8.11.
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
