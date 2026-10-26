# Changelog

All notable changes to noortrace are recorded here. The format follows
Keep a Changelog; versions follow semantic versioning once the first release
is tagged.

## Unreleased

- CT-3, approvals, revision 0.3: a named person, authenticated by the
  client's identity system, approves from their session while the signature
  is still made by their own key in their own wallet, never by a server; the
  signed object of a vote is unchanged (`A`, `D_A`, EIP-191 version `0x45`).
  The revision specifies the canonical session identity and
  re-authentication; the organisation's approver directory, one active
  address per person; enrolment of an address by proof of possession (a
  readable `personal_sign` text, distinct from any vote, validated by another
  administrator), rotation and revocation; four signing paths (browser wallet
  through EIP-1193 and EIP-6963, hardware wallet through it, WalletConnect v2
  when the organisation opts in, encrypted key file) with each failure and its
  answer; the console's local check, which recomputes `A`, `JCS(A)` and `D_A`
  and refuses to have anything else signed; and the console channel to the
  service, which refuses a vote from an address other than the session's
  (new refusal reason `session_non_autorisee`). New schemas
  `console-approbation-v0`, `annuaire-approbateurs-v0` and
  `console-service-v0`; `ticket-v0` extended compatibly.
- CT-3 reference console: a dependency-free library
  (`scripts/lib/console.mjs`), a static page (`console/`) under a strict
  content security policy with subresource integrity, and an end-to-end test
  in Chromium through Playwright 1.56.1, run in continuous integration by a
  new `console-chromium` job that fails instead of skipping. A deterministic
  differential test (`test/console-primitives.test.js`) compares the
  library's hashing, key derivation, encryption and secp256k1 primitives with
  node:crypto, @noble/hashes, @noble/curves and ethers: 2,673 comparisons, no
  difference. The library's secp256k1 signing is not constant-time; CT-3
  §14.9 states the risk and recommends a hardware wallet. New vector families
  `annuaire/` and `console/` and a reading test `acceptation-console/`;
  existing CT-3 vectors unchanged except `INDEX.md`. The CT-3 Go verifier
  recomputes 7,149 values, all matching, 84 outside its scope. Every
  signature and key file of the vectors is confronted with ethers 6.17.0 and
  eth-account 0.14.0, without discrepancy.
- CT-4, the registry, revision 0.4, textual only: the registry digests
  (`periodDigest`, `registerDigest`, `revokeDigest`) are signed outside the
  CT-3 console, by the `signer` command of the CT-4 reference tool or any tool
  that meets CT-4 EX-7.10; version 0 ships no tool that signs them in an
  approver's wallet. No CT-4 vector changes.
- CT-5, anchoring: annex EX-A.7 now names the two continuous integration jobs
  that reach the network beyond installing dependencies (`confrontation` and
  `console-chromium`). Text only.
- CT-2, the recorder, revision 0.5: Gemini `generateContent` and
  `streamGenerateContent` move to version 0 at the model gateway (routes,
  `x-goog-api-key`, `alt=sse` streams, consolidation, extraction, errors in the
  provider's format), and the SDK accepts the `gemini` format; Python and
  TypeScript SDKs with adapters for LangChain and LangGraph, CrewAI,
  LlamaIndex, the OpenAI Agents SDK and LiteLLM, with a rule against double
  capture; ingestion of OpenTelemetry GenAI traces over OTLP/HTTP (JSON and
  protobuf), recorded as declarative; a legal hold on the WORM copies, placed
  and released outside the daemon, released by two people, the writer never
  allowed to delete or release; a per-agent cost formula whose unit prices are
  parameters; integration files for Gemini, CrewAI, LlamaIndex and LiteLLM.
  Changes of behaviour in production: WORM copies in `governance` mode and of
  type `gcs-object-retention`, accepted in revision 0.4, are refused, and so is
  the new `legal_hold_on_write` member.
  Schemas `worm-v0` and `cout-agent-v0`; `configuration-enregistreur-v0`
  extended compatibly.
- CT-2 reference code (`scripts/lib/capture.mjs`, `otel.mjs`, `worm.mjs`,
  `cout-agent.mjs`) and new vector families (`pieces-modele/gemini-*`, `otel/`,
  `worm/`, `cout-agent/`); existing CT-2 vectors unchanged except `INDEX.md`.
  The CT-2 Go verifier recomputes 6,036 values, 6,030 matching, none
  discordant, 6 outside its scope. Gemini payloads are confronted with the
  official google-genai 2.33.0 library and OTLP requests with
  opentelemetry-proto 1.45.1, in continuous integration as well.

- CT-5, anchoring, version 0.2: signed checkpoints every 60 seconds aligned on
  the period start, each one that commits to a new event anchored in the
  registry (at most 62 anchors per hour and journal, the manifest included),
  and at most one every 300 seconds countersigned by an RFC 3161 authority,
  which bounds the rewrite window for the date to 300 seconds plus the token
  delay; the hourly qualified closure is unchanged. The specification covers
  the RFC 3161 and OpenTimestamps clients with retries, fallbacks and response
  checks, an optional non-qualified internal server, the scheduler with its
  durable queue and restart rules, the registry anchors of checkpoints,
  monitoring with the four components of each token delay, the series
  completeness check against the registry (the next period's series served
  too, order checked within each series), providers and their measurable
  qualified status, and a cost formula whose unit price is a parameter.
  Schemas `ancrage-v0` and `planificateur-ancrage-v0`.
- CT-5 reference scheduler (`scripts/lib/ancrage.mjs`) with an injected clock,
  deterministic vectors (`spec/vecteurs/ct-5`, `npm run vecteurs:ct5`: 21
  normative traces, requests, responses, proofs, cost and completeness cases),
  and a Go verifier written from the specification alone: 3,255 values
  recomputed, 3,227 matching, none discordant, 28 third-party tool verdicts
  outside its scope. Requests and responses are confronted with OpenSSL,
  proofs with the official OpenTimestamps library, and consistency proofs with
  transparency-dev/merkle v0.0.2.
- CT-1, formats, revision 0.3: the checkpoint (`point-de-controle-v0`), its
  hash and signature prefixes, the RFC 9162 consistency proof, the rewrite
  window, and an optional thirteenth evidence folder part
  `points-de-controle.json` with checks K-1 to K-6; ten new CT-1 folders. The
  CT-1 Go verifier recomputes 2,885 values, 2,883 matching, none discordant,
  2 outside its scope; its copy inside the CT-2 verifier is updated to match.
- CT-2, the recorder, revision 0.4: production of checkpoints, the
  `checkpoint_interval_s` key and the `anchoring.ancrage` reference; the CT-2
  vectors are unchanged.
- CT-4, the registry, revision 0.3: the checkpoint `docType` label only.
- CT-6, the verifier, revision 0.2: the checkpoint part is checked (K-7 to K-9
  for its anchors, R-11 for a registry inclusion), the statement gains the
  checkpoint fragment with the bound it proves, and the JSON report gains
  `facts.checkpoint`; eighteen new CT-6 folders.

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
