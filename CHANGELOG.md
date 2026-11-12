# Changelog

All notable changes to noortrace are recorded here. The format follows
Keep a Changelog; versions follow semantic versioning once the first release
is tagged.

## Unreleased

- Build step 7, packages, observability and runbooks. Six container images
  `noortrace/*` (recorder, file-attribute companion, approval service,
  console, stdio bridge, verifier) are built from `conteneurs/`: no shell, no
  `/usr/bin/env`, Node.js 22.23.4 and only the programs each needs (`flock`,
  `chattr`, `lsattr`) on a minimal base pinned by digest, entry point the
  program itself; two builds without cache, from two copies of the sources,
  give the same digests (`scripts/deploiement/construire-images.mjs`).
  Nothing is published: no image, tag, release or package leaves the build
  machine. The recorder gains `noortrace-ctl sonde`, `etat` and
  `close-period --now` (which ends the journal, development only); its file
  lease no longer needs a shell; a chain key of class B or C is held by a key
  management service, and the emergency rotation of the chain key alone is
  relayed to the registry from threshold-signed requests. The approval
  service's socket directory shared by two accounts (`3770`) is accepted; the
  attribute companion fails loudly when it cannot read; `d_registre` is
  observed once per anchor. Reference observability
  (`deploiement/observabilite/`): 88 alerting rules with a firing and a
  silent case each, checked by promtool 3.5.0 in CI, a log extractor, a rule
  generator and a probe. Installation and operations tooling: host
  preparation for the reference system, systemd templates for the scheduled
  tasks, backup and restore with the deterministic archive and its minutes,
  operations-log archiving, runbook copies checked against CT-8. A release is
  prepared without publishing (`scripts/publication/`, `version.yml`): two
  reproducible builds of the verifier for amd64 and arm64, `SHA256SUMS`,
  release note and unsigned provenance; signing waits for a decision on the
  key. The full installation, steps IC-1 to IC-18 of CT-8, ran on a bench
  without public network access in 58 minutes, the first evidence folder
  accepted by both verifiers; the bench is not the reference system.
  The quick installation now obtains a real RFC 3161 closing token: by the
  owner's decision, its placeholder provider is replaced by the internal,
  non-qualified timestamping server of `paquets/ancrage`, accepted as the
  principal provider outside production only (production still refuses it,
  with its reason). A seventh image, `noortrace/tsa-interne`, runs it in the
  recorder's network namespace (`horodatage` service, initialised by the
  `horodatage-init` tool, no secret), and `configurer-rapide.mjs` copies its
  CA certificate into the anchoring document. The quick installation ran from
  step IR-1 to IR-8 with Docker and no public network: check 4 passed with
  the internal server's token in both verifiers, check 5 was not run (no
  OpenTimestamps proof without network).
  CT-2 0.10, CT-3 0.7, CT-5 0.9, CT-6 0.8, CT-8 0.7, CT-9 0.9; recorded
  changes MC-42 onwards. CI: actions pinned by commit, Node.js
  22.23.4, a promtool step and an `images` job (double build and image
  tests, no publication).
- npm advisories in the development dependencies. `mocha` moves to 12.0.3 and
  `@nomicfoundation/hardhat-toolbox-mocha-ethers` to 4.0.0, which brings
  `@nomicfoundation/hardhat-mocha` 4.0.1; `overrides` scoped to mocha pin
  `glob` 14.0.3 and `minimatch` 11.0.3, outside the ranges of
  GHSA-3g3m-2fjr-6pw4 and GHSA-g3hv-75wg-m249; two more overrides pin the
  transitive `brace-expansion` 5.0.12 and `@isaacs/nonrecursive-glob-match`
  1.0.3, so that no package added by this change was published less than two
  weeks before it. This clears the five mocha
  entries of `npm audit` (`serialize-javascript`, `diff`, `glob`, `minimatch`
  and `mocha` itself). Every development dependency is now pinned to an exact
  version; Hardhat stays at 3.20.0. The 13 remaining high-severity entries all
  come from one zod 3 advisory (GHSA-mrhx-c7xc-m3w5) that no Hardhat 3 release
  lets us fix yet; `SECURITY.md` records why it is kept and when to revisit
  it. The CI job `tests` now runs `npm audit --omit=dev --audit-level=low` and
  fails on any advisory that reaches a production dependency.
- Build step 6, the operating console and what surrounds it. `paquets/console`:
  the approval console of CT-3 §13, in three parts — a library run unchanged
  under Node and in the browser, shared with the approval service; a console
  server without framework (OIDC, local accounts outside production, sessions
  in memory, authenticated relay to the approval service, health and probe);
  static pages loaded with their integrity, where an approver enrols an address
  by proof of possession and signs a decision in their own wallet. The approval
  service (`paquets/approbation`) gains the console channel, the persisted
  approver directory, signed webhook notifications and its configuration
  document. Client onboarding (`paquets/inscription`): an operator web
  interface that holds no key and a separate agent that holds them, driving the
  CT-4 steps with the same outputs as the reference tool and producing the
  client package, which the client checks on receipt. The recorder exports an
  evidence folder on request (`noortrace-ctl dossier exporter`), atomically,
  into a dedicated exports directory. The verification page
  (`paquets/verification-web`) runs the Go verifier compiled to WebAssembly in
  a browser worker and shows the same report as the binary, byte for byte.
  The step's criterion is demonstrated end to end (CT-9 TE-13): an approver
  signs a decision from the console, and the exported folder passes both
  verifiers with `--exiger 7`, timestamp and registry controls included. A CI
  job runs the console, the page in Chromium, Firefox and WebKit, and the
  criterion without the development network. Specification revisions CT-2 0.9,
  CT-3 0.6, CT-4 0.7, CT-6 0.7, CT-8 0.5 and CT-9 0.8, recorded as MC-27 to
  MC-39 in the design-freeze register.
- Build step 3, the development registry. `npm run e2e:registre`
  (`scripts/e2e/parcours-registre.mjs`) replays the CT-4 §7 walkthrough on the
  local noorcore network for a fictitious client: onboarding, key
  registration, root anchoring, period closure, capture of blocks, receipts,
  commit certificates and validator sets, export of the registry parts, and
  control 8 of CT-6 run by both the JavaScript reference and the Go verifier,
  which agree exactly. `test/registre-dev.test.js` runs it when a noorcore
  binary with `noor_getCommitCertificate` is present and is pending otherwise.
  The registry node image is rebuilt with that method, its two base images
  pinned by digest, and it rebuilds to the same digest. A block of 64 anchor
  transactions was filled and the capture of one transaction measured
  (CT-9 TM-31, report under `spec/vecteurs/ct-9/mesures/`). The CT-9 vector
  generator now keeps campaign reports under `mesures/`, as EX-11.11 requires.
  Recorded as MC-5 in the design-freeze register.
- Build step 2, the offline verifier binary `noortrace-verifier`, written in
  Go from the CT-6 text alone (`verificateur/`): the eight checks, including
  RFC 3161 timestamp tokens, OpenTimestamps proofs with their Bitcoin header
  chain, and registry blocks with their commit certificates; the trust-anchor
  file, the JSON and readable reports, the bilingual statement. Go 1.27.3,
  vendored dependencies (`golang.org/x/crypto`, decred `secp256k1`), no cgo.
  Every evidence folder of the CT-1 and CT-6 vectors is replayed against its
  expected result with no discrepancy; two builds in different directories
  and caches give the same bytes; the four no-network proofs of CT-6 EX-14.5
  pass. A CI job runs all three. CT-9: TV-55 is now runnable; recorded as
  MC-3 in the design-freeze register.
- Build step 1, the production core library `@noortrace/noyau`
  (`paquets/noyau/`, npm workspace): strict JSON and canonical form, hashing,
  Ed25519 and EIP-191 signatures, chaining, RFC 6962 Merkle trees and RFC 9162
  consistency proofs, period manifests, checkpoints, the perimeter attestation
  and every evidence-folder check of CT-1. Written from the CT-1 text alone,
  without reading the reference implementation, so that a defect of the oracle
  cannot be copied into the product. It replays all 684 CT-1 vector files
  (`test/noyau-vecteurs.test.js`, with an inventory test), and the CT-9
  property tests TU-12 run on it with `fast-check` 4.10.2
  (`test/noyau-proprietes.test.js`). Runtime dependencies: `@noble/curves` and
  `@noble/hashes` 2.4.0, exact. The CT-9 change is recorded as MC-1 in the
  design-freeze register.
- Design frozen as version 1.0 (first gate of the project plan), 2 November
  2026. A manifest records the SHA-256 of every file under `spec/`
  (`spec/figeage/conception-v1.0.sha256`, `sha256sum` format); every later
  change, addition or removal is recorded in a register of numbered entries
  with the digest of each file before and after
  (`spec/figeage/modifications.json`). `npm run conception:figeage` replays the
  register against the manifest and fails on any unrecorded change; CI runs it.
  The status of the nine specifications in `spec/README.md` now reads "frozen".

- CT-9, the test plan, version 0.1, the last of the nine design
  specifications: eight test levels (unit and property tests on the core,
  conformance to the published vectors, interoperability of exports, APIs and
  integrations, end-to-end runs of the two demonstration cases, adversarial
  tests, measurements, blind replays, code review), each with its rules and
  the build step that makes it runnable. A machine-readable catalogue
  (`spec/vecteurs/ct-9/catalogue.json`, schema `plan-de-tests-v0`) is the
  single source of 321 tests, each with its preconditions, steps and oracle:
  189 are runnable today and cite 359 existing tests or CI steps word for
  word, 132 are to be written at a named step of the build. One adversarial
  test per threat of CT-7 (98) and five plan scenarios state which answer is
  removed and what then fails; 58 of them run today against copies of the
  reference code with the answer removed (62 copies, all detected). Three
  answers of CT-7 are not yet coded in the reference implementation (bounded
  read of the MCP delegation, refusal of custody class D in production, the
  "dated by declaration only" reserve of a minutes record); their tests are
  written and will fail until the recorder is built. Every target of CT-2,
  CT-5 and CT-8 is listed with its source and failure threshold; no
  measurement is invented. A common protocol for blind replays, a full replay
  on a blank machine, and the mapping of each criterion of the second gate to
  tests and a computable verdict complete the plan.
- CT-9 coverage tool (`scripts/tests/couverture.mjs`, `npm run
  tests:couverture`) run by the tests and continuous integration: 2,332
  requirements and checks of CT-1 to CT-8, 2,193 covered by a test, 139 by a
  named justification, none uncovered; 98 of 98 threats with an adversarial
  test; 117 of 117 references to CT-9 answered; the tables of the text equal
  the catalogue. Measurement-report checker (`scripts/tests/mesures.mjs`).
  Vectors `spec/vecteurs/ct-9` (`npm run vecteurs:ct9`), regenerated twice to
  the same bytes, a Go verifier written from the specification alone and an
  independent Python recount, both without discrepancy. New tests
  `test/plan-de-tests.test.js` and `test/adversarial.test.js`; no existing
  test changed. No CT-1 to CT-8 specification or vector changes.
- `README.md`, `README.fr.md`, `ARCHITECTURE.md` (version 0.12) and
  `spec/README.md` mention CT-9.
- CT-8, deployment and operations, version 0.1: topologies and packages (what
  runs at the client, in a cloud tenant or at a Swiss host, and what stays
  with the NOORTRACE operator); reference Compose files for the quick install
  and for production, described image by image and checked statically by 14
  rules (CO-1 to CO-14) without building or running a container; 31 network
  flows, each tied to the requirement that needs it, with a default-deny
  rule; a host pre-check of 13 points (IP-1 to IP-13), blocking or advisory
  by profile; a quick install in eight steps with a 900-second budget and a
  full production install in eighteen steps with a 450-minute budget, each
  step with its command, expected result and check, including the WORM
  support, the key ceremony of CT-7, the first verified folder and the
  perimeter attestation; calculated sizing (DM-1 to DM-22) with a worked
  example and 15 cases, each coefficient cited or marked as to be measured;
  observability (collection points, alert rules, dashboard) and eight incident
  runbooks (writer stopped, lease lost, degraded anchoring, time-stamp
  provider unreachable, WORM copy lost, clock jump, registry RPC unreachable,
  suspected key compromise) with invariants, gates and exit checks; backup
  and recovery without breaking the chain (RPO/RTO as targets, two recovery
  paths, ticket-prefix epoch change), updates, minutes of operating acts
  (PV-1 to PV-10) and a chained log of consultations and accesses (CA-1 to
  CA-6); an observation mode where the approval policy is evaluated but never
  applied and no failure delays a relayable call; a deterministic reviewer
  package (`MANIFESTE.json`, fixed tar metadata) verified offline in one
  command (PR-1 to PR-12), with the instructions handed to the reviewer in
  French and English; three blind-reading tests with their grids, to be run
  by CT-9. Section 15 lists what this version does not cover: the images
  themselves, the host-preparation script, the observability files, a backup
  tool, a second WORM support, the installs themselves, which have not been
  executed because the recorder does not exist yet; every duration and
  capacity is a target. Eight new schemas (`conteneurs-v0`,
  `controle-prealable-v0`, `dimensionnement-v0`,
  `proces-verbal-exploitation-v0`, `consultation-v0`,
  `verification-journal-v0`, `rapport-observation-v0`, `paquet-reviseur-v0`).
- CT-2, the recorder, revision 0.6, and CT-3, approvals, revision 0.4, both
  minimal and compatible: the observation mode (`observation` value of the
  wait mode, reserved rule forms, `-observation` policy suffix and test
  approvers in CT-2; `evaluerObservation`, evaluation without effect, answer
  without ticket and the ` [observation <x>]` mark of `policy.rule` in CT-3).
  `configuration-enregistreur-v0` extended compatibly; `politique-approbation-v0`
  reserves one rule name. No CT-1 format and no CT-1 to CT-7 vector changes.
- CT-8 reference code and tools: `deploiement/` (Compose files, image
  descriptions, quick-install configuration), `scripts/deploiement/` (host
  pre-check, sizing calculator, Compose checks, quick configuration,
  deployment archive, log-directory verification, observation report,
  minutes, consultations, CT-8 cross-reference checker: 115 references, 115
  rows), `scripts/paquet-reviseur/` (build and verify), libraries
  `scripts/lib/deploiement.mjs`, `exploitation.mjs`, `paquet.mjs`, and
  `evaluerObservation` in `scripts/lib/approbation.mjs`. Vectors
  `spec/vecteurs/ct-8` (`npm run vecteurs:ct8`: containers, pre-check, sizing,
  observation, logs, minutes, consultations, two reading grids, 13 package
  archives), regenerated twice to the same bytes; a Go verifier written from
  the specification alone recomputes 5,183 values, all matching, 65 outside
  its scope. Package archives are confronted with GNU tar 1.35, Python 3.13
  `tarfile` and `sha256sum`, the consultation log with an independent Python
  reading, without discrepancy. Continuous integration adds the CT-8 steps
  (regeneration, Compose checks, cross-references, tools, Go verifier, a
  complete package built twice and verified offline by its embedded copy).
  `js-yaml` 4.3.2 becomes an exact development dependency.
- `README.md`, `README.fr.md`, `ARCHITECTURE.md` (version 0.11) and `NOTICE`
  (a complete reviewer package redistributes ethers under the MIT license)
  mention CT-8.
- CT-7, security and compliance, version 0.1: a threat model by component (14
  components, 98 threats, each with its answer citing exact requirements, its
  detection, its residual risk and the test CT-9 must write; 82 accepted risks,
  each named, bounded and assigned), consolidating without contradiction the
  threat tables of CT-2 to CT-6 and answering every reference to CT-7 in the
  other specifications; the inventory of keys and secrets with their custody
  class, rotation, revocation and response to compromise; the key ceremony and
  its minutes record (`ceremonie-cles-v0`), signed by every participant over a
  digest with its own domain prefix and checked offline (CR-1 to CR-12); the
  recorder's mandatory events on itself, and what CT-7 asks of CT-2 as
  proposals; the perimeter attestation (`attestation-perimetre-v0`), signed by
  members of the client's approver set and reported as declared, never as
  proven; a compliance matrix (`matrice-conformite-v0`: 10 texts, 58 rows, each
  with the exact quotation of the primary source, what the evidence covers,
  what remains with the client and its status) presented as a technical
  mapping, not legal advice; six model audit clauses. Schema
  `modele-menace-v0` for the threat model.
- CT-1, formats, revision 0.4, and CT-6, the verifier, revision 0.3: an
  optional fourteenth evidence folder part `attestation-perimetre.json`, a
  compatible extension of `dossier-v0`, with checks AT-1 to AT-7 filed under
  checks 6 and 7 without changing their status or any verdict, the
  `facts.perimeter` member of the report and a statement fragment; 20 new CT-1
  folders and 5 new CT-6 folders, existing vectors unchanged except `INDEX.md`.
  The CT-1 Go verifier, and its copy in the CT-2 verifier, now recompute 2,985
  values, 2,923 matching, none discordant, 62 outside their scope.
- CT-7 reference code (`scripts/lib/securite.mjs`, `scripts/verify/ceremonie.mjs`)
  and a cross-reference checker (`scripts/conformite/verifier-renvois.mjs`) run
  by the tests and continuous integration: every requirement cited by the
  threat model and the matrix exists, and the tables of the text equal their
  JSON files. Vectors `spec/vecteurs/ct-7` (`npm run vecteurs:ct7`) and a new Go
  verifier written from the specification alone: 1,241 values recomputed, all
  matching, 32 outside its scope. Signatures of attestations (100) and
  ceremony minutes (130) are confronted with ethers 6.17.0 and eth-account
  0.14.0, without discrepancy.
- CT-5 confrontation: the published `reponses.txt` and `coherence.txt` outputs
  are replayed and carry one more block, for the new CT-6 folder that reuses an
  already confronted checkpoint part.
- `README.fr.md` and `ARCHITECTURE.md`: regulatory statements aligned on the
  primary texts read for CT-7 (DORA for financial entities; FINMA
  communication 08/2024; OPDo art. 4 para. 1 and 5 since 1 December 2025;
  EU AI Act dates of application, 2 December 2027 and 2 August 2028; Olico
  art. 9 para. 1 let. b, without a compliance claim).
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
