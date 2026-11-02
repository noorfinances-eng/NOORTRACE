# noortrace

[![ci](https://github.com/noorfinances-eng/NOORTRACE/actions/workflows/ci.yml/badge.svg)](https://github.com/noorfinances-eng/NOORTRACE/actions/workflows/ci.yml)
[![licence](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE)

**A verifiable flight recorder for AI agents.**

noortrace records the tool calls and model exchanges an AI agent makes through
its recorder, in a form a third party can verify years later, offline, without
trusting the agent. The verifier specification (CT-6 §7) states what the
verification proves and what the reviewer must still trust.

- **Capture outside the agent.** A recorder sits between the agent and its tools as
  an MCP proxy, and between the agent and its model as an API gateway reached through
  the SDK's base URL; an ICAP hook into an existing intercepting proxy is the
  fallback, and an in-process SDK the last resort. Agents can and do erase their own
  traces; a trace the agent cannot reach is the only one worth keeping.
- **An append-only, hash-chained, signed journal.** Every event carries the hash of the
  previous one and an Ed25519 signature of the recorder. Deleting, inserting,
  reordering or editing an event breaks the chain, and the verifier names the
  break when it lies between an event and the neighbours in its folder. Until
  an event is committed by an external anchor, whoever holds the recorder key
  can still rewrite and re-sign it. Signed checkpoints every 60 seconds,
  countersigned by a time-stamping authority at most every 5 minutes, bound
  that window to 300 seconds plus the time-stamp delay; after it, a rewritten
  event no longer passes with the original anchors, and a new time-stamp would
  carry a later instant (CT-5 §3.3, CT-6 §7.2, §7.9).
- **Hourly Merkle periods, minute checkpoints.** Each period closes with a signed
  manifest and a root; a signed checkpoint commits to the head of the journal every
  minute, and an RFC 9162 consistency proof links it to the period's final root.
  Only 32-byte hashes leave the operator's perimeter.
- **Independent anchoring.** The hash of each period manifest, which commits to the
  root, is time-stamped by a qualified trust service provider (RFC 3161), anchored on
  a public chain (OpenTimestamps) and recorded in an operating registry whose block
  commit certificates are themselves verifiable offline (the registry's block hash is
  noorcore's BFT hash, not Ethereum's). Checkpoints that commit to new events are
  recorded in the same registry, and at most one every 5 minutes is time-stamped (CT-5).
- **Human approval before sensitive actions.** Threshold-signed decisions are events of
  the same journal, and the action is held until they exist. Each approver is a named
  person, authenticated by the client's identity system, who signs with their own key
  in their own wallet (CT-3).
- **An open evidence format and an offline verifier.** One event proves itself,
  revealing no other event than its neighbours and its linked approval
  decisions, with a verifier that needs no network and no noortrace. Among its
  inputs it trusts only the trust anchors the reviewer supplies (time-stamping
  authorities, a Bitcoin checkpoint, the registry's validator set), never the
  evidence folder itself, and its statement asserts only what was proven.

## Status

Early. The nine design specifications are written, each with test vectors
checked by implementations written separately from the reference.

- **CT-1, formats**: event model, canonical form, hashing, signing, Merkle periods,
  period manifests, signed checkpoints with RFC 9162 consistency proofs, and
  evidence folders. Revision 0.4 adds an optional part carrying the perimeter
  attestation of CT-7.
- **CT-2, the recorder**: MCP proxy, model API gateway, redaction before hashing,
  key custody classes, append-only storage, single-writer lease and behaviour under
  failure. The computable parts (full canonical form, redaction, MCP and model
  payloads, stream reassembly, event construction) are implemented and checked.
  Revision 0.4 adds the production of checkpoints and their hand-over to the
  anchoring component.
  Revision 0.5 adds Gemini (`generateContent`, `streamGenerateContent`) to the
  model gateway; Python and TypeScript SDKs with adapters for LangChain and
  LangGraph, CrewAI, LlamaIndex, the OpenAI Agents SDK and LiteLLM; ingestion
  of OpenTelemetry GenAI traces over OTLP, recorded as declarative like the SDK;
  a legal hold on the WORM copies, released by two people, with the writer
  unable to delete or release; and a per-agent cost formula whose unit prices
  are parameters. Gemini payloads and OTLP requests in the vectors are
  confronted with the official google-genai and opentelemetry-proto libraries.
- **CT-3, approvals**: a JSON rule language over a tool and its arguments, three
  levels (automatic, time-boxed window, per-call review), the ticket lifecycle, the
  approver set pinned by the policy and read from the client's CuratorSet, what an
  approver sees before signing, and the proxy's behaviour while waiting: an
  immediate tool error result (`isError`) carrying the ticket and its state by
  default. Rule evaluation, tickets and decision checks are implemented and
  checked. Revision 0.3 adds approval from the session of a named person
  authenticated by the client's identity system, an approver directory where
  each address is enrolled by proof of possession, the signing paths (browser
  wallet, hardware wallet through it, mobile wallet when the organisation opts
  in, encrypted key file), and a local check where the console recomputes the
  signed digest and refuses to have anything else signed. A reference console
  (`console/`, `scripts/lib/console.mjs`) is tested end to end in Chromium;
  its signatures are confronted with ethers and eth-account.
- **CT-4, the registry**: the dedicated noorcore instance (genesis rules checked
  at start-up, identifiers, validators and quorum, fee-less gas with an admission
  guard against mempool poisoning), the contracts and their conventions
  (`docType`, signed digests, anchor fingerprints), client onboarding step by
  step, the block commit certificate and its capture for the evidence folder,
  container topologies, and the substitution rule that decides at gate 4 between
  partner validators and a signed database journal. A reference command-line
  tool (`npm run registre`) performs onboarding, anchoring, period closure and
  capture on the development network.
- **CT-5, anchoring**: checkpoint cadence and selection, the registry,
  RFC 3161 and OpenTimestamps anchors with their retries, fallbacks and durable
  queue, the hourly qualified closure, monitoring, the series completeness check
  against the registry, and a cost formula whose unit price is a parameter. The
  scheduler is implemented with an injected clock and replayed on normative
  traces; its requests and proofs are checked by OpenSSL, the official
  OpenTimestamps library and a public RFC 9162 implementation.
- **CT-6, the verifier**: the eight checks, the reviewer's trust anchors, verdicts
  and what each one proves and does not prove, human and JSON output, and the
  reproducible, network-free build of a future Go binary. Revision 0.2 checks a
  folder's checkpoint part (K-1 to K-9) and states the bound it proves. The RFC 3161,
  OpenTimestamps and registry checks are implemented in the JavaScript verifier;
  their vectors are recomputed without discrepancy by OpenSSL, the official
  OpenTimestamps library and go-ethereum. Revision 0.3 checks the optional
  perimeter attestation (AT-1 to AT-7) and reports it as declared, never as
  proven, without changing any verdict.
- **CT-7, security and compliance**: a threat model by component (98 threats, each
  with its answer, its detection and its residual risk; 82 accepted risks, each
  named, bounded and assigned), the inventory of keys and secrets, the key
  ceremony with a minutes record signed by every participant and checked offline,
  the recorder's journal on itself, the perimeter attestation signed by the
  client's approvers, a compliance matrix that maps quoted passages of Swiss and
  EU texts to evidence and says what remains with the client, and model audit
  clauses. The matrix is a technical mapping, not legal advice. Signatures are
  confronted with ethers and eth-account.
- **CT-8, deployment and operations**: topologies and packages, reference Compose
  files checked statically (CO-1 to CO-14), network prerequisites (31 flows),
  the host pre-check (IP-1 to IP-13), a quick install in eight steps within
  15 minutes and a full production install in eighteen steps within a day,
  calculated sizing (DM-1 to DM-22, a reference calculator), observability and
  eight incident runbooks, backup and recovery without breaking the chain,
  updates, a log of consultations and accesses, an observation mode in which
  the approval policy is evaluated but never applied (CT-2 revision 0.6, CT-3
  revision 0.4, both minimal and compatible), and a deterministic reviewer
  package verified offline in one command (PR-1 to PR-12). Every duration and
  capacity is a target to be measured by CT-9 once the recorder exists; the
  install procedures themselves have not been run. Package archives are
  confronted with GNU tar, Python's `tarfile` and `sha256sum`.
- **CT-9, the test plan**: eight test levels (unit and property, vectors,
  interoperability, end to end, adversarial, measurements, blind replays, code
  review) and a machine-readable catalogue of 321 tests, each with its
  preconditions, steps and oracle, either runnable today (it names an existing
  test of this repository word for word) or to be written at a named step of
  the build. One adversarial test per threat of CT-7 states which answer is
  removed and what then fails; the ones already possible are run against copies
  of the reference code with the answer removed. A coverage tool checks, in the
  tests and in continuous integration, that every requirement and check of CT-1
  to CT-8 is covered by a test or by a named justification, that every threat
  has its adversarial test and that every reference to CT-9 has its answer. No
  measurement is invented: every target is listed with its source and failure
  threshold, to be measured at the second gate.

CT-1, CT-2, CT-3, CT-4, CT-5, CT-7, CT-8 and CT-9 vectors are also recomputed by
Go verifiers written from the specification alone, without reading the
JavaScript.

The registry contracts, the commit-certificate verifier and the reference approval
console exist and are tested. The recorder, the approval service and the operating
console, the anchoring component with its network clients, and the verifier's Go
binary are specified, not built yet.

## Layout

| Path | Content |
|---|---|
| `spec/` | Normative specifications, JSON schemas, test vectors |
| `scripts/lib/` | JavaScript reference implementation |
| `scripts/verify/` | Offline verifiers (evidence folder, commit certificate) |
| `scripts/registre/` | CT-4 reference tool: client onboarding, anchoring, period closure, capture |
| `deploiement/` | CT-8 reference deployment files: Compose files, image descriptions, quick-install configuration |
| `scripts/deploiement/` | CT-8 tools: host pre-check, sizing, Compose checks, quick configuration, operations logs, minutes, consultations |
| `scripts/paquet-reviseur/` | CT-8 reviewer package: build and offline verification in one command |
| `scripts/tests/` | CT-9 coverage tool and measurement-report checker |
| `console/` | CT-3 reference approval console: a static page with a strict content security policy |
| `contracts/` | Registry contracts (Solidity) |
| `test/` | Tests and fixtures |
| `chain/` | Dedicated development instance of the registry node, container image |
| `ARCHITECTURE.md` | Target architecture, in French |

The specifications, code comments and project documentation are written in French;
`README.fr.md` is the French front page. JSON keys, schemas and this file are in
English.

## Getting started

```bash
npm install
npm test
```

## What noortrace is not

It is not the legal proof by itself: the presumption of date and integrity belongs to the
qualified time-stamp. It is not a blockchain product: the registry is an operating
component and is substitutable. It never holds business data: only hashes leave the
operator. It does not see what bypasses it: an action taken through a channel that is
neither MCP nor a configured model API is not recorded, and no evidence folder can
prove it or its absence. And an evidence folder reveals no event beyond the
proven one, its neighbours and its linked approval decisions, but a registry
block certificate carries the raw transactions of its whole block, so the
folder also shows other organisations' period closures and anchors recorded in
the same blocks: their hashes, identifiers and times.

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.
