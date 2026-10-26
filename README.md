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
  the same journal, and the action is held until they exist.
- **An open evidence format and an offline verifier.** One event proves itself,
  revealing no other event than its neighbours and its linked approval
  decisions, with a verifier that needs no network and no noortrace. Among its
  inputs it trusts only the trust anchors the reviewer supplies (time-stamping
  authorities, a Bitcoin checkpoint, the registry's validator set), never the
  evidence folder itself, and its statement asserts only what was proven.

## Status

Early. Six specifications are written, each with test vectors checked by
implementations written separately from the reference.

- **CT-1, formats**: event model, canonical form, hashing, signing, Merkle periods,
  period manifests, signed checkpoints with RFC 9162 consistency proofs, and
  evidence folders.
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
  checked.
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
  OpenTimestamps library and go-ethereum.

CT-1, CT-2, CT-3, CT-4 and CT-5 vectors are also recomputed by Go verifiers
written from the specification alone, without reading the JavaScript.

The registry contracts and the commit-certificate verifier exist and are tested. The
recorder, the approval service and console, the anchoring component with its
network clients, and the verifier's Go binary are specified, not built yet.

## Layout

| Path | Content |
|---|---|
| `spec/` | Normative specifications, JSON schemas, test vectors |
| `scripts/lib/` | JavaScript reference implementation |
| `scripts/verify/` | Offline verifiers (evidence folder, commit certificate) |
| `scripts/registre/` | CT-4 reference tool: client onboarding, anchoring, period closure, capture |
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
