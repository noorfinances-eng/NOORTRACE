# noortrace

[![ci](https://github.com/noorfinances-eng/NOORTRACE/actions/workflows/ci.yml/badge.svg)](https://github.com/noorfinances-eng/NOORTRACE/actions/workflows/ci.yml)
[![licence](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE)

**A verifiable flight recorder for AI agents.**

noortrace records what an AI agent actually did, in a form a third party can verify
years later without trusting the operator, the agent, or noortrace itself.

- **Capture outside the agent.** A recorder sits between the agent and its tools as
  an MCP proxy, and between the agent and its model as an API gateway reached through
  the SDK's base URL; an ICAP hook into an existing intercepting proxy is the
  fallback, and an in-process SDK the last resort. Agents can and do erase their own
  traces; a trace the agent cannot reach is the only one worth keeping.
- **An append-only, hash-chained, signed journal.** Every event carries the hash of the
  previous one and an Ed25519 signature of the recorder. Deleting, inserting, reordering
  or editing an event breaks the chain in a way the verifier names.
- **Hourly Merkle periods.** Each period closes with a signed manifest and a root. Only
  32 bytes leave the operator's perimeter.
- **Independent anchoring.** The root is time-stamped by a qualified trust service
  provider (RFC 3161), anchored on a public chain (OpenTimestamps) and recorded in an
  operating registry whose block commit certificates are themselves verifiable offline.
- **Human approval before sensitive actions.** Threshold-signed decisions are events of
  the same journal, and the action is held until they exist.
- **An open evidence format and an offline verifier.** One event proves itself, without
  revealing the others, with a verifier that needs no network and no noortrace.

## Status

Early. Two specifications are written, each with test vectors and two
implementations developed separately inside this project: a JavaScript reference,
and a Go verifier written from the specification alone, without reading the
JavaScript.

- **CT-1, formats**: event model, canonical form, hashing, signing, Merkle periods,
  period manifests and evidence folders.
- **CT-2, the recorder**: MCP proxy, model API gateway, redaction before hashing,
  key custody classes, append-only storage, single-writer lease and behaviour under
  failure. The computable parts (full canonical form, redaction, MCP and model
  payloads, stream reassembly, event construction) are implemented and checked.

The registry contracts and the commit-certificate verifier exist and are tested. The
recorder itself is specified, not built yet; it is the next component.

## Layout

| Path | Content |
|---|---|
| `spec/` | Normative specifications, JSON schemas, test vectors |
| `scripts/lib/` | JavaScript reference implementation |
| `scripts/verify/` | Offline verifiers (evidence folder, commit certificate) |
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
prove it or its absence.

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.
