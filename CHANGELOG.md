# Changelog

All notable changes to noortrace are recorded here. The format follows
Keep a Changelog; versions follow semantic versioning once the first release
is tagged.

## Unreleased

- CT-1: event model v0, canonical form (RFC 8785 with integer-only numbers),
  SHA-256 hashing and Ed25519 signing with domain prefixes, hash-chained
  journal, RFC 6962 Merkle periods with the zero root for empty periods,
  period manifests, evidence folder v0, offline verifier (checks 1, 2, 3, 6, 7),
  deterministic test vectors, JavaScript reference and clean-room Go verifier.
- Registry contracts: PeriodRegistry (continuity per journal, per-organisation
  uniqueness), RecorderRegistry, ThresholdSignatures; AttestationRegistry,
  CuratorSet and CuratorSetRegistry reused from noorchain-core.
- Offline verifier of BFT commit certificates (`noor_getCommitCertificate`),
  byte-for-byte parity with the node's signing scheme.
- Dedicated development instance of the registry node, container image, study of
  what a follower node provides.
- Apache-2.0 licence, English README, contribution and security policies.
- Continuous integration: full test suite, deterministic regeneration of the CT-1
  vectors and the clean-room Go verifier run against them on every push.
