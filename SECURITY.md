# Security policy

noortrace is evidence infrastructure: a flaw in hashing, signing, canonicalisation or
verification matters more than anywhere else in the code.

Please report vulnerabilities privately through GitHub security advisories on this
repository ("Report a vulnerability"). Do not open a public issue for a security
problem. You will receive an acknowledgement, a severity assessment and a fix timeline;
credit is given in the release notes unless you prefer otherwise.

## Accepted advisories in development dependencies

The CI job `tests` runs `npm audit --omit=dev --audit-level=low` right after
`npm ci` and fails on any advisory, of any severity, that reaches a production
dependency. The full `npm audit` is not a gate: the advisory below is known,
assessed and kept on purpose.

### GHSA-mrhx-c7xc-m3w5: zod 3, memory exhaustion on oversized constrained collections

- **Advisory.** GHSA-mrhx-c7xc-m3w5, high (CVSS 7.5, CWE-770): zod `<4.6.6`
  can exhaust memory while validating an oversized array, set or map that a
  schema bounds in size. Fixed in zod 4.6.6, in the v4 API only.
- **Packages.** `npm audit` reports 13 high-severity entries, all from this one
  advisory: `zod` 3.25.76, nested under `hardhat` and under the
  `@nomicfoundation/hardhat-{ethers,keystore,mocha,typechain,verify}` plugins,
  each of which declares `zod ^3.23.8`; `@nomicfoundation/hardhat-zod-utils`
  3.0.8 (peer `zod ^3.23.8`); and, through them, `hardhat` 3.20.0 and the
  plugins `hardhat-ethers`, `hardhat-ethers-chai-matchers`, `hardhat-ignition`,
  `hardhat-ignition-ethers`, `hardhat-keystore`, `hardhat-mocha`,
  `hardhat-network-helpers`, `hardhat-toolbox-mocha-ethers`,
  `hardhat-typechain` and `hardhat-verify`. The repository's own `zod` (4.6.7)
  is not affected.
- **Why it is not reached.** These are development tools only: no production
  package depends on them, and `npm audit --omit=dev` reports nothing. Hardhat
  uses zod 3 to validate `hardhat.config.mjs` on every command and the RPC
  parameters of its local-accounts provider on the `noorcore` network. Both
  inputs are written by this repository, never received from the network, and
  none of the installed Hardhat schemas puts an upper bound on the size of a
  collection, which is the pattern the advisory targets.
- **Why it cannot be fixed today.** Every Hardhat 3 release published so far
  (up to 3.21.2) and every Hardhat plugin that uses zod declares
  `zod ^3.23.8`; no zod 3 release carries the fix (3.25.76 is the last one).
  Overriding zod to 4.6.7 breaks Hardhat: an invalid configuration then ends in
  a `TypeError` inside `hardhat-zod-utils` instead of the `HHE15` error list,
  and the override leaves the peer range of `hardhat-zod-utils`. The only
  version npm proposes as a fix is Hardhat 2, a major step back.
- **When to revisit.** As soon as a published Hardhat release accepts zod 4
  (a zod range that admits 4.6.6 or later), together with the plugins this
  repository installs: upgrade them, check that `npm audit` no longer reports
  this advisory, and remove this section.
