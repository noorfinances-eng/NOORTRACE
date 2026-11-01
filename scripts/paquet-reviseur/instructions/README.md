# NOORTRACE reviewer package

This package contains NOORTRACE evidence dossiers and what is needed to verify
them offline. Its format is the reviewer package version 0 (specification
CT-8, section 13); each dossier is verified according to specification CT-6.

## Contents

- `MANIFESTE.json`: the list of files, with the size and SHA-256 of each,
  and, for each dossier, the anchors file and the Bitcoin headers file to
  verify it with.
- `dossiers/`: one directory per evidence dossier.
- `ancres/`: the trust anchors file that you gave to the operator. Make sure
  it is yours: `sha256sum <your anchors file>` must give the value that the
  summary prints (warning AV-PR-3), without its `0x` prefix; otherwise, or
  if you gave no file, give yours with the `--ancres` option.
- `entetes/`: Bitcoin headers, trusted only through the checkpoint of your
  anchors file.
- `attestation/` (if present): the signed scope attestation and the approver
  set that the operator declares.
- `pieces/` (if present): documents published by the operator to prepare and
  cross-check your anchors (provider records, registry instance manifest…).
  They are declarative: the tool does not read them, and they do not replace
  your own sources.
- `verificateur/` (if present): the reference verifier, the package
  verification tool and the only library they depend on.

## Verifying in one command

Node.js 22 is required (tested with v22.22.0 on Linux; later versions and
other systems are not verified); no network access is needed.

1. Take the verification tool from a source you trust: the public NOORTRACE
   repository, whose address and commit the release note gives, at a
   published version, or the enclosed copy under `verificateur/`. To use the
   enclosed copy:
   - extract the package into a new, empty directory with
     `tar -xkf <package.tar> -C <directory>` (never with the `-P` option)
     and require exit code 0: with `-k`, a duplicate name makes `tar` fail
     instead of replacing the first file with the second;
   - in `<directory>/paquet-reviseur/verificateur/`, check the extracted
     files with `sha256sum --strict -c <SHA256SUMS>`, where `<SHA256SUMS>`
     is the signed list of the verifier's SHA-256 published with the
     release note, over another channel than the package; neither the
     package manifest nor the `--version` output of the copy replaces it.
     As long as no version of the tool is published, there is no such
     list and this check is not possible: take the tool from the public
     repository, at a commit that the operator names to you together with
     the package digest, over the same channel; you then trust the
     operator for the tool.
2. Run, from any directory:

       node <tool>/scripts/paquet-reviseur/verifier.mjs <package.tar> \
            --empreinte <SHA-256 of the package received over another channel> \
            --ancres <your anchors file>

   `<tool>` is the root of the repository, or the `verificateur/` directory
   of the extracted copy. Both options are optional; without them, the
   report says so. `--json` gives the report in JSON, `--langue en` in
   English. `--exiger` requires CT-6 controls (numbers 1 to 8).

The tool checks the archive without writing anything (headers, names,
files against the manifest), then only extracts it into a new directory
under the system temporary directory, verifies each dossier, and deletes
that directory.

On a valid package, the "Checks not passed" section may hold up to three
"not run" lines, which are not failures: `PR-2 (empreinte_non_fournie)` if
you did not give `--empreinte`, an omitted precaution; `PR-11 (sans_objet)`
if the package has no enclosed verifier; `PR-12 (sans_objet)` if it has no
attestation. With the recommended command, on a package without an enclosed
verifier and with an attestation, only one remains: `PR-11`.
`PR-11 (auto_comparaison)` says that the running tool is the enclosed copy
itself, which cannot check itself.

Controls 1 to 8 and the `D-`, `E-`, `C-`, `M-` identifiers of a dossier are
those of CT-6 (section 8); section 13.7 of CT-8 names the eight controls.
For the decision, only the exit code, the verdict and the provenance of the
anchors count: with "package anchors", an exit code 0 is worth nothing until
you have compared their SHA-256 with your file (warning AV-PR-3). In the
"Statement" line of a dossier, "the reviewer's" means the anchors file that
was used: as long as the dossier line says "package anchors" and you have
not made that comparison, read "the operator's".

## Exit codes

Code 4 prevails over everything, because no dossier is then verified;
between dossiers, the priority is 1, then 2, 3, 0.

| Code | Meaning |
|---|---|
| 0 | Package intact, every dossier valid. |
| 1 | Package intact, at least one dossier invalid. |
| 2 | Unusable input: usage, unreadable archive, extraction impossible, internal error; or package intact where at least one dossier returns code 2 (anchors file refused) and none returns code 1. |
| 3 | Package intact, no dossier invalid or unusable, at least one dossier incomplete (`--exiger` option). |
| 4 | Package not conforming: no dossier is verified. |

What to do for each code:

- Code 1: the package is the one the manifest describes, but at least one
  dossier is invalid. That dossier does not prove the event (CT-6 §8.3):
  keep the `--json` report and report it to the operator. Every other
  dossier keeps the meaning of its own code, under the anchors used.
- Code 2 of type `usage` (option, unreadable `--ancres` file, existing
  `--conserver` directory): it comes from your command; correct it and run
  again. A code 2 with an intact package and a refused anchors file puts
  that file in question (yours, or the package's if you did not give
  `--ancres`), not the integrity of the package.
- Code 3: a control required by `--exiger` did not pass, while no check
  failed; the dossier is not invalid, it is incomplete. Ask for the missing
  pieces or run again after the proofs have been upgraded.
- Code 4, or code 2 due to the archive (unreadable, extraction impossible):
  the package is refused and is not used. Keep the archive, its SHA-256 and
  the `--json` report, and ask the operator for a new package, whose digest
  reaches you over another channel. A failed PR-2 only says that the SHA-256
  of the archive differs from the value given: re-read the digest you
  received before concluding that the package is not the announced one.
  After a failed PR-2, a second run without `--empreinte` can locate the
  difference (PR-3 to PR-9 then run; PR-8 names the file at fault): attach
  its `--json` report to your report. It does not change the decision: the
  package stays refused until you hold an archive whose SHA-256 equals the
  digest you received, re-read.

## What the result proves, and what it does not

- "Package intact" says that the files are those the manifest describes,
  byte for byte. It does not say who made the package: only the digest
  received over another channel (`--empreinte`) ties this package to its
  sender.
- "VALID" for a dossier repeats the statement of the verifier (CT-6), which
  is worth only what the anchors used are worth. Anchors taken from the
  package are the operator's until you have compared them with yours.
- The scope attestation is declared by its signatories, not proven.
- The package proves nothing about events it does not contain: it does not
  say that the list of dossiers is complete.

## Safety

Never extract a package with `tar -P` or into a directory that already holds
files. The tool refuses links, absolute names, names that contain `..`,
duplicates and any file the manifest does not declare.
