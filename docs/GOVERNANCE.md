# How Trooth's formats change

Version 1.0, October 8, 2026. Added in trooth 0.16.1.

This is the public process for changing the formats Trooth publishes and checks. Anyone may take part: no account with Trooth, no relationship and no fee.

## 1. What it covers

- `trooth.declaration` (the discovery file at `/.well-known/trooth.json`; [DECLARATION.md](DECLARATION.md))
- The witness statement versions and their envelope ([VERIFY.md](VERIFY.md))
- `trooth.public-record` and the evidence formats ([EVIDENCE.md](EVIDENCE.md))
- The log's entries, checkpoints, tiles and receipts ([LOG.md](LOG.md), [MIRRORS.md](MIRRORS.md))
- The JSON schemas in [`schemas/`](../schemas) and the test vectors in [`tests/vectors/`](../tests/vectors)

The api.trooth.co contract has its own versioning and deprecation policy at https://trooth.co/api-versioning.

## 2. Proposing a change (an RFC)

Open an issue in this repository using the **RFC** template, titled `RFC: <title>`. It asks for:

- the problem;
- the change, written as spec text;
- what existing checkers would do with it;
- test vectors that should pass and fail.

Trooth acknowledges each RFC within 5 business days and labels it `rfc:proposed`. Security problems go to security@trooth.co rather than a public issue.

## 3. Review and decision

- **Comment period.** A change that existing checkers would read differently stays open for comment for at least 30 days. An addition that changes no existing result stays open for at least 14 days.
- **Decision.** Trooth decides, and writes its reasons on the issue whether it accepts, revises or declines. The issue is labelled `rfc:accepted`, `rfc:revised` or `rfc:declined`.
- **Credit.** An accepted change names its author in the changelog and in the spec's revision note.
- **Change control.** Trooth, LLC holds change control today. If a format is later moved to a neutral standards body, that body's process replaces this one for that format.

## 4. Versions

Every format names its version in its `format` field (or its schema's `$id`).

- **Major** (`.v1` to `.v2`): a change that would make an existing checker give a different result.
- **Minor**: an optional new member that existing checkers ignore. Noted, with its date, in the spec's header.
- **Clarification**: wording that changes no result. Made in place and dated.

The `trooth` package follows [semantic versioning](https://semver.org) for its command-line interface, its exit codes and its library exports.

## 5. Migration windows

When a new major version of a format is published:

- Trooth keeps producing the old version alongside it for at least **6 months**.
- `trooth` keeps checking the old version for at least **12 months**.

Signed statements and log entries are never rewritten. A document that was valid under the version it names stays checkable for as long as the log exists.

## 6. Deprecation

A format version is deprecated by a dated notice, at least **90 days** before Trooth stops producing it. The notice appears in three places:

- the format's spec;
- this package's [CHANGELOG](../CHANGELOG.md);
- https://trooth.co/changelog.

An exit code or a command of `trooth` is removed only in a major release, after a deprecation notice in at least one earlier release.

## 7. Compatibility

An implementation that passes the test vectors for a format version is compatible with it. Every accepted change ships with its vectors.
