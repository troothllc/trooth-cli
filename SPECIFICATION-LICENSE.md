# The Trooth record format: specification license

The Trooth record format is an open specification. Anyone may implement it, in any language, without asking Trooth.

## What is a specification here, and its license

These parts of this repository are the specification, and they are licensed under the [Community Specification License 1.0](https://github.com/CommunitySpecification/Community_Specification/blob/main/1._Community_Specification_License-v1.md), the license the Joint Development Foundation publishes for open standards, in addition to the Apache License 2.0 that covers the whole repository:

- `docs/VERIFY.md`, `docs/LOG.md`, `docs/DECLARATION.md`, `docs/EVIDENCE.md`, `docs/ACTION-EVIDENCE.md`, `docs/IDS.md` and `docs/GUARD.md`: the rules a statement is checked by
- `schemas/`: the JSON Schemas for every signed object
- `spec/`: the formal model of the guard decision
- `tests/vectors/`: the conformance suite (the cases every implementation must agree on)

## The code, and its license

Everything else, the `trooth` command line tool and the software development kits in `sdk/` included, is licensed under the Apache License 2.0 only. See [LICENSE](LICENSE). The one exception is the guard decision engine (`bin/lib/guard.mjs`, `guard-decide.mjs`, `guard-policy.mjs`, `guard-evidence.mjs` and `guard-ci.mjs`), which from 0.24.0 is under the Functional Source License 1.1 with the Apache 2.0 future license ([LICENSE-FSL.md](LICENSE-FSL.md)). The formal model of the guard decision in `spec/` and the rules in `docs/GUARD.md` stay under the licenses above, so anyone may build their own engine to the same model.

## The name is not licensed by either

Neither license grants any right to the Trooth name or marks. A copyright license is not a trademark license. How the name may be used, and which issuers may call their statements Trooth records, is in [TRADEMARKS.md](TRADEMARKS.md).
