# Checking a Trooth witness statement

Version 1.2, October 6, 2026, revised October 7, 2026 (section 9: the log's witnesses). Normative for `trooth verify`, the SDKs in `sdk/` and any other implementation. Version 1.2 adds the witness statement log and corrections (section 10, with the log itself in [LOG.md](LOG.md)) and the verdict `superseded`. Version 1.1 added statement v3 (RFC 8785 bytes, section 2.1), stable ids, verification bundles (section 7) and the published schemas (section 8). Every v1 and v2 statement checks exactly as under 1.0.

Trooth signs one object: the **witness statement** for a reading it took of a company's public surface. Everything else on a Trooth profile is unsigned. This document says how to check a witness statement without trusting Trooth's website, API or any summary of the result. An implementation that follows it must reach the verdict given for every case in [`tests/vectors/vectors.json`](../tests/vectors/vectors.json) [`tests/vectors/bundles.json`](../tests/vectors/bundles.json) and [`tests/vectors/log.json`](../tests/vectors/log.json). The JavaScript core (`bin/lib/verify.mjs`), the Python package (`sdk/python`) and the Go package (`sdk/go`) all do, in their own test suites.

The key words MUST, MUST NOT and SHOULD are used as in RFC 2119.

## 1. Inputs

| Input | Where to get it | Notes |
|---|---|---|
| Statement | `witnessStatement` in `GET https://trooth.co/api/network/profile?q=<domain>&contract=2` | An object with `payload`, `signature`, `key_id`, `alg`, `canonicalization` |
| Key list | `GET https://api.trooth.co/public/keys` | Use the `keys` array. Record when you read it (`list_read_at`). |
| Check mapping (v2) | The URL in the payload's `methodology.mapping_url` | The exact bytes, as served. Immutable copies live under `https://trooth.co/standard/check-mapping/`. |
| Evidence manifest (v2) | `witnessEvidenceManifest` in the same profile response | A JSON list of `{check_id, source}` or `{check_id, commitment}` |
| Domain | The domain you are about to rely on | Lowercase, no trailing dot |

## 2. The signature

1. `payload` MUST be a string. It is the signing input: the exact UTF-8 bytes that were signed. Do not parse and re-serialize it before checking; different bytes with the same meaning do not check (vector `reserialized-payload`).
2. `alg` MUST be `Ed25519`. Any other value: the result is `malformed`.
3. `signature` MUST match `^ed25519:([A-Za-z0-9+/]+={0,2})$`. The capture is standard base64 of the 64-byte signature. Otherwise the result is `malformed`.
4. Parse `payload` as JSON. Its `statement` field MUST be `trooth.witness-statement.v1`, `trooth.witness-statement.v2` or `trooth.witness-statement.v3`; otherwise the result is `malformed`. A v3 statement must also meet section 2.1 before its signature is checked.
5. Find the key whose `kid` equals `key_id`. Decode `public_key` as hex when `encoding` is `hex`, as base64 when it is `base64`. It MUST be 32 bytes.
6. Check the Ed25519 signature (RFC 8032, pure EdDSA) over the payload bytes. The result is `valid` or `invalid`. An unknown `key_id` gives `invalid`.

### 2.1 Statement v3: one byte string per meaning

A v1 or v2 payload is signed in a fixed member order with no whitespace. A v3 payload is signed as its RFC 8785 (JSON Canonicalization Scheme) form, so anyone can rebuild the exact signed bytes from the parsed JSON. For a v3 statement, all of these MUST hold, or the result is `malformed` and the signature is not checked (vectors `v3-not-canonical`, `v3-fraction`, `v3-wrong-label`, `v3-signer-differs`):

1. The envelope's `canonicalization` is `RFC8785`.
2. The payload bytes equal the canonical form of the JSON they hold: object members sorted by UTF-16 code units, no whitespace, strings escaped exactly as ECMAScript `JSON.stringify` escapes them. The Trooth profile allows only integers between -(2^53 - 1) and 2^53 - 1: a fraction, an exponent, `-0` written as such or a lone surrogate has no canonical form. A key repeated in one object cannot survive the round trip, so it fails here too.
3. `signer.key_id` inside the payload equals the envelope's `key_id`, so the signed bytes name the key that signed them.

A v3 payload carries everything a v2 payload does, plus `subject_id` (`trooth:domain:<domain>`, see [IDS.md](IDS.md)) and `signer` (`key_id`, `issuer: "trooth.co"`). Section 4 adds two identities for v3: `subject_id` names the payload's `domain`, and `subject_scope.domain` equals `domain`.

Trooth's checkers accept v3 from this version on. The witness worker keeps signing v2 until every Trooth surface that shows a statement checks v3 too; that switch is announced in the changelog, and v1 and v2 statements stay checkable for as long as any is published.

## 3. The key's lifecycle

A valid signature is relied on only when the key is trusted at the time the payload carries in `read_at`:

| State (from the key entry) | Trusted? |
|---|---|
| `compromised_at` set, or `status` is `compromised` | Never, whatever time the statement carries |
| `retired_at` set, or `status` is `retired` | Only when `read_at` is strictly before `retired_at` |
| `status` is `revoked` or `revoked_at` set, with no compromise recorded | Never (treated as compromised) |
| `status` is `active` or empty | Yes |
| Not on the list | Never: not a Trooth key |

The time in `read_at` is asserted by Trooth when it signs; there is no independent timestamp. A saved key list cannot show a compromise announced after it was saved, so refresh it before relying on a result for a decision.

If the signature is not `valid` or the key is not trusted, the verdict is **`signature_not_trusted`** and nothing in the payload is relied on. Stop here.

## 4. What the signature binds

With a trusted, valid signature, check in this order:

**Count identities.** For every version, `counts.read` MUST equal the number of checks whose `outcome` is not `not read`, and `counts.as_expected` the number whose outcome is `as expected`. Every outcome MUST be one of `as expected`, `not as expected`, `not read`. For v2 and v3 additionally:

- `read + not_read = in_reading`, `as_expected + not_as_expected = read`, `in_reading` = the number of checks, `subject_scope.checks_in_scope` = the number of checks;
- every check other than `as expected` carries a `reason` whose `code` is one of the codes below and goes with that outcome; a reason marked `withheld` publishes no `source_ref` and gives a `withheld_reason`.

| Reason code | Goes with |
|---|---|
| `source_unavailable`, `timeout`, `evaluator_limitation`, `carried_from_earlier_reading`, `check_misconfigured` | `not read` |
| `contrary_observation`, `expected_item_absent` | `not as expected` |

**Subject.** When a domain is given, the payload's `domain` MUST equal it. A genuine statement about another domain is a mismatch (vector `domain-mismatch`).

**Mapping (v2, v3).** `sha256:` followed by the lowercase hex SHA-256 of the exact mapping bytes MUST equal `methodology.mapping_digest`.

**Manifest (v2, v3).** Sort the entries by `check_id` (code-unit order); no `check_id` may appear twice. Serialize as a JSON array with no whitespace, each entry as `{"check_id":…,"source":…}` or `{"check_id":…,"commitment":…}` in that key order. `sha256:` plus the hex SHA-256 of those UTF-8 bytes MUST equal `evidence_manifest.digest`, and the number of entries MUST equal `evidence_manifest.entries`. A `commitment` is `sha256` over `salt || 0x0A || private reference`; only its holder can open it.

A v1 statement binds no mapping, manifest, evaluator or subject scope.

## 5. The verdict

| Verdict | When | `trooth verify` exit code |
|---|---|---|
| `checked` | v2 or v3: signature valid, key trusted, counts hold, subject matches (or no domain given), mapping and manifest both match | 0 |
| `checked_v1` | v1: signature valid, key trusted, counts hold, subject matches | 0 |
| `partially_checked` | Everything checked held, but the mapping or the manifest was not supplied. Not supplied is never reported as a match | 4 |
| `signature_not_trusted` | Malformed, invalid signature, or key not trusted | 8 |
| `mismatch` | Signature trusted, but counts disagree, the domain differs, a supplied mapping or manifest does not match, or a log receipt was supplied and does not check | 9 |
| `superseded` | Everything checked held, and a correction Trooth signed and logged withdraws or replaces the statement (section 10) | 10 |

## 6. What a `checked` verdict does and does not mean

It means Trooth's key signed these outcome bytes, for this domain, together with the digest of the exact check mapping, the evaluator version, the subject scope and the digest of the evidence manifest. It does not establish the company's identity, that the signed time was independently established, that anything outside the reading is true, or that the company is safe, compliant or authorized for any transaction. What to do with a checked reading is the reader's decision.

Every result also carries `statement_id`: `trooth:statement:` plus the hex SHA-256 of the exact payload bytes. Two parties holding the same id hold the same signed bytes.

## 7. Verification bundles

A bundle (`trooth.verification-bundle.v1`, [schema](../schemas/verification-bundle.v1.schema.json)) carries every input in one file: the envelope as published, the evidence manifest, the key list with the time it was read, and the mapping document as standard base64 of its exact bytes. `trooth verify <domain> --save-bundle <file>` writes one; `trooth verify --bundle <file>`, `verify_bundle` (Python) and `VerifyBundle` (Go) check one with no network.

- The checker hashes the carried mapping bytes itself; the `digest` written beside them is for display and is never trusted.
- A domain the reader gives replaces the one the bundle names (vector `bundle-asked-other-domain`).
- A bundle written by `trooth` 0.9.0 or later also carries the log's answer (`log`: the log key used, the receipt or null, and every correction), so the log part is checked offline too. A log key the checker has pinned replaces the one the bundle carries.
- A bundle is only as fresh as its key list. A compromise announced after `keys.list_read_at` is not in it, so refresh the list before relying on an old bundle for a decision.
- A document whose `bundle` is not `trooth.verification-bundle.v1` is refused, not checked (vector `not-a-bundle`).

## 8. Schemas and types

[`schemas/`](../schemas) holds JSON Schema (2020-12) for the envelope, the v1, v2 and v3 payloads, the key list, the evidence manifest, the bundle and the result, with a description on every field. Each is served at `https://trooth.co/schemas/<file>`. `scripts/gen-types.mjs` generates TypeScript (`types/trooth.d.ts`), Pydantic v2 (`sdk/python/trooth_verify/models.py`) and Go (`sdk/go/trooth/types.go`) types from them, and the tests fail when a generated file is stale. The schemas describe; this document decides: a document can validate and still not check.

## 9. Limits of this version

- The log has one operator; witness cosignatures begin when the witness network follows it ([LOG.md](LOG.md) sections 7 and 12).
- Statements and receipts are JSON, not COSE (RFC 9052); a COSE form for SCITT (RFC 9943) receipts is planned.
- There is no external timestamp.
- The witness worker still signs v2; see section 2.1.

## 10. The witness statement log

When the checker can reach the log (or a bundle carries its answer), the result gains a `log` part: the log status (`included`, `not_logged`, `unavailable`, `checkpoint_invalid`, `proof_invalid`), the entry index and signed tree size, and each correction with whether it is relied on. The rules for receipts and corrections are in [LOG.md](LOG.md) sections 4 to 6.

- `checkpoint_invalid` or `proof_invalid` makes the verdict `mismatch`: the log's answer about this statement does not check.
- A correction that meets every rule in [LOG.md](LOG.md) section 6 makes the verdict `superseded` (exit 10), unless the verdict is already `signature_not_trusted` or `mismatch`. The statement's signature is still valid; Trooth has said it no longer stands behind it.
- `not_logged` and `unavailable` change nothing in this version, and are reported.

`trooth verify` asks the log unless `--offline` or `--no-log` is given, and checks checkpoints against the log key pinned in the release, or the key given with `--log-vkey`.
