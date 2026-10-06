# Checking a Trooth witness statement

Version 1.0, October 6, 2026. Normative for `trooth verify` and for any other implementation.

Trooth signs one object: the **witness statement** for a reading it took of a company's public surface. Everything else on a Trooth profile is unsigned. This document says how to check a witness statement without trusting Trooth's website, API or any summary of the result. An implementation that follows it must reach the verdict given for every case in [`tests/vectors/vectors.json`](../tests/vectors/vectors.json).

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
4. Parse `payload` as JSON. Its `statement` field MUST be `trooth.witness-statement.v1` or `trooth.witness-statement.v2`; otherwise the result is `malformed`.
5. Find the key whose `kid` equals `key_id`. Decode `public_key` as hex when `encoding` is `hex`, as base64 when it is `base64`. It MUST be 32 bytes.
6. Check the Ed25519 signature (RFC 8032, pure EdDSA) over the payload bytes. The result is `valid` or `invalid`. An unknown `key_id` gives `invalid`.

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

**Count identities.** For both versions, `counts.read` MUST equal the number of checks whose `outcome` is not `not read`, and `counts.as_expected` the number whose outcome is `as expected`. Every outcome MUST be one of `as expected`, `not as expected`, `not read`. For v2 additionally:

- `read + not_read = in_reading`, `as_expected + not_as_expected = read`, `in_reading` = the number of checks, `subject_scope.checks_in_scope` = the number of checks;
- every check other than `as expected` carries a `reason` whose `code` is one of the codes below and goes with that outcome; a reason marked `withheld` publishes no `source_ref` and gives a `withheld_reason`.

| Reason code | Goes with |
|---|---|
| `source_unavailable`, `timeout`, `evaluator_limitation`, `carried_from_earlier_reading`, `check_misconfigured` | `not read` |
| `contrary_observation`, `expected_item_absent` | `not as expected` |

**Subject.** When a domain is given, the payload's `domain` MUST equal it. A genuine statement about another domain is a mismatch (vector `domain-mismatch`).

**Mapping (v2).** `sha256:` followed by the lowercase hex SHA-256 of the exact mapping bytes MUST equal `methodology.mapping_digest`.

**Manifest (v2).** Sort the entries by `check_id` (code-unit order); no `check_id` may appear twice. Serialize as a JSON array with no whitespace, each entry as `{"check_id":…,"source":…}` or `{"check_id":…,"commitment":…}` in that key order. `sha256:` plus the hex SHA-256 of those UTF-8 bytes MUST equal `evidence_manifest.digest`, and the number of entries MUST equal `evidence_manifest.entries`. A `commitment` is `sha256` over `salt || 0x0A || private reference`; only its holder can open it.

A v1 statement binds no mapping, manifest, evaluator or subject scope.

## 5. The verdict

| Verdict | When | `trooth verify` exit code |
|---|---|---|
| `checked` | v2: signature valid, key trusted, counts hold, subject matches (or no domain given), mapping and manifest both match | 0 |
| `checked_v1` | v1: signature valid, key trusted, counts hold, subject matches | 0 |
| `partially_checked` | Everything checked held, but the mapping or the manifest was not supplied. Not supplied is never reported as a match | 4 |
| `signature_not_trusted` | Malformed, invalid signature, or key not trusted | 8 |
| `mismatch` | Signature trusted, but counts disagree, the domain differs, or a supplied mapping or manifest does not match | 9 |

## 6. What a `checked` verdict does and does not mean

It means Trooth's key signed these outcome bytes, for this domain, together with the digest of the exact check mapping, the evaluator version, the subject scope and the digest of the evidence manifest. It does not establish the company's identity, that the signed time was independently established, that anything outside the reading is true, or that the company is safe, compliant or authorized for any transaction. What to do with a checked reading is the reader's decision.

## 7. Limits of this version

- The signed bytes use a fixed key order, not RFC 8785 (JCS). A later version will move to JCS or COSE; this document will say so and keep v1 and v2 checkable.
- Witness statements are not yet entered in a public transparency log, so there is no inclusion proof to check. That is the next phase of work.
- There is no external timestamp.
