# Changelog

Each release of `trooth` on npm. The README's "Changed in" sections summarise the same entries.

## 0.8.0 (2026-10-06)

### Bundles, statement v3, schemas and SDKs

- `trooth verify <domain> --save-bundle <file>` writes a `trooth.verification-bundle.v1` file: the statement as published, the evidence manifest, the key list with the time it was read, and the mapping document as base64 of its exact bytes. It refuses to overwrite an existing file. `trooth verify --bundle <file>` checks such a file and sends nothing; it cannot be combined with `--file`, `--keys`, `--mapping`, `--manifest` or `--save-bundle`. A domain given on the command line replaces the one the bundle names. Output from a saved key list says when it was read.
- Every result carries `statement_id`, `trooth:statement:` plus the SHA-256 of the exact payload bytes. `docs/IDS.md` defines the `trooth:<type>:<value>` grammar for domains, readings, statements, keys, mappings and (reserved) entities; `bin/lib/ids.mjs` implements it.
- Statement v3 (`trooth.witness-statement.v3`) is checked: the envelope names `RFC8785`, the payload bytes must equal their RFC 8785 canonical form (integers only, so every implementation agrees), `signer.key_id` inside the payload must equal the envelope's `key_id`, and `subject_id` must name the payload's domain. `bin/lib/jcs.mjs` implements the profile. Trooth's witness worker still signs v2; v1 and v2 check exactly as in 0.7.0. `docs/VERIFY.md` is version 1.1.
- `schemas/` holds JSON Schema 2020-12 for the envelope, payloads v1, v2 and v3, the key list, the evidence manifest, the bundle and the `--json` result, with a description on every field. `scripts/gen-types.mjs` generates `types/trooth.d.ts`, `sdk/python/trooth_verify/models.py` and `sdk/go/trooth/types.go`; `tests/schemas.test.mjs` validates every vector, every bundle, a real trooth.co bundle and the CLI's own output, and fails when a generated file is stale.
- The package can be used as a library: `trooth/verify`, `trooth/jcs`, `trooth/ids` and `trooth/schemas/*`, with TypeScript declarations. The one dependency is unchanged.
- `sdk/python` (`trooth-verify`, depends on `cryptography`) and `sdk/go` (standard library only) implement the same checks and run every vector and bundle. CI runs both.
- Vectors: 9 new (valid v3, v3 not canonical, a fraction, the wrong canonicalization label, a signer that differs from the envelope, a tampered v3 payload, a subject id that disagrees, a v3 domain mismatch, v3 with no manifest), 27 in all; `tests/vectors/bundles.json` adds 7 bundle cases.

## 0.7.0 (2026-10-06)

### `trooth verify`: check the signed reading yourself

- New command. It reads the record's witness statement, the published key list and the check mapping the statement names, and checks on your machine: the Ed25519 signature over the exact payload bytes; the key's lifecycle (active, retired before the statement's time, compromised, revoked, unknown); that the statement was signed for the domain asked about; the count identities; and for v2 the SHA-256 of the exact mapping bytes and of the canonical evidence manifest. It trusts no summary from Trooth.
- `--file` reads a saved profile, `{statement, manifest}` or a bare statement; `--keys`, `--mapping` and `--manifest` read saved inputs; `--offline` sends nothing and requires `--file` and `--keys`.
- Verdicts: `checked` and `checked_v1` exit 0; `partially_checked` (mapping or manifest not supplied) exits 4; a record with no statement exits 5; `signature_not_trusted` exits 8 (new); `mismatch` exits 9 (new).
- The rules are written down in `docs/VERIFY.md`, shipped in the package. `tests/vectors/vectors.json` holds 18 cases (valid v1 and v2, hex and base64 keys, tampered and re-serialized payloads, wrong and unknown keys, compromised, revoked and retired keys, mapping, manifest, domain and count mismatches, malformed signatures and algorithms), signed with test keys whose seeds are public in `generate.mjs`. `generate.mjs --check` proves the file is reproduced byte for byte.
- `tests/verify.test.mjs` runs every vector through the core and the CLI end to end in offline mode.
- `check` is unchanged except its closing line, which now names `trooth verify`.

## 0.6.1 (2026-10-04)

Fixes from the audit of 2026-10-04 (O04, N01, N02, N03, N04). Not yet published to npm.

### The GitHub Action installs into a fresh directory on every run (V10)

- Up to this release `action.yml` reused `$RUNNER_TEMP/trooth-cli-<version>` whenever a `trooth.mjs` already existed there and checked only the version string in that directory's `package.json`. A file already written at that path (an earlier step, or a reused self-hosted runner) ran in place of the registry's package. Each run now installs into its own `mktemp -d` directory readable only by the runner user, so only what npm installed (each tarball checked against the registry's integrity value) runs. The Action still pins 0.5.1 by default; this change is in the Action itself.

### Output is delivered whole, or the exit code says it was not (O04)

- Up to 0.6.0 a command wrote its output and called `process.exit` at once. When stdout is a pipe, Node queues the write, and the forced exit dropped what was still queued: a piped reader of `check --json` could get the first part of a large record, invalid JSON, with exit 0. Nothing calls `process.exit` now. Each command returns its exit code to one dispatcher, which waits until every write to stdout and stderr has been handed to the operating system, then sets `process.exitCode` and lets Node end on its own. This covers every path: the record, the withheld and absent answers, the labelled fallback, error documents from usage and service errors, and `lint` reports.
- New exit code 7, output not delivered. When stdout or stderr fails (EPIPE from a reader that closed early, a full disk), nothing more is written to that stream, a one-line note goes to the other stream when it still works, and the exit code is 7 in place of the command's own code. A partial document never carries a success code. No stack trace is printed.
- The exit codes 0 to 6 and `signature_checked: false` are unchanged.
- `tests/output-delivery.test.mjs` runs the CLI as a child process against a loopback record server at four output sizes (small, exactly 64 KiB, about 300 KB, just under the 2 MiB body limit), captured through a socket pipe, a kernel pipe, a file and a slow reader that pauses after every chunk, and checks that every success parses, ends with its final field and equals the served record. It also covers an early close, a full device, a large `lint` report with exit 4 and the eight canonical record cases. It was run on Linux with Node 22; other operating systems and Node versions were not run for this release.
- The GitHub Action treats an exit code it does not define as a failure to produce a report, so a 7 fails the step. The Action still installs 0.5.1 by default.

### `lint`: malformed nested declarations are invalid, not complete (N01)

- A Kubernetes `List` (or another `*List` kind that carries `items`) whose `items` is missing or is not an array is invalid. An empty `items: []` is still a valid, empty List.
- In `.tf.json`, `resource`, each resource type and each resource body must be an object or an array of objects; a string, a boolean, a number or null there is invalid. `"//"` comment keys are still allowed. A key repeated within one JSON object is invalid.
- In `.tf`, an attribute set twice in one body, or a key repeated in one object constructor, is invalid. Up to 0.6.0, `encrypted = false` followed by `encrypted = true` was read as declaring encryption. Repeated blocks of one type are still allowed.
- Each case is listed under `coverage_details.invalid` with a reason that names a path or line, never a value. The read is incomplete and exits 4, and the valid files beside it are still read.

### `lint`: plan values unknown until apply are unresolved (N02)

- A plan marks a value Terraform learns only at apply time with `true` in `change.after_unknown`, and in `proposed_unknown` when present. Those marks are now merged into each resource, by full address, before anything is counted, in both the `resource_changes`-only form and the `planned_values` form, including nested modules and nested attributes. Encryption that is unknown is counted under `storage_encryption_unresolved`; up to 0.6.0 it was counted under `storage_encryption_not_declared`. Nothing is inferred from an unknown attribute that does not decide encryption.

### `lint`: HCL string escapes are decoded (N03)

- Quoted strings decode `\n`, `\t`, `\r`, `\"`, `\\`, `\uNNNN` and `\UNNNNNNNN`; an invalid escape or a Unicode escape that does not name a scalar value makes the file invalid, without echoing the digits. In quoted strings and heredocs alike, `$${` and `%%{` are the literal text `${` and `%{`, and only a live `${ }` or `%{ }` makes a string an expression. Backslashes stay literal in heredocs, as Terraform documents. `<<-` heredocs now strip their shared indentation. The same `$${` and `%%{` rule applies to `.tf.json` strings.
- A decoded constant stays a constant even when its text holds `${` or `$`, so `password = "$${...}"` is now counted as an inline credential literal, and `region = "us-east-\u0031"` is reported as `us-east-1`. Real interpolation is still unresolved. Credential values are still never printed.

### `lint`: Dockerfile logical lines (N04)

- Dockerfiles are now read in logical lines formed as BuildKit forms them: a line ending in the escape character continues on the next with nothing inserted between them, full comment lines and empty lines inside a continuation are dropped, CRLF reads like LF, and the `# escape=` parser directive (backslash or backtick) is honored at the top of the file. Up to 0.6.0 the reader inserted a space when joining and kept a comment line inside a continuation, so `ENV API_TOKEN=\` followed by a value on the next line was missed.
- `ENV` and `ARG` are then read as one or more `name=value` pairs, or the legacy `ENV name value` and `ARG name` forms, with quotes and escapes removed as the build removes them. A value with an unescaped `$` reference outside single quotes is unresolved. An instruction lint cannot read that way (a word without `=` among pairs, an unterminated quote, an `ENV` without a value, an unsupported escape directive) makes the file invalid. A `RUN` heredoc body is skipped, not read as instructions. The full list of assignments is kept, so an earlier literal is still counted when a later assignment replaces it (T18).
- `tests/audit-1004.test.mjs` holds the audit's nine declaration fixtures verbatim, with positive controls and the regression cases for N01 to N04.

### Changes to counts

- The same tree can count differently in 0.6.1, so its `facts_digest` can change: files that 0.6.0 read as complete may now be invalid, unknown plan encryption moves from not declared to unresolved, and decoded HCL strings and joined Dockerfile lines can add credential literals and regions.

## 0.6.0

### `check` reads the one record projection

- `trooth check <domain>` now sends `GET https://trooth.co/api/network/profile?q=<domain>&contract=2`. That route is the one public record projection. The website's record page, the REST API, the MCP server (`trooth_public_trust_profile`, `trooth_ai_data_use_disclosures`) and the llms.txt twin all read it, and the server validates it against [network-profile.v2.schema.json](https://trooth.co/schemas/network-profile.v2.schema.json) before sending it. Up to 0.5.1, `check` read `GET https://api.trooth.co/directory/api/vendors/<domain>`, a different body with different fields. So the CLI could not be held to the same contract as the other surfaces.
- The contract number is pinned in the request. A server that stops serving contract 2 refuses with 400, and the CLI exits 3 rather than misreading a new shape.
- `check --json` carries the projection body whole, under `record`. Each fact has its `key`, `category`, `label`, `value` and `origin`, its typed `claim` and its `record` (record version, issuer, source reference, freshness), exactly as the API serves them. `conflicts`, `witnessed`, `signing` and `methodology` come with it.
- `check --json` adds `source`. It says which surface answered (`record_projection` or `directory_fallback`), the URL read and the contract and schema. It also carries the record version: `record_version`, `record_digest` and `record_previous_digest` come from the `Trooth-Record-Version`, `Trooth-Record-Digest` and `Trooth-Record-Previous-Digest` headers, the same values the MCP server reports, and `record_updated_at` is the body's `updatedAt`. A value the server does not state is `null` and is never guessed.
- `check --json` also adds `slug`, `first_witnessed_at`, `coverage` (the last reading's counts, with their source), `facts_published` and `facts_contested`. `probes` and `authority_key_id` keep their 0.5 names: the same counts and the signing key id.
- From a projection read, `check --json` no longer emits `badge_id`, `attested`, `events`, `receipt_signature` or `first_published_at`, because the projection does not carry them. A fallback read still emits them.
- The human output prints the record version, the URL it read, the last reading's counts in the wording the MCP server uses, and every published fact under its category with the label of who stated or observed it. It also says what is signed.

### The fallback, labelled

- The directory feed is read only when the projection cannot be reached: a connection failure, the deadline, or a 5xx after one retry. A fallback answer is labelled as such in every mode. The human output starts with `FALLBACK READ.` and the reason, stderr says so, and `--json` carries `source.surface: "directory_fallback"`, `source.fallback: true` and `source.projection_error`, with `record_version: null`. The directory feed has no facts, no per-fact provenance and no record version.
- A 4xx, a contract mismatch, an ambiguous-name answer or a body that is not this domain's record is a contract error (exit 3). None of them triggers the fallback.
- New flag `--no-fallback`: an unreachable projection exits 3 and the directory feed is never read.

### Exit codes

- New: 6, withheld. The projection answered `found: true, withheld: true`: the record exists and is withheld while a report about it is reviewed. The reason is printed in Trooth's own words. This is neither an absence nor a finding.
- Exit 1 from a projection read means `found: false`: no published record.

### Environment

- New: `TROOTH_WEB`, the base URL of the record projection (default `https://trooth.co`). `TROOTH_API` now names only the fallback's base URL.

### Limits

- The projection's body limit is 2 MiB, the bound the server itself enforces before it sends (`PROFILE_RESPONSE_MAX_BYTES`). The directory feed keeps 1 MiB.

### Release provenance

- `.github/workflows/publish.yml` publishes on a version tag (`v0.6.0`) with `npm publish --provenance --access public`, authenticated by npm trusted publishing (GitHub OIDC, `id-token: write`). No npm token is stored in the repository. First the workflow checks that the tag equals `package.json`'s version and `trooth --version`, then it runs the metadata check and the test suite, then it prints the tarball. Publishing starts working once a maintainer registers the trusted publisher on npmjs.com: organization `troothllc`, repository `trooth-cli`, workflow `publish.yml`, no environment.

### Not changed

- `lint` is unchanged. `digest`, the 0.4 name of `facts_digest`, was to be removed in 0.6. It stays until 0.7, because the GitHub Action still exposes it as an output, and its `digest_scope` text now says 0.7.
- The GitHub Action's default `version` stays `0.5.1` until 0.6.0 is on the registry, because the action installs the version it names from npm.
