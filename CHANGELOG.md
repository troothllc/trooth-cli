# Changelog

Each release of `trooth` on npm. The README's "Changed in" sections summarise the same entries.

## 0.16.3 (2026-10-09)

### Help for every command, a longer wait for public-record, slugs, and the exit codes in full

- docs/LOG.md 1.3 and docs/EVIDENCE.md: a public record statement is logged only for a company on the Trooth Network, at most once per domain per UTC day. Any other domain gets an unsigned observation that is never logged, and a domain that does not exist is not read. Until October 9 any request could add an entry; entries 62 to 64 came from Trooth's own testing on October 8 and stay, as the log is append-only.
- `trooth <command> --help` and `-h` work for every command and nested subcommand: `check`, `lint`, `verify`, `log` (`checkpoint`, `monitor`, `receipt`), `mirror`, `public-record`, `mcp-tools`, `guard` (`decide`, `hook`, `ci`, `cache`) and `declare` (`init`, `sign`, `check`). Each prints that command's usage, what it does, its flags, every exit code it uses and examples, on stdout, and exits 0, before any other argument is checked (so `trooth guard decide --policy missing.yaml --help` is help, not an error). `trooth help <command> [<subcommand>]` and `trooth --help <command>` print the same; `trooth help <unknown>` exits 2. Up to 0.16.2 every `trooth <subcommand> --help` exited 2 with "unknown flag --help". A usage error now points at the command's own `--help`.
- `public-record` waits up to 45 seconds for each request instead of 15: a first (cold) reading of a domain is taken live and took 23 to 30 seconds in testing, so 0.16.2 timed out on it. `--timeout <seconds>` (1 to 600) sets the deadline; `TROOTH_TIMEOUT_MS`, when set, still sets every command's. On a terminal, a note on stderr after 5 seconds says a reading is in progress (`TROOTH_PROGRESS=1` shows it anywhere, `0` never). A reading that runs out of time says that a finished reading is cached for a day, so a second run usually answers at once, and the `--json` error carries `timeout_ms`. Every other command keeps 15 seconds.
- `check`, `verify` and `public-record` accept a Trooth slug where the server API does, as the MCP connector and the A2A agent already did ("domain or Trooth slug"). Input that is not a domain and is a bare name (`trooth`) is resolved on the record projection, `GET /api/network/profile?q=<slug>&contract=2`, and used only when the record found carries exactly that slug; stderr names the domain it resolved to. A record the projection matched by name is offered as a suggestion (`The closest record is Acme Cloud, acme.example: trooth verify acme.example`), never used. A slug no record carries, or one that names more than one record, exits 2 and says to pass the domain; a projection that cannot be read exits 3. A domain is never read as a slug, `localhost` and other reserved single labels never are, and `verify --offline`, `verify --bundle`, `declare check` and `guard` take domains only.
- `guard decide --json` for a tool the policy does not cover printed `{"covered": false, "tool", "policy", "note"}`, which `schemas/guard-decision.v1.schema.json` did not describe. The output is unchanged; the schema now carries it as `GuardNotCovered` (`$defs/notCovered`), and the new `schemas/guard-decide-output.v1.schema.json` accepts exactly a `GuardDecision` or a `GuardNotCovered`. The generated TypeScript, Pydantic and Go types include both (`GuardDecideOutput`); scripts/gen-types.mjs now writes a boolean literal as `Literal[False]` in Python and `bool` in Go.
- The exit codes are documented as the source uses them, after an audit of every exit path in bin/: the README table gains 20, 21 and 22 and lists, per code, every command that uses it (1 for `verify` with no record, `public-record` with no SEC filer or LEI named, `log receipt` with no such entry, `mcp-tools` with no reading, `guard cache` with no record; 6 for `verify`; 9 for `log checkpoint` and `mirror`); docs/VERIFY.md section 5 lists `verify`'s non-verdict exits (1, 2, 3, 5, 6, 7); docs/EVIDENCE.md, docs/MIRRORS.md (3 for a mirror that cannot be read), docs/LOG.md and docs/GUARD.md say the same; `trooth --help` lists every code by command.
- `--witnesses`: the examples in the README and docs/LOG.md now say plainly that no witness follows the log yet, so every checkpoint carries no cosignature and `--witnesses 2` (or any value above 0) exits 9 today. The flag is unchanged.
- Help text: `--log-vkey` is listed for every command that takes it (mirror and guard were missing), and `--timeout`, `--timeout-ms`, `--from`, `--check` and `--help` are listed; the exit codes in `trooth --help` are in order and complete.
- New `tests/cli-0163.test.mjs` in `npm test`: help for every command and subcommand, help in any position and with `--json`, help topics, every listed exit code defined and in the README table, `verify --help` against docs/VERIFY.md, slugs (resolution, name matches, ambiguity, unknown slugs, an unreachable projection, offline), `--timeout` validation and expiry, the 45-second default against an answer that takes 16.5 seconds, and the progress note. tests/guard-cli.test.mjs validates every `guard decide --json` output (allow, hold, deny, offline, uncovered) against the output schema.

## 0.16.2 (2026-10-08)

### An independent advisory panel

- docs/GOVERNANCE.md section 8: the charter of an independent advisory panel, with three seats (cryptography and transparency logs, identity, buyer risk). It covers who may serve, what members do (comment on format changes, a yearly note published unedited, and review of a reopened correction case at a party's request), how Trooth answers, and how to apply. All three seats are open.
- Section 9: a public list of outside input on the formats. The IANA requests for `trooth.json` and `_trooth-key`, sent on 2026-10-08, are the first two entries, both pending. No code changed.

## 0.16.1 (2026-10-08)

### How the formats change

- New `docs/GOVERNANCE.md`: the public change process for Trooth's formats. It covers RFCs opened as issues (acknowledged within 5 business days), comment periods of 30 days for a change that alters results and 14 for an addition, written decisions and credit, major and minor versions, migration windows (the old version is produced for at least 6 months and checked for at least 12), and deprecation (at least 90 days' notice). The api.trooth.co contract keeps its own policy at trooth.co/api-versioning.
- New issue template `.github/ISSUE_TEMPLATE/rfc.yml`. No code changed.

## 0.16.0 (2026-10-08)

### Mirrors of the witness statement log; IANA considerations for the discovery file

- New `trooth mirror <dir> [--from <url|dir>]` (bin/lib/mirror.mjs, docs/MIRRORS.md): reads the log's signed checkpoint, checks it with the pinned log key, reads every entry bundle, recomputes the root (RFC 9162) and writes nothing unless it is the signed root. Hash tiles are derived from the entries; the checkpoint is written last. A second run accepts only a tree whose first entries hash to the root the mirror already holds, so a mirror never shrinks and never takes a rewritten history (exit 9, mirror untouched). `--from` copies from another mirror with the same checks.
- New `trooth mirror --check <dir|url>`: a mirror is compatible when its checkpoint is signed by the log key, its entries hash to the checkpoint's root, every hash tile it serves is the one its entries make, and the live log extends it (same root at the same size, or a consistency proof). A live log smaller than a faithful mirror is reported: it is evidence of a split view or a lost tail. Named URLs must be https (loopback http is allowed, for testing).
- New `tests/mirror.test.mjs` in `npm test`: tile paths, bundles, multi-level tiles, and the command end to end against a loopback log (growth, a forked source, a changed entry, a wrong or missing tile, a mirror ahead of the log, a mirror of a mirror).
- New `.github/workflows/log-mirror.yml`: a daily mirror on GitHub's runners, checked and kept as an artifact. It runs in Trooth's own organization and is not an independent mirror.
- docs/DECLARATION.md section 8: the Well-Known URIs registration (RFC 8615) for `trooth.json` and the RFC 8552 registration for `_trooth-key`, and the versioning rule for `trooth.declaration`. Neither registration has been submitted.

## 0.15.0 (2026-10-07)

### guard ci reads destinations, not dotted keys; fuzzing, CodeQL and a threat model; the pilots as nightly CI; Phase 4 exit as amended

- `trooth guard ci`: a new rule for what counts as a destination (bin/lib/guard-ci.mjs, docs/GUARD.md section 7). Run on the trooth.co repository, 0.14.0 reported 323 i18n keys and dotted identifiers as hosts (`"page.docs.cli.guardTitle"`, `"lib.changelog.e2026.name"`, `"x.open"`, `"y.next"`, `"z.link"`), because any quoted dotted string counted and many key endings are real top-level domains. Now a destination is the host of an http, https, ws or wss URL, always; or a bare host name only when it is the whole value of a host-like key or argument (host, hostname, domain, endpoint, url, base_url or baseURL, origin, webhook, to, from, redirect, server, api, matched on the key's last word) in YAML, JSON, TOML, .env, a JavaScript object literal or a command-line flag, quoted when it is in source code, written in lowercase letters, digits, dots and hyphens with at least two labels, and ending in a suffix from the curated `PUBLIC_SUFFIXES` list in the module. Prose files are still not read; IP literals, localhost and the reserved example names are still skipped.
- New `tests/guard-fuzz.test.mjs`, in `npm test`: seeded, dependency-free property-based testing of `parsePolicy` (YAML and JSON: mutated, truncated and byte-flipped valid policies, random bytes, deep nesting, huge strings and numbers, Unicode look-alikes, prototype keys), of the decision path (random facts through `decideFrom`, random cached bundles through `factsFromBundle`), of an offline guard and of the hook. About 80,000 cases in under 20 seconds. Four defects it found are fixed: deep nesting in a policy exhausted the stack with a RangeError instead of a PolicyError (nesting is now limited to 64 levels, and `parsePolicy` throws only PolicyError); `decideFrom` read some facts loosely (now a field that is not exactly the value that shows the evidence counts as missing, and a malformed claim is not cited); an `applies_to.http` method given as a list passed through `String()`; a tool name or host with no String form threw instead of being decided.
- GitHub CodeQL scans the repository through GitHub's default code scanning setup, on every push, pull request and weekly. (A separate codeql.yml shipped with the release and was removed the same day: GitHub refuses an advanced CodeQL workflow while the default setup is on, and the default setup scans the languages GitHub detects in the repository.)
- New `docs/GUARD-THREAT-MODEL.md`: assets, trust boundaries, attacker capabilities, threats mapped to the code and tests that answer them, residual risks, and the review status.
- The Trooth-run pilot harness is in `pilots/` (paths relative to this repository), and the new `.github/workflows/guard-pilots.yml` runs it every night and on demand against the latest releases of @openai/agents, @langchain/langgraph, langchain, @langchain/core, openai-agents and crewai, with no secrets and no model key, failing on any failed step and uploading the logs.
- This repository's own Claude Code sessions run `trooth guard hook` before consequential tools (`.claude/settings.json`, `.trooth/guard-policy.yaml`).
- docs/GUARD.md section 13, "Phase 4 exit, as amended on 2026-10-07": by the founder's decision for confidentiality before launch, an internal review gate stands in place of an outside review before launch, and Trooth as the first production user stands in place of three outside teams before launch. An outside security review and outside production use move to the launch phase; neither has happened. docs/GUARD-PILOTS.md and docs/GUARD-ADAPTERS.md updated to match; docs/GUARD-RESULTS.md rerun.

## 0.14.0 (2026-10-07)

### Proof methods, the domain-signed declaration, and the remaining first-class subjects

- New `trooth declare` command and `trooth/declaration` library (docs/DECLARATION.md). `declare init --domain <d> [--key <path>]` makes an Ed25519 key with node:crypto and saves it as a private JWK (default `~/.trooth/declaration-key/<domain>.jwk`, mode 0600, never overwritten, never printed). `declare sign` writes a signed `trooth.declaration.v1` document (Ed25519 over the RFC 8785 bytes without `signature`; the key named `<domain>#<RFC 7638 thumbprint>`) with the company's Trooth record, products, APIs with an MCP manifest hash, and repositories, valid for at most 400 days, and prints the `_trooth-key.<domain>` TXT pin line. `declare check <domain>|--file <path>` fetches `https://<domain>/.well-known/trooth.json` (no redirects, 64 KB, a deadline) or reads a file, checks every rule, and reads the pin over DNS over HTTPS. Exit 0 checks, 1 none published, 3 not read, 8 signature or key, 9 another rule or a pin naming another key, and the new 11 expired.
- Schemas: new `declaration.v1`; `public-record.v1` gains (optional) `proofs` and `declaration`, the proof methods `dns_txt`, `domain_signed_declaration`, `identity_provider_sign_in`, `domain_email_code` and `repository_control` on bindings and proofs, the subject kinds `company`, `product` and `person`, the continuity events `declaration_appeared`, `declaration_key_changed` and `declaration_disappeared`, and the evidence classes `domain_declaration` (30 days) and `trooth_claim_record` (365 days). Types regenerated for TypeScript, Python and Go.
- Ids (`docs/IDS.md` 1.5): `company` (slug), `product` (`<domain>/<id>`), `person` (16 lowercase hex), and `key` values of the form `<domain>#<thumbprint>` for a company's own key.
- `trooth public-record` prints each proof (method, status, what it binds) and the declaration line.
- The guard: `domain_control_confirmed` is now a signed claim, derived from the signed public record: present when a proof binding the domain to the company record or to its declaration key is `confirmed` by `dns_txt`, `domain_email_code`, `identity_provider_sign_in` or `domain_signed_declaration`; fresh for `trooth_claim_record` (365 days) or `domain_declaration` (30 days). docs/GUARD.md section 4 updated.
- docs/DECLARATION.md (new), docs/EVIDENCE.md 1.4 (section 11), docs/GUARD.md, docs/GUARD-RESULTS.md (rerun).
- The guard's adapters were run against the real framework packages in three Trooth-run pilots (docs/GUARD-PILOTS.md: @openai/agents 0.19.0 and openai-agents 0.20.0, @langchain/langgraph 1.4.21 and langchain 1.5.15, crewai 1.15.24, and the Claude Code hook). Four defects they found are fixed: `guardDecisionOf(err)` finds the Decision inside framework error wrappers; LangGraph routing requires `toolsGoto` (a static edge from the guard node let a denied call run); the Python `needs_approval` no longer fails on a tool the policy does not cover; the CrewAI task guardrail is accepted by `Task`. These are pilots Trooth ran itself; they are not production use by outside teams and not an outside review, and both of those Phase 4 conditions stay open.

## 0.13.0 (2026-10-07)

### The guard: an open pre-execution check for consequential agent actions

- New `trooth/guard` library and `trooth guard` command (docs/GUARD.md). It runs inside the customer's agent. Before a consequential tool call (a payment, a contract signature, sending data out, installing an MCP server), it looks up the counterparty's domain, checks Trooth's signed records locally (RFC 8785 bytes, Ed25519 signature, the key's status at signing time, log inclusion against the pinned log key, cosignatures by pinned witnesses, freshness, the subject is the host being called) and applies the customer's written policy. It answers allow, hold for a person, or deny, with reason codes, as a `guard-decision.v1` document. Missing, stale or disputed evidence holds; only a failed proof or a rule the customer marked absolute denies; an unreachable source with no cached bundle holds. It never fails open, never follows a link found in vendor content, and never sends the action to Trooth.
- Policies are data (`guard-policy.v1`, YAML or JSON). Claims come only from signed, logged records: `trooth_reading` and `check:<id>` from the witness statement; `legal_entity_registry_record`, `no_sanctions_name_match`, `no_sam_exclusion_name_match`, `domain_registration_record` and `security_txt_published` from the public record, each with the freshness of its evidence class. `domain_control_confirmed` is not a signed claim today, so a rule requiring it holds.
- `trooth guard decide` (exit 0 allow, 20 hold, 21 deny; a tool the policy does not cover decides nothing and exits 0), `trooth guard hook` (a Claude Code PreToolUse hook: hold asks a person, deny exits 2), `trooth guard ci` (exit 22 when a change adds a destination host the policy does not list) and `trooth guard cache` (signed bundles for offline use).
- Adapters: `trooth/guard/openai-agents`, `trooth/guard/langchain`, `trooth/guard/langgraph`, `trooth/guard/http`, and the Python package `trooth_guard` (CrewAI, LangGraph, LangChain, OpenAI Agents) over the CLI (docs/GUARD-ADAPTERS.md). Duck-typed: no framework package is a dependency.
- The decision table is checked exhaustively in `tests/guard-model.test.mjs` (4,534,272 input combinations) and by TLC on `spec/GuardDecision.tla`; an adversarial suite (injection in vendor text, spoofed records, a malicious tool description, replayed, revoked and compromised keys, confused-deputy hosts, policy bypass, forged log proofs, corrections, unreachable sources) runs in `npm test`. Results in docs/GUARD-RESULTS.md.
- Public record (scan worker): `bindings[].proof_method`, `evidence_classes` (each with its stale-after days and what it does not establish), `continuity` against the previous reading (a changed entity is never merged), and the subjects `representative` and `signing_authority`. Schema `public-record.v1` gains them (optional); `docs/EVIDENCE.md` 1.3; id type `contact` (`docs/IDS.md` 1.4).
- Open: the guard has not had an outside security review, and it is not yet used in production by teams outside Trooth. Both are Phase 4 exit conditions; neither is claimed.

## 0.12.0 (2026-10-07)

### MCP tool description hashes, the rest of the public record, and the hardware key

- New command `trooth mcp-tools [endpoint] [--live] [--json]`. Without an endpoint it lists the MCP servers whose tool lists Trooth reads (`https://api.trooth.co/scan/mcp-tools`). With one it reads Trooth's newest reading, recomputes each tool's `description_sha256` and the `manifest_sha256` from the definition hashes, checks the reading's RFC 8785 SHA-256, the `trooth.mcp-tools.v1` statement and its key, and the log receipt. `--live` reads the server's tool list from this machine (streamable HTTP, no credentials) and reports tools added, removed or changed since Trooth logged them. Exit 9 on any difference, 8 when the signature or key does not hold, 4 when the server could not be read. `bin/lib/mcp-tools.mjs` holds the hashes and a small MCP client.
- Log entries gain the kind `mcp_tools`. The Python and Go packages accept it.
- `trooth public-record` prints the reading's new sections: `sam` (SAM.gov registrations and exclusions, exact legal name), `patents` (USPTO Open Data Portal applications by first applicant), `registries` (New York, Colorado, Connecticut and Oregon open-data registries, exact legal name), `merger_review` (FTC early termination notices), `domain_registration` (RDAP), `changes` (renames, Items 2.01 and 5.01, previous legal names, parents, merger notices, domain events) and `subjects`.
- `trooth log checkpoint` reports the hardware key's signature line (`hardware_key` in `--json`), checked against `HARDWARE_LOG_VKEY` in `bin/lib/log-trust.mjs`.
- Ids (`docs/IDS.md` 1.3): `jurisdiction`, `registry`, `uei`, `repo`, `api`, `mcp`.
- Schemas: `public-record.v1` gains the new sections (all optional for older readings); new `mcp-tools.v1` and `mcp-tools-statement.v1`. Fixtures: a reading of nvidia.com built by the scan worker's reader, and a signed reading of Trooth's own MCP server built by the scan worker's code.
- `docs/KEY-CEREMONY.md` 1.2 (ceremony v2: the hardware key in AWS KMS, which co-signs every checkpoint; why two-person control is not adopted and what stands in its place; drill 4), `docs/LOG.md` 1.2, `docs/EVIDENCE.md` 1.2 (sections 7 to 9).

## 0.11.0 (2026-10-07)

### Witnesses, COSE receipts and a signed public record

- The log asks the staging witnesses of the witness network (Geomys, Mullvad, TrustFabric) to cosign its checkpoints over c2sp.org/tlog-witness and serves their cosignatures as further signature lines on `/checkpoint`; `/witnesses` says what each last did. `bin/lib/log-trust.mjs` pins their Ed25519 cosigner keys. `trooth log checkpoint` and `trooth log monitor` report which cosigned (the monitor also saves them), and `--witnesses <n>` exits 9 when fewer did. A witness answers 404 until the witness network follows the log, so the first checkpoints carry no cosignature.
- `trooth log receipt <index> [--out <file>]` fetches `/receipt/<index>`, an RFC 9942 COSE receipt of inclusion (COSE_Sign1, EdDSA, vds RFC9162_SHA256, detached payload), checks it against the entry and the pinned log key, and confirms `https://api.trooth.co/.well-known/scitt-keys` (a COSE Key Set, kid = RFC 9679 thumbprint) lists that key. `bin/lib/cose.mjs` holds a small CBOR reader and the check.
- Log entries gain the kind `public_record`. The Python and Go packages accept it.
- `trooth public-record` checks the `signed` block each reading now carries: the reading's RFC 8785 SHA-256 (`canonicalizeRecord` in `bin/lib/jcs.mjs`, which writes non-integer numbers in ECMAScript's shortest form), a `trooth.public-record.v1` statement signed with a key trusted at `issued_at`, and its log receipt. Exit 8 when the signature or key does not hold, 9 when the reading is not the one named or the receipt does not check. `--log-vkey` checks the receipt against another log key. `--json` adds `cli_check`.
- The reading adds `entity` (`trooth:entity:lei:<LEI>` or `trooth:entity:cik:<CIK>`, `docs/IDS.md` 1.2), `certificates` from Certificate Transparency logs, `security_txt`, `site.links` (investor relations, trust center, security, status, sustainability: linked, not read), `sanctions` (exact-name check against the OFAC SDN list; a name match is not an identification) and `sources` (each response read and the SHA-256 of its bytes). The output's financial labels are no longer cut short.
- Schemas: `public-record.v1` gains those fields (all optional for older readings); new `public-record-statement.v1`. 57 generated types.
- `docs/LOG.md` 1.1 (witnesses, COSE), `docs/EVIDENCE.md` 1.1 (new sources, the signed statement), `docs/KEY-CEREMONY.md` 1.1 (drills; a witnessed log changes key by changing origin; what hardware custody and two-person control need). `tests/vectors/witness-cose.json`: 6 cosignature cases and 9 COSE receipt cases, which Trooth's log reproduces byte for byte.

## 0.10.0 (2026-10-07)

### The public record: what a company publishes outside its own site

- New command `trooth public-record <domain> [--cik N] [--lei X] [--ticker T] [--json]`, reading `https://api.trooth.co/scan/public-record/<domain>`. It shows the SEC filer record (name, CIK, tickers, exchanges, filer category, SIC, state of incorporation, fiscal year end, address, website on file, former names), the latest 10-K, 10-Q, 8-K, DEF 14A, 20-F and others with links, two years of 8-K filings with their item numbers, material cybersecurity incidents (Item 1.05), auditor changes (4.01) and non-reliance (4.02), the count of insider forms in 90 days, and annual revenue, net income and total assets as filed in XBRL; the GLEIF LEI record and its parents; and DMARC policy, MTA-STS and its mode, SMTP TLS reporting, BIMI and DNSSEC.
- Each identifier is a binding with evidence for and against. It is `corroborated` only when the company's own annual filing declares its XBRL extension taxonomy under the domain, the SEC record lists the domain, or (for an LEI) the LEI record agrees with a corroborated filer. A site that states a company's legal name is `claimed_by_site`: any site can copy a copyright line.
- `docs/EVIDENCE.md`: who-said-it classes (company declaration, Trooth observation, regulator filing, registry record, DNS record, public source), the full inventory of what a company publishes on its site, with regulators and registries, and through others, with what Trooth reads of each today, and the binding rules.
- Schema `public-record.v1.schema.json`, generated TypeScript, Pydantic and Go types; `trooth:cik:` and `trooth:lei:` ids (`docs/IDS.md` 1.1). The type generator now handles unions, numbers and Python keyword field names.
- Exit 0 when an identifier was found, 1 when none was, 2 for usage, 3 when the reading could not be had (including its rate limits).

## 0.9.0 (2026-10-06)

### The witness statement log, corrections and monitoring

- Trooth now enters every published witness statement, and every correction it issues, in one append-only log at `https://api.trooth.co/scan/log/v1`: an RFC 9162 tree (SHA-256, 0x00 leaves, 0x01 nodes), a C2SP checkpoint signed as a C2SP signed note with an Ed25519 key that signs nothing else, and C2SP tlog-tiles. A reading that was never published is never logged. `docs/LOG.md` is the normative text.
- `trooth verify` asks the log for the statement by its statement id and for corrections naming it, checks the receipt against a checkpoint signed by the log key pinned in `bin/lib/log-trust.mjs`, and reports `included`, `not_logged`, `unavailable`, `checkpoint_invalid` or `proof_invalid`. The last two make the verdict `mismatch`. `not_logged` and `unavailable` change nothing in this version.
- Corrections: `trooth.correction.v1`, signed like a v3 statement and logged. A correction that names the statement, is signed by a key trusted at `issued_at` and is itself included in the log makes the verdict `superseded` (new exit code 10). Others are reported and not relied on.
- `--no-log` skips the log; `--log-vkey <key>` checks checkpoints against another key. `--save-bundle` writes the log's answer into the bundle, and `--bundle` checks it offline, with the pinned key replacing the key the bundle carries.
- New `trooth log checkpoint` and `trooth log monitor --state <file>`: the monitor saves the checkpoint it saw and, on each later run, verifies a consistency proof from it; a log that shrank, forked or cannot prove it grew exits 9 and the saved state is kept. `.github/workflows/log-monitor.yml` runs it hourly in public.
- `docs/KEY-CEREMONY.md`: how the statement key and the log key are made, held, rotated and revoked, what is in place now and what is planned.
- `docs/VERIFY.md` 1.2. Schemas: `log-receipt`, `correction-payload.v1`; `verification-bundle.v1` gains an optional `log`; `verify-result` gains `log` and `superseded`. The package exports `trooth/tlog`.
- Python `trooth-verify` 0.2.0 and the Go package check receipts, consistency proofs and corrections, and run every log vector. `tests/vectors/log.json` holds 13 statement cases with a log answer and 7 consistency cases; Go's `golang.org/x/mod/sumdb/note` and `sumdb/tlog` agree with its checkpoints, roots and proofs.

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
