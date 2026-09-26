# trooth

The Trooth Network from your terminal. Published on npm as **`trooth`**.

Trooth operates the Trooth Network: one public, machine-readable record per company, carrying its identity, products and demos, commercial terms, domain and marketing links, people, documents, security and privacy posture, AI practices, procurement terms and relationships. It is Trooth's only product and it is free. Trooth signs one object in that record, the witness statement for a reading Trooth took of the company's public surface. The rest of the profile, including what the company declares about itself, is not signed.

DNS says where a company is. A TLS certificate says the connection is authentic. The Trooth Network says who the company is and what it does with your data.

This CLI is the terminal interface to that record. It does two things:

- `trooth check <domain>` reads a company's published record from the public Network. No key and no account. It sends one request to `api.trooth.co` with **the domain you ask about in the request URL**, plus what every web request carries: your IP address and a `trooth-cli/<version>` user agent. Trooth's servers can therefore see which domain you looked up; [trooth.co/privacy](https://trooth.co/privacy) and the [retention schedule](https://trooth.co/retention) say what is kept and for how long. Nothing else about you or your machine is sent.
- `trooth lint [path]` reads what your own infrastructure declares and prints those declarations as facts. Entirely local: it opens files and opens no sockets.

**Trooth witnesses and dates facts. It does not grade, rate or rank anyone.** The CLI prints counts, reported apart, and never adds them into one number.

## Install

```bash
# No install:
npx trooth check stripe.com

# Or install it:
npm install -g trooth
trooth --version
```

Node 18 or newer, because the binary uses the built-in `fetch`. One dependency, pinned to an exact version and locked in `npm-shrinkwrap.json`: [`yaml`](https://www.npmjs.com/package/yaml), the maintained YAML parser, which itself has none. It is there so Kubernetes files are parsed rather than pattern-matched. Install with `--ignore-scripts` if you like; neither package has an install script.

## Commands

| Command | What it does |
|---|---|
| `trooth check <domain>` | Reads a company's record from the live Network and prints its listing and evidence state, the date of the witnessed reading and of first publication, the live-probe and self-attestation counts, the badge id, the id of the signing key, and the three newest events in its ledger, newest first. `--json` adds the signature itself and every event the feed returns. It does not check the signature. |
| `trooth lint [path]` | Reads the infrastructure the given directory declares and prints those declarations, a coverage report and an aggregate digest of the counts. Local and offline. `path` defaults to `.`. |
| `trooth --help` | Help. Also `-h` and `help`. |
| `trooth --version` | Version. Also `-v` and `version`. |

## Flags

`--json` is the flag both commands take; `lint` also takes `--allow-incomplete`. With `--json`, stdout carries exactly one JSON document and nothing else, and every diagnostic goes to stderr. On an error the document is `{"ok": false, "error": "...", "exit": N}`; a non-2xx response adds `http_status`, and `lint` with nothing to read adds `files_opened`. `--help` and `--version` print plain text whether or not `--json` is given.

Any other flag is a usage error. The message names the flag, and for a `--` flag given to `check` or `lint` it also lists the ones that exist.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | `check`: listed, and the record carries a dated reading Trooth witnessed. `lint`: a complete read of at least one declaration. Help and version also exit 0. |
| 1 | `check`: not listed, or revoked. `lint`: nothing to read. |
| 2 | Usage error: a missing argument, an unknown flag or command, input that is not one domain, or a path that does not exist. |
| 3 | Service or contract error: Trooth unreachable or slower than 15 seconds, a status other than 2xx or the documented not-listed 404, a body over 1 MiB, a body that is not JSON, or a record for a different domain. Never an answer about a company. An unexpected failure inside the CLI also exits 3. |
| 4 | `lint`: the read was incomplete. A selected file was over the size limit, did not parse or could not be read, or the walk stopped at its file limit. `--allow-incomplete` reports the same and exits 0 (or 1 when nothing was read). New in 0.5.0. |
| 5 | `check`: the company is listed, but its record carries no reading this CLI can confirm Trooth witnessed. New in 0.5.0. |

A company with no record, a listed company without a witnessed reading, and a Network that could not be read are different answers, so they exit differently. A pipeline can tell them apart without parsing prose, and a Trooth outage never reads as a company with no record.

## `trooth check`

```bash
trooth check trooth.co
```

Example output. The values are illustrative; the shape is what the binary prints.

```
Trooth Network // public record · read-only //
Trooth, LLC   trooth.co
Listing state: listed; Trooth witnessed a reading   reading dated 2026-09-26   first published 2026-08-01

Live probes: 65 read; 63 as expected
Self-attestations: 35 asked; 27 attested
Live probes are readings Trooth took itself, from the company's public surface.
Self-attestations are what the company attested about itself; Trooth records them
and did not witness them. The two are reported apart and never added into one number.
Badge rw_...   Key trooth-master-2026-09

Latest ledger events, newest first
  • 2026-09-26  live probes re-read
  • 2026-09-26  reading completed
  • 2026-08-01  record published to the Trooth Network
  --json carries the whole ledger, with the feed's own wording for each event.

This command did not check the record's signature. The signature covers the
reading, not every fact on the company's profile. To check it yourself: https://trooth.co/docs/verifiable-evidence
A dated, point-in-time record. Trooth issues no verdict and no single number.
Full record: https://trooth.co/network/trooth.co   ·   Signing keys: https://api.trooth.co/public/keys
```

The line that begins `Listing state:` gives the listing and evidence state, decided from the record's own fields and never from a matching name:

| `state` in `--json` | Printed | Exit | Meaning |
|---|---|---|---|
| `listed_witnessed` | listed; Trooth witnessed a reading | 0 | The record carries a dated reading with at least one live probe read. |
| `listed_not_witnessed` | listed; no reading witnessed | 5 | The record says it was not witnessed, or its reading read no probe. |
| `listed_evidence_unknown` | listed; the reading could not be read from this record | 5 | Listed, with no reading this CLI can interpret. |
| `revoked` | revoked | 1 | The record says it was revoked or withdrawn. |
| `not_listed` | not listed in the Trooth Network's public feed | 1 | The documented not-listed answer: a JSON 404 whose body says `listed: false`. |
| `service_error` | (an error on stderr) | 3 | Anything else. Never read as an answer about the company. |

The two counts use the same form as the record page on trooth.co: live probes (how many were read at the last reading, and how many of those returned the expected result) and self-attestations (how many the company was asked for, and how many it attested). Live probes are readings Trooth took itself; self-attestations are the company's statements about itself, which Trooth records and does not witness. The counts come from the directory record; they are the counts of the signed reading, and not any other total a page may show.

The events section prints the three newest entries in the record's ledger, newest first, by timestamp; entries with the same timestamp keep the feed's order, the later entry first. Known event types get a plain label: `scan_completed` prints as "reading completed", `standing_published` as "record published to the Trooth Network" and `rewitnessed` as "live probes re-read". A type the CLI does not know prints with its underscores turned into spaces. `--json` carries every event the feed returns, with its type and detail exactly as the feed has them.

**What `check` accepts.** A bare domain or a URL. It is parsed with the standard URL parser, so case, a trailing dot, the default port (80 or 443), a path and an internationalized name (converted to its ASCII form) normalize to one domain, and a leading `www.` is dropped: `https://Trooth.co:443/path` reads `trooth.co`. A URL with a user name or password, a non-default port, an IP address, a scheme other than http or https, or a name with no dot is a usage error (exit 2) rather than a guess.

**How `check` asks.** One `GET /directory/api/vendors/<domain>`, with a 15-second deadline (`TROOTH_TIMEOUT_MS` changes it), a 1 MiB limit on the body, redirects refused, a JSON content type required, and at most one retry, only after a connection failure or a 502, 503 or 504. Up to 0.4.4, a plain-text 404 made the CLI download the whole directory list and search it; the single-record route has been served since 2026-09-26, and 0.5.0 has no fallback, so an unexpected answer is a service error, never "not listed".

For scripting:

```bash
trooth check trooth.co --json
```

```json
{
  "domain": "trooth.co",
  "listed": true,
  "state": "listed_witnessed",
  "company_name": "Trooth, LLC",
  "witnessed_at": "2026-08-30T00:00:00Z",
  "first_published_at": "2026-08-01T00:00:00Z",
  "badge_id": "rw_...",
  "probes": { "passed": 64, "total": 65 },
  "attested": { "passed": 27, "total": 35 },
  "events": [
    { "type": "scan_completed", "at": "2026-08-01T00:00:00Z", "detail": "65 probes read · 64 returned the expected result · 27 declarations recorded · reading signed" },
    { "type": "standing_published", "at": "2026-08-01T00:00:00Z", "detail": "point-in-time · published to the Trooth Network" },
    { "type": "scan_completed", "at": "2026-08-30T00:00:00Z", "detail": "65 probes read · 64 returned the expected result · 27 declarations recorded · reading signed" },
    { "type": "standing_published", "at": "2026-08-30T00:00:00Z", "detail": "point-in-time · published to the Trooth Network" }
  ],
  "receipt_signature": "...",
  "authority_key_id": "trooth-master-2026-09",
  "signature_checked": false,
  "verify_keys": "https://api.trooth.co/public/keys",
  "verify_how": "https://trooth.co/docs/verifiable-evidence",
  "record_url": "https://trooth.co/network/trooth.co"
}
```

In `probes`, `total` is how many live probes were read at the last reading and `passed` (the API's field name) is how many returned the expected result. In `attested`, `total` is how many declarations were asked for and `passed` is how many the company attested. `witnessed_at` is the date of the witnessed reading, and is `null` unless `state` is `listed_witnessed`; it is never a profile edit time. `events` is the whole ledger, oldest first, in the feed's order. Each event's `detail` is written when the event is stored and is not rewritten afterward, so older and newer events of the same type can be worded differently.

`category` and `description` are added when the record carries them. Those are the only fields `check --json` emits: anything else the feed happens to carry is dropped on the way out, so a script written against this shape keeps working. A field whose name contains `score`, `tier`, `grade`, `rank`, `rating`, `level` or `percent`, or is `rate`, is dropped no matter what the feed sends.

A company with no record exits 1 and emits `{"domain": "...", "listed": false, "state": "not_listed", "record_url": "..."}`. That is not a judgment. It means the Network's public feed carries no record for that domain. A company gets a record at [trooth.co/get-started](https://trooth.co/get-started), free.

`receipt_signature` is Trooth's Ed25519 signature over the directory receipt and `authority_key_id` names the key that made it; the public keys are listed at [trooth.co/verify/keys](https://trooth.co/verify/keys). `signature_checked` is always `false`: this CLI does not check any signature, and nothing it prints should be read as a checked signature. The object whose exact signed bytes Trooth publishes is the reading's witness statement, which is not part of this feed; [trooth.co/docs/verifiable-evidence](https://trooth.co/docs/verifiable-evidence) shows how to fetch and check it offline. That signature covers the reading. It does not cover the company's own declarations, which are not signed by anyone.

## `trooth lint`

`lint` reads what your infrastructure **declares** and reports it. It does not judge it. There is no verdict, no threshold, no severity and no rating, and nothing is checked against a named standard or regulation. Declaring public ingress is not a failing: a load balancer is supposed to be public. What the facts mean is your decision.

```bash
trooth lint ./infra
```

Output for the small fixture in this repository (`trooth lint tests/fixtures/infra`, trooth 0.5.0):

```
trooth lint // local · offline · declarations only //
tests/fixtures/infra   2 declaration file(s) read
terraform 1 · kubernetes 1

Declared
  Regions and zones                        us-east-1
  Storage declarations                     1
    declaring encryption                   1
    declaring encryption off               0
    declaring nothing about encryption     0
    set by an unresolved expression        0
  Logging declarations                     0
  Identity declarations                    0
  Open to any address (0.0.0.0/0, ::/0)    1
  Marked public                            0
  Inline credential literals               0

Most declared resource types
     1  aws_s3_bucket
     1  aws_s3_bucket_server_side_encryption_configuration
     1  aws_security_group_rule
     1  Deployment

Coverage  complete
  2 selected: 2 read, 0 not declarations, 0 excluded, 0 skipped, 0 invalid, 0 unreadable.

Facts digest  sha256:2ba1da28be9e97e1e8be1f7e41641288bc632192c062ba1fbd563350448fd5a8
A SHA-256 over the counts above, in canonical form. It is an aggregate: two different
trees with the same counts share it. It does not identify your files, your repository
or a deployment.

How this was read
  Every file is parsed; a file that does not parse is reported as invalid, not read.
  Comments count for nothing. Nothing is evaluated: a setting that depends on a variable,
  a local, a module or a function is reported as unresolved. Dockerfiles: ENV and ARG only.

Counts of what the files declare. Not a judgment: a public load balancer is
supposed to be public. Trooth issues no verdict here and checks nothing against
any standard. Nothing left this machine: lint opens files and opens no sockets.
Publish what you choose on your record at https://trooth.co/dashboard.
```

The bucket's encryption configuration is a setting on the bucket, not a second store, so the fixture has one storage declaration, and that one declares encryption.

**How each source is read.** Every file is parsed, and a file that does not parse is reported as invalid, never as read.

| Source | Parsed with | Unit |
|---|---|---|
| `.tf` | The HCL reader in `bin/lib/hcl.mjs` (comments dropped, heredocs and templates understood) | One `resource` block, at any indentation |
| `.tf.json` | `JSON.parse` | One resource |
| `terraform show -json` plan | `JSON.parse` | One planned managed resource; data sources are skipped |
| Kubernetes YAML (`apiVersion` and `kind`) | The `yaml` package, strict mode | One document, classified by `kind` |
| Dockerfile | `ENV` and `ARG` instructions only | The file |

Nothing is evaluated. A setting that depends on a variable, a local, a module output or a function is reported as unresolved and is never counted as declared. Storage, logging and identity are counted by a resource's type or a document's kind, never by the words around it. Counts are of parsed values, not lines: two credential literals on one minified line are two.

**Encryption, per store.** Each storage declaration is counted in exactly one of five states:

| Field | State |
|---|---|
| `storage_declaring_encryption` | An explicit `true`, a named key (a literal or a reference to a key resource such as `aws_kms_key.main.arn`), or an encryption block, in the store or in a setting resource that refers to it |
| `storage_declaring_encryption_off` | An explicit `false`. It wins over any other signal |
| `storage_encryption_not_declared` | Nothing about encryption. A commented-out setting is nothing |
| `storage_encryption_unresolved` | Decided by a variable, a local or another expression lint does not evaluate |
| `storage_encryption_unsupported` | A value lint does not interpret, such as a number where a switch belongs |

A declaration is what a file says, not what a cloud account does: a provider default, an account-wide setting or a module can encrypt a store whose file declares nothing, and lint cannot see any of those.

**Coverage.** Every file the walk selects (`.tf`, `.tf.json`, `.json`, `.yaml`, `.yml`, Dockerfiles) ends in exactly one bucket: read; not applicable (a JSON or YAML file that is not a plan or a manifest); excluded by a stated rule (a templated manifest containing `{{ }}`, which has to be rendered first); skipped (over 4 MiB); invalid (did not parse); or unreadable (a permission or I/O error). The walk visits directories depth first with entries sorted by name, skips `node_modules`, `.git`, `.terraform` and the other build and dependency directories listed in the source, and stops at 5,000 selected files. A read with anything skipped, invalid or unreadable, or a truncated walk, is **incomplete**: the output says so, `--json` carries a `coverage` object with each count and a `coverage_details` object listing up to 50 paths per bucket with the reason (never file contents), and the exit code is 4 unless you pass `--allow-incomplete`.

Nothing leaves the machine. No line, no code and no value is printed or transmitted, only the path you gave it, counts, resource type names, region strings and, for files that could not be read, their paths and the reason. The credential count is a count: the literal it found is never shown.

**The facts digest** (`facts_digest`, also emitted as `digest` until 0.6) is a SHA-256 over the `facts` object in canonical form. It is an aggregate: two different trees with the same counts produce the same digest, and a release that changes how something is counted changes the digest of the same tree. It does not identify file contents, a repository, a commit or a deployment, and it is not an attestation of any of them. It is useful for noticing that the counts changed between two runs of the same version.

```bash
# Keep the fact document as a build artifact.
trooth lint --json > trooth-lint.json
```

## In GitHub Actions

The same `lint`, as a step, is [`troothllc/trooth-action`](https://github.com/troothllc/trooth-action). It is advisory by default: it writes what your infrastructure declares to the job summary and does not fail your workflow over anything it read unless you opt in to one of two gates. It does fail the step when it could not read at all: a path that does not exist, or a CLI it could not install or start.

```yaml
- uses: troothllc/trooth-action@<full commit SHA>  # v1
  with:
    path: ./infra
```

Pin the action by its full commit SHA. A tag can be moved; a commit cannot. The action installs one exact `trooth` version with install scripts disabled and refuses a version input that is a range, a tag or a URL.

That repository's README documents the inputs and outputs.

## Environment

| Variable | Effect |
|---|---|
| `TROOTH_API` | Base URL for `check`. Defaults to `https://api.trooth.co`. `lint` ignores it, because `lint` makes no requests. |
| `TROOTH_TIMEOUT_MS` | The deadline for each `check` request. Defaults to 15000; the minimum is 1000. |
| `TROOTH_LINT_MAX_FILES` | The number of selected files after which `lint` stops walking and reports the read as truncated. Defaults to 5000. |
| `NO_COLOR` | Disables ANSI color. Color is already off when stdout is not a TTY. |

There is no API key. The binary asks for no credential of any kind and has no write path.

## From an AI assistant

The same public Network powers Trooth's read-only MCP server, so ChatGPT, Claude, Cursor or any MCP client can ask about a company in plain words:

```
https://api.trooth.co/public/mcp
```

Four read-only tools, public data, no key. The pattern is written up at [trooth.co/docs/agents](https://trooth.co/docs/agents).

## Changed in 0.5.0

Breaking where the old behavior overstated what was read.

- `lint` parses every format instead of matching patterns. `encrypted = false` on one line, `false` followed by a comment, a commented-out setting and a setting that depends on a variable no longer count as declaring encryption; each store is counted in one of five encryption states. Comments count for nothing, indentation no longer changes a count, and a minified JSON file counts the same as a pretty one.
- `lint` reports coverage and exits 4 on an incomplete read: a malformed file, a file over the size limit, an unreadable file or a truncated walk. 0.4.4 read a malformed file as a success and an oversized one as "nothing to read".
- The digest is renamed `facts_digest` and described as what it is, an aggregate of the counts. `digest` carries the same value until 0.6.
- `check` decides the evidence state from the record's fields: a listed record is no longer printed as witnessed unless it carries a witnessed reading, and exit 5 means listed but not witnessed. The full-list fallback is gone, so an unexpected answer is a service error, never "not listed". Requests have a deadline, a body limit, a content-type check and one bounded retry. Input is normalized with the URL parser.
- `check` says that it did not check the signature, and the help and this README say that `check` sends the domain you ask about.

## Changed in 0.4.4

- `check` asked the Trooth Network for the one record it needs (`/directory/api/vendors/<domain>`) instead of downloading the whole directory list, and fell back to the list when the API did not serve that path. 0.5.0 removes the fallback.

## Changed in 0.4.3

- `check` labels the listing state `Listing state:` and prints the two counts in the record page's form (`65 read; 64 as expected`, `35 asked; 27 attested`). It prints the three newest ledger events, newest first, with plain labels and without the detail text. 0.4.2 printed the ledger's three oldest events under a heading that called them recent. `check --json` is unchanged.
- `lint` no longer counts a storage setting (a bucket's encryption configuration, a bucket policy, a volume attachment) as a second store, and a setting that declares encryption credits the store it refers to. It no longer counts `encrypted = false`, or an empty encryption setting in a plan, as declaring encryption. It classifies by resource type or Kubernetes `kind` only, parses `.tf.json` and plan JSON and counts their resource types, and reads Kubernetes YAML one document at a time. The same tree can therefore produce different counts, and a different digest, than under 0.4.2. The `lint --json` field names are unchanged.
- The human `lint` output states how each source was read.

## Removed in 0.4.0

Breaking, and deliberately so.

- The `scan` and `eu` commands are gone. Trooth does not check infrastructure against a standard and does not issue a verdict. Running either exits 2 with a sentence saying what happened, rather than "unknown command", so an old CI job or an old bookmark gets an explanation.
- `lint` is real. In 0.3.0 it shelled out to a package that was never published, so the command failed for everyone who ran it. It is implemented in this binary now, entirely locally.
- `scan_id` is gone from `check --json`. Every other field is unchanged.
- `--strict` is gone, along with the only command that took it.
- The package description and keywords no longer name any certification, standard or regulation, because Trooth does not offer one.

The Trooth Network is Trooth's only product. This CLI, the public API and the MCP server are interfaces to that one record, not separate products.

## Security

Report a vulnerability through the [Vulnerability Disclosure Policy](https://trooth.co/security/vulnerability-disclosure-policy). Nothing in this CLI takes a credential, so there is no key to leak from it. Reproduce the published tarball with `npm pack` at the tagged commit and compare its SHA-512 with the `integrity` value `npm view trooth@<version> dist.integrity` prints.

## Links

- The Network: [trooth.co/network](https://trooth.co/network)
- This CLI on the site: [trooth.co/cli](https://trooth.co/cli)
- API reference: [trooth.co/docs/api](https://trooth.co/docs/api)
- Developers: [trooth.co/developers](https://trooth.co/developers)
- Publish your own record, free: [trooth.co/get-started](https://trooth.co/get-started)
- Contact: [trooth.co/contact](https://trooth.co/contact)

## License

Apache License 2.0. See [LICENSE](LICENSE).

The same license applies to this repository, to the `trooth` package on npm and to the copyright header in `bin/trooth.mjs`. They are meant to agree. If you find that they do not, that is a defect: please report it at [trooth.co/contact](https://trooth.co/contact).

Trooth signs what it witnessed. It never signs on a company's behalf.
