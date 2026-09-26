# trooth

The Trooth Network from your terminal. Published on npm as **`trooth`**.

Trooth operates the Trooth Network: one public, signed, machine-readable record per company, carrying its identity, products and demos, commercial terms, domain and marketing links, people, documents, security and privacy posture, AI practices, procurement terms and relationships. It is Trooth's only product and it is free.

DNS says where a company is. A TLS certificate says the connection is authentic. The Trooth Network says who the company is and what it does with your data.

This CLI is the terminal interface to that record. It does two things:

- `trooth check <domain>` reads a company's published record from the public Network. No key, no account, and nothing about you is sent beyond what any web request carries (your IP address and a `trooth-cli/<version>` user-agent).
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

Node 18 or newer, because the binary uses the built-in `fetch`. Zero dependencies.

## Commands

| Command | What it does |
|---|---|
| `trooth check <domain>` | Reads a company's record from the live Network and prints whether it is listed, when it was last witnessed and first published, the live-probe and self-attestation counts, the badge id, the id of the key that signed the record, and the three newest events in its ledger, newest first. `--json` adds the signature itself and every event the feed returns. |
| `trooth lint [path]` | Reads the infrastructure the given directory declares and prints those declarations plus a canonical SHA-256 digest of them. Local and offline. `path` defaults to `.`. |
| `trooth --help` | Help. Also `-h` and `help`. |
| `trooth --version` | Version. Also `-v` and `version`. |

## Flags

`--json` is the only flag `check` and `lint` take. With it, stdout carries exactly one JSON document and nothing else, and every diagnostic goes to stderr. On an error the document is `{"ok": false, "error": "...", "exit": N}`; a non-2xx response adds `http_status`, and `lint` with nothing to read adds `files_opened`. `--help` and `--version` print plain text whether or not `--json` is given.

Any other flag is a usage error. The message names the flag, and for a `--` flag given to `check` or `lint` it also lists the ones that exist.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The company is listed, or `lint` read at least one declaration, or you asked for help or the version. |
| 1 | The company is not listed, or `lint` found nothing to read. |
| 2 | Usage error: a missing argument, an unknown flag or command, or a path that does not exist. |
| 3 | Trooth could not be read: unreachable, a non-2xx response, or a response that is not JSON. An unexpected failure inside the CLI also exits 3. |

A company with no record and a Network that could not be read are different answers, so they exit differently. A pipeline can tell them apart without parsing prose, and a Trooth outage never reads as a company with no record.

## `trooth check`

```bash
trooth check trooth.co
```

Example output. The values are illustrative; the shape is what the binary prints.

```
Trooth Network // public · signed · read-only //
Trooth, LLC   trooth.co
Listing state: listed and witnessed   last witnessed 2026-08-30   first published 2026-08-01

Live probes: 65 read; 64 as expected
Self-attestations: 35 asked; 27 attested
Live probes are readings Trooth took itself, from the company's public surface.
Self-attestations are what the company attested about itself; Trooth records them
and did not witness them. The two are reported apart and never added into one number.
Badge rw_...   Key ed25519-2026-01

Latest ledger events, newest first
  • 2026-08-30  record published to the Trooth Network
  • 2026-08-30  reading completed
  • 2026-08-01  record published to the Trooth Network
  --json carries the whole ledger, with the feed's own wording for each event.

A dated, point-in-time record. Trooth issues no verdict and no single number.
Full record: https://trooth.co/network/trooth.co   ·   Signing keys: https://api.trooth.co/public/keys
```

The line that begins `Listing state:` gives the listing state. For a listed company it reads `listed and witnessed`, then the date of the most recent published reading (`last witnessed`) and the date the record was first published. The two counts use the same form as the record page on trooth.co: live probes (how many were read at the last reading, and how many of those returned the expected result) and self-attestations (how many the company was asked for, and how many it attested). Live probes are readings Trooth took itself; self-attestations are the company's statements about itself, which Trooth records and does not witness.

The events section prints the three newest entries in the record's ledger, newest first, by timestamp; entries with the same timestamp keep the feed's order, the later entry first. Known event types get a plain label: `scan_completed` prints as "reading completed", `standing_published` as "record published to the Trooth Network" and `rewitnessed` as "live probes re-read". A type the CLI does not know prints with its underscores turned into spaces. The human view leaves out each event's detail text. `--json` carries every event the feed returns, with its type and detail exactly as the feed has them.

For scripting:

```bash
trooth check trooth.co --json
```

```json
{
  "domain": "trooth.co",
  "listed": true,
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
  "authority_key_id": "ed25519-2026-01",
  "verify_keys": "https://api.trooth.co/public/keys",
  "record_url": "https://trooth.co/network/trooth.co"
}
```

In `probes`, `total` is how many live probes were read at the last reading and `passed` (the API's field name) is how many returned the expected result. In `attested`, `total` is how many declarations were asked for and `passed` is how many the company attested. `witnessed_at` is the date of the most recent published reading. `events` is the whole ledger, oldest first, in the feed's order. Each event's `detail` is written when the event is stored and is not rewritten afterward, so older and newer events of the same type can be worded differently.

`category` and `description` are added when the record carries them. Those are the only fields `check --json` emits: anything else the feed happens to carry is dropped on the way out, so a script written against this shape keeps working. A field whose name contains `score`, `tier`, `grade`, `rank`, `rating`, `level` or `percent`, or is `rate`, is dropped no matter what the feed sends.

A company with no record exits 1 and emits `{"domain": "...", "listed": false, "record_url": "..."}`. That is not a judgment. It means the Network's public feed carries no record for that domain. A company gets a record at [trooth.co/get-started](https://trooth.co/get-started), free.

`receipt_signature` is Trooth's Ed25519 signature and `authority_key_id` names the key that made it; the public keys are listed at [trooth.co/verify/keys](https://trooth.co/verify/keys). You cannot re-run that signature check from this output yet: the exact bytes the signature covers are not published, and this JSON does not carry every field that goes into them. [`trooth-signatures`](https://github.com/troothllc/trooth-signatures) states that gap and what will close it.

## `trooth lint`

`lint` reads what your infrastructure **declares** and reports it. It does not judge it. There is no verdict, no threshold, no severity and no rating, and nothing is checked against a named standard or regulation. Declaring public ingress is not a failing: a load balancer is supposed to be public. What the facts mean is your decision.

```bash
trooth lint ./infra
```

Output for the small fixture in this repository (`trooth lint tests/fixtures/infra`, trooth 0.4.3):

```
trooth lint // local · offline · declarations only //
tests/fixtures/infra   2 declaration file(s) read
terraform 1 · kubernetes 1

Declared
  Regions and zones                        us-east-1
  Storage declarations                     1
    of those declaring encryption          1
  Logging declarations                     0
  Identity declarations                    0
  Open to any address (0.0.0.0/0, ::/0)    1
  Marked public                            0
  Inline credential literals               0

Most declared resource types
     1  aws_s3_bucket
     1  aws_s3_bucket_server_side_encryption_configuration
     1  aws_security_group_rule

Digest  sha256:a40bf6cf27dfd0b9079ac48a326fb2d1423b076c96b405451dde1ed2d7848944
A SHA-256 over the facts above, in canonical form, with the timestamp excluded.
The same tree read by the same trooth version produces the same digest, so you can
record it as evidence that a state was observed without publishing the tree.

How this was read
  A pattern reader, not a Terraform evaluator: variables and modules are not resolved.
  .tf by pattern, one resource block at a time. .tf.json and plan JSON parsed, one
  resource at a time. Kubernetes YAML by pattern, one document at a time, by kind.
  Dockerfiles for regions, open addresses, public markers and credential literals only.

Counts of what the files declare. Not a judgment: a public load balancer is
supposed to be public. Trooth issues no verdict here and checks nothing against
any standard. Nothing left this machine: lint opens files and opens no sockets.
Publish what you choose on your record at https://trooth.co/dashboard.
```

The bucket's encryption configuration is a setting on the bucket, not a second store, so the fixture has one storage declaration, and that one declares encryption.

It reads `.tf`, `.tf.json`, Kubernetes YAML (anything carrying both `apiVersion` and `kind`), `terraform show -json` plan files and Dockerfiles. It is a pattern reader, not a Terraform evaluator: variables, modules and `for_each` are never resolved, so a count can differ from what Terraform itself would plan. `.tf` files are read by pattern, one resource block at a time. `.tf.json` and plan files are parsed as JSON, one resource at a time. Kubernetes YAML is read by pattern, one document at a time, and classified by its `kind`. Dockerfiles are read for regions, open addresses, public markers and credential literals only. Storage, logging and identity are counted by a resource's type or a document's kind, never by the words around it. The output states this under "How this was read".

Nothing leaves the machine. No file name, no line, no code and no value is printed or transmitted, only the path you gave it, counts, resource type names and region strings. The credential count is a count: the literal it found is never shown.

The digest is a SHA-256 over the `facts` object in canonical form. The timestamp, the path and the CLI version are outside it, so the same tree read by the same trooth version produces the same digest. A release that changes how something is counted changes the digest of the same tree: the fixture above digests differently under 0.4.2 and 0.4.3. Record the digest in CI, or on your own record, as evidence that a given state was observed, without publishing the tree it came from.

```bash
# Keep the fact document as a build artifact.
trooth lint --json > trooth-lint.json
```

## In GitHub Actions

The same `lint`, as a step, is [`troothllc/trooth-action`](https://github.com/troothllc/trooth-action). It is advisory by default: it writes what your infrastructure declares to the job summary and does not fail your workflow over anything it read unless you opt in to one of two gates. It does fail the step when it could not read at all: a path that does not exist, or a CLI it could not install or start.

```yaml
- uses: troothllc/trooth-action@v1
  with:
    path: ./infra
```

That repository's README documents the inputs and outputs.

## Environment

| Variable | Effect |
|---|---|
| `TROOTH_API` | Base URL for `check`. Defaults to `https://api.trooth.co`. `lint` ignores it, because `lint` makes no requests. |
| `NO_COLOR` | Disables ANSI color. Color is already off when stdout is not a TTY. |

There is no API key. The binary asks for no credential of any kind and has no write path.

## From an AI assistant

The same public Network powers Trooth's read-only MCP server, so ChatGPT, Claude, Cursor or any MCP client can ask about a company in plain words:

```
https://api.trooth.co/public/mcp
```

Four read-only tools, public data, no key. The pattern is written up at [trooth.co/docs/agents](https://trooth.co/docs/agents).

## Changed in 0.4.4

- `check` asks the Trooth Network for the one record it needs (`/directory/api/vendors/<domain>`) instead of downloading the whole directory list and searching it. When the API does not serve that path yet, it reads the list as 0.4.3 did. The printed output, `check --json` and the exit codes are unchanged.

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

Report a vulnerability through the [Vulnerability Disclosure Policy](https://trooth.co/security/vulnerability-disclosure-policy). Nothing in this CLI takes a credential, so there is no key to leak from it.

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
