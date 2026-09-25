# trooth

The Trooth Network from your terminal. Published on npm as **`trooth`**.

Trooth operates the Trooth Network: one public, signed, machine-readable record per company, carrying its identity, products and demos, commercial terms, domain and marketing links, people, documents, security and privacy posture, AI practices, procurement terms and relationships. It is Trooth's only product and it is free.

DNS says where a company is. A TLS certificate says the connection is authentic. The Trooth Network says who the company is and what it does with your data.

This CLI is the terminal interface to that record. It does two things:

- `trooth check <domain>` reads a company's published record from the public Network. No key, no account, and nothing about you is sent beyond what any web request carries (your IP address and a `trooth-cli/<version>` user-agent).
- `trooth lint [path]` reads what your own infrastructure declares and prints those declarations as facts. Entirely local: it opens files and opens no sockets.

**Trooth witnesses and dates facts. It does not score, rate, rank or certify anyone.** The CLI prints counts, reported apart, and never adds them into one number.

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
| `trooth check <domain>` | Reads a company's record from the live Network and prints whether it is listed, when it was witnessed and first published, the live-probe and attestation counts, the badge id, the id of the key that signed the record, and the first three events in its ledger. `--json` adds the signature itself. |
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
Trooth Network // witnessed · public · read-only //
Trooth, LLC   trooth.co
Standing: listed and witnessed   witnessed 2026-08-30   first published 2026-08-01

Live probes 64/65     Attestations 27/35
Probes are checks Trooth read for itself. Attestations are the company's own declarations.
They are counts, reported apart on purpose. Trooth never adds them up into one number.
Badge rw_...   Key ed25519-2026-01

Recent witness events
  • 2026-08-01  scan completed  64 of 65 live probes passed · 27 of 35 declarations recorded · signature valid
  • 2026-08-01  standing published  point-in-time · published to the Trooth Network
  • 2026-08-30  scan completed  64 of 65 live probes passed · 27 of 35 declarations recorded · signature valid

A witnessed, point-in-time reading of public evidence. Not a certification. Not one number.
Full record: https://trooth.co/network/trooth.co   ·   Signing keys: https://api.trooth.co/public/keys
```

The line that begins `Standing:` is the binary's label for the listing state. For a listed company it reads `listed and witnessed`, then the date of the most recent published reading and the date the record was first published. The two counts are live probes (how many returned the expected result, out of how many were read at the last reading) and attestations (how many the company attested, out of how many were asked for).

The events section prints the first three entries in the record's ledger. The feed keeps the ledger oldest first, so these are the record's earliest events even though the heading says "Recent"; `--json` carries every event the feed returns. Event types and details are the feed's own wording, printed as received.

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
    { "type": "scan_completed", "at": "2026-08-01T00:00:00Z", "detail": "64 of 65 live probes passed · 27 of 35 declarations recorded · signature valid" },
    { "type": "standing_published", "at": "2026-08-01T00:00:00Z", "detail": "point-in-time · published to the Trooth Network" },
    { "type": "scan_completed", "at": "2026-08-30T00:00:00Z", "detail": "64 of 65 live probes passed · 27 of 35 declarations recorded · signature valid" },
    { "type": "standing_published", "at": "2026-08-30T00:00:00Z", "detail": "point-in-time · published to the Trooth Network" }
  ],
  "receipt_signature": "...",
  "authority_key_id": "ed25519-2026-01",
  "verify_keys": "https://api.trooth.co/public/keys",
  "record_url": "https://trooth.co/network/trooth.co"
}
```

In `probes`, `total` is how many live probes were read at the last reading and `passed` (the API's field name) is how many returned the expected result. In `attested`, `total` is how many declarations were asked for and `passed` is how many the company attested. `witnessed_at` is the date of the most recent published reading. `events` is the whole ledger, oldest first.

`category` and `description` are added when the record carries them. Those are the only fields `check --json` emits: anything else the feed happens to carry is dropped on the way out, so a script written against this shape keeps working. A field whose name would carry a score, grade, rank, rating or percentage is dropped no matter what the feed sends.

A company with no record exits 1 and emits `{"domain": "...", "listed": false, "record_url": "..."}`. That is not a judgment. It means the Network's public feed carries no record for that domain. A company gets a record at [trooth.co/get-started](https://trooth.co/get-started), free.

`receipt_signature` is Trooth's Ed25519 signature and `authority_key_id` names the key that made it; the public keys are listed at [trooth.co/verify/keys](https://trooth.co/verify/keys). You cannot re-run that signature check from this output yet: the exact bytes the signature covers are not published, and this JSON does not carry every field that goes into them. [`trust-verifier-sdk`](https://github.com/troothllc/trust-verifier-sdk) states that gap and what will close it.

## `trooth lint`

`lint` reads what your infrastructure **declares** and reports it. It does not judge it. There is no verdict, no pass mark, no severity and no score, and nothing is checked against a named standard or regulation. Declaring public ingress is not a failing: a load balancer is supposed to be public. What the facts mean is your decision.

```bash
trooth lint ./infra
```

Example output. The values are illustrative; the shape is what the binary prints.

```
trooth lint // local · offline · declarations only //
infra   14 declaration file(s) read
terraform 11 · kubernetes 3

Declared
  Regions and zones                        eu-west-1, us-east-1
  Storage declarations                     9
    of those declaring encryption          9
  Logging declarations                     4
  Identity declarations                    6
  Open to any address (0.0.0.0/0, ::/0)    1
  Marked public                            2
  Inline credential literals               0

Most declared resource types
     5  aws_s3_bucket
     3  aws_iam_role
     2  aws_cloudwatch_log_group

Digest  sha256:...
A SHA-256 over the facts above, in canonical form, with the timestamp excluded.
The same tree always produces the same digest, so you can record it as evidence
that a state was observed without publishing the tree it came from.

Counts of what the files declare. Not a judgement: a public load balancer is
supposed to be public. Trooth issues no verdict here and checks nothing against
any standard. Nothing left this machine: lint opens files and opens no sockets.
Publish what you choose on your record at https://trooth.co/dashboard.
```

It reads `.tf`, `.tf.json`, Kubernetes YAML (anything carrying both `apiVersion` and `kind`), `terraform show -json` plan files and Dockerfiles. It is a declaration reader, not a full HCL parser: it matches patterns in the text of each file and parses none of them, so a count can differ from what a full parser would find. Its output does not state this limit.

Nothing leaves the machine. No file name, no line, no code and no value is printed or transmitted, only the path you gave it, counts, resource type names and region strings. The credential count is a count: the literal it found is never shown.

The digest is a SHA-256 over the canonical fact document with the timestamp excluded, so the same tree always produces the same digest. Record it in CI, or on your own record, as evidence that a given state was observed, without publishing the tree it came from.

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
