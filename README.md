# trooth

The Trooth Network from your terminal.

The Trooth Network gives every company one public, signed record: what it is,
what it sells, who runs it, where its data lives, how it handles AI, and what a
buyer needs before signing. DNS tells a machine where a company is. A TLS
certificate tells it the connection is authentic. Neither says anything about
the company itself. The Trooth Network is that layer, and this CLI reads it.

**`check` reads only public, already-published records. No key, no account.**
**`lint` is entirely local: it opens files and opens no sockets.**
**Trooth publishes facts and counts, never one number that sums a company up.**

## Install / run

```bash
# No install needed:
npx trooth check stripe.com

# or install it:
npm i -g trooth
trooth check trooth.co
```

Requires Node 18+ (uses built-in `fetch`). Zero dependencies.

## Commands

| Command | What it does |
| --- | --- |
| `trooth check <domain>` | Reads a company's record from the live Trooth Network (`GET https://api.trooth.co/directory/api/vendors`) and prints whether it is listed, when it was witnessed and first published, the live-probe and attestation counts, the badge id, and the signature and key id you can verify. Prints an honest "not listed yet" when a company has no published record. |
| `trooth lint [path]` | Reads the infrastructure the given directory **declares** and prints those declarations as facts, plus a canonical SHA-256 digest of them. Entirely local and offline. |
| `trooth --help` / `--version` | Help / version. |

## Flags

- `--json`: stdout carries exactly one JSON document and nothing else; every
  diagnostic goes to stderr. On an error the document is
  `{"ok": false, "error": "...", "exit": N}`.

Any other flag is a usage error (exit 2) that names the flag and lists the
known ones.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | ok: company listed; lint read at least one declaration; help / version |
| 1 | finding: company not listed; lint found nothing to read |
| 2 | usage error: missing argument, unknown flag or command, unreadable path |
| 3 | Trooth unreachable, non-2xx response, or malformed response |

A company that is not listed and a network that could not be read are different
answers and they exit differently, so a pipeline never reads a Trooth outage as
"this vendor is unverified".

## `trooth check`

```bash
trooth check trooth.co
```

```
Trooth Network // witnessed · public · read-only //
Trooth, LLC   trooth.co
Standing: listed and witnessed   witnessed 2026-08-30   first published 2026-08-01

Live probes 64/65     Attestations 27/35
Probes are checks Trooth read for itself. Attestations are the company's own declarations.
They are counts, reported apart on purpose. Trooth never adds them up into one number.
Badge bronze_rw_...   Key ed25519-2026-01

Recent witness events
  • 2026-08-30  rewitnessed  64 of 65 live probes re-run

A witnessed, point-in-time reading of public evidence. Not a certification. Not one number.
Full record: https://trooth.co/network/trooth.co   ·   Signing keys: https://api.trooth.co/public/keys
```

```bash
# For scripting: one JSON document on stdout, exit 1 when a company is not listed.
trooth check trooth.co --json
```

```json
{
  "domain": "trooth.co",
  "listed": true,
  "company_name": "Trooth, LLC",
  "witnessed_at": "2026-08-30T00:00:00Z",
  "first_published_at": "2026-08-01T00:00:00Z",
  "badge_id": "bronze_rw_...",
  "probes": { "passed": 64, "total": 65 },
  "attested": { "passed": 27, "total": 35 },
  "events": [ { "type": "rewitnessed", "at": "2026-08-30T00:00:00Z", "detail": "64 of 65 live probes re-run" } ],
  "receipt_signature": "...",
  "authority_key_id": "ed25519-2026-01",
  "verify_keys": "https://api.trooth.co/public/keys",
  "record_url": "https://trooth.co/network/trooth.co"
}
```

Those are the only fields `check --json` emits. Anything else the feed happens
to carry is dropped on the way out, so a script written against this shape
keeps working — and a field that would carry a score, tier, grade, rank or
rating is dropped no matter what the feed sends.

## `trooth lint`

`lint` reads what your infrastructure **declares** and reports it. It does not
judge it. There is no verdict, no pass mark, no severity and no score, and
nothing is checked against a named standard or regulation — declaring public
ingress is not a failing, because a load balancer is supposed to be public.
What the facts mean is your call.

```bash
trooth lint ./infra
```

```
trooth lint // local · offline · declarations only //
./infra   14 declaration file(s) read
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

Digest  sha256:a963291330bce2ab…
```

It reads `.tf`, `.tf.json`, Kubernetes YAML (anything with `apiVersion` and
`kind`), `terraform show -json` plan files and Dockerfiles. It is a declaration
reader, not a full HCL parser, and it says so rather than pretending otherwise.

**Nothing leaves the machine.** No file name, no line, no code and no value is
ever printed or transmitted — only counts, resource type names and region
strings. The credential count is a count: it never shows the literal it found.

**The digest** is a SHA-256 over the canonical fact document with the timestamp
excluded, so the same tree always produces the same digest. Record it in CI, or
on your Trooth record, as evidence that a given state was observed — without
publishing the tree it came from.

```bash
# In CI: keep the fact document as a build artifact.
trooth lint --json > trooth-attestation.json
```

## Use it from an AI assistant

The same public network powers Trooth's read-only MCP server, so ChatGPT,
Claude, Cursor, or any MCP client can ask about a company in plain words:

```
https://api.trooth.co/public/mcp
```

## Notes

- `check` reads only the **public** record. There is no key and no account, and
  it never sends anything about you. It is a read.
- A "not listed" result is not a judgement. It means no record has been
  published for that domain yet. A company gets one at
  <https://trooth.co/get-started>.
- Set `TROOTH_API` to point at a different base URL (defaults to
  `https://api.trooth.co`). `lint` ignores it: `lint` makes no requests.
- Set `NO_COLOR=1` to disable ANSI colour. Colour is already off when stdout is
  not a TTY.

## Changes in 0.4.0

Breaking, and deliberately so.

- **`scan` and `eu` are removed.** Trooth does not scan infrastructure against a
  standard, does not issue a verdict and does not offer a compliance product.
  Both commands now exit 2 with a sentence saying so, rather than "unknown
  command", so an old CI job or an old README gets an explanation.
- **`lint` is real.** In 0.3.0 it shelled out to `@trooth/os`, which was never
  published, so the command failed for everyone who ran it. It is now
  implemented in this binary, entirely locally.
- **`scan_id` is gone from `check --json`.** Every other field is unchanged.
- **`--strict` is gone**, along with the only command that took it.
- The package description and keywords no longer name any certification,
  standard or regulation, because Trooth does not offer one.

The Trooth Network is Trooth's only product. This CLI, the public API and the
MCP server are interfaces to it, not separate products.

Trooth automates. Trooth never signs for you.

## License

Apache License 2.0. See [LICENSE](LICENSE).

The same licence applies to this repository, to the `trooth` package on npm and
to the copyright header in `bin/trooth.mjs`. They are meant to agree; if you
ever find that they do not, that is a defect and we want to hear about it at
https://trooth.co/contact.
