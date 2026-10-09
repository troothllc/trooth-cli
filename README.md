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
| `trooth profile <domain>` | Prints the company's complete Trust Profile, section by section: every section the record carries, each fact with its value, who said it and its date when Trooth recorded one ("date unknown" otherwise, never borrowed), and "not published" for a section the company left empty. `--section security,privacy` picks sections by the MCP tool's names; `--json` and `--markdown` print the same profile as one JSON document or as Markdown. The profile is the company's own declared record and is not signed; `verify` checks the one signed object. New in 0.16.4. |
| `trooth verify <domain>` | Checks the record's signed witness statement on your machine, trusting no summary from Trooth: the Ed25519 signature over the exact payload bytes, the key's lifecycle on `api.trooth.co/public/keys`, that it was signed for the domain you asked about, the count identities, and for a v2 statement the SHA-256 of the exact check mapping and of the evidence manifest. `--file` reads a saved profile or statement; `--offline --keys <file>` sends nothing at all; `--save-bundle` keeps every input in one file and `--bundle` checks it later with no network. Statements v1, v2 and v3 (RFC 8785 bytes) are checked. The rules are in [docs/VERIFY.md](docs/VERIFY.md), and [tests/vectors](tests/vectors/vectors.json) holds 27 cases plus 7 bundles any other implementation must agree on. New in 0.7.0; bundles and v3 new in 0.8.0; the witness statement log and corrections new in 0.9.0. |
| `trooth public-record <domain>` | What the company has published outside its own site, read by Trooth from the authorities that hold it: its SEC filer record and filings (10-K, 10-Q, 8-K with item numbers, including material cybersecurity incidents and auditor changes), annual revenue, net income and assets as filed in XBRL, its LEI record and parents, DNS mail authentication beyond SPF and DMARC, certificates for the domain in Certificate Transparency logs, its security.txt, the pages its home page links to, an exact-name check against the OFAC list, SAM.gov registrations and exclusions, patent applications, entries in four state business registries, FTC merger review notices, the domain's registration, the changes those sources record and the subjects the reading names, and the evidence tying each identifier to the domain (its own 10-K's XBRL namespace, or the registry naming the domain). A look-alike site that copies a company's name is reported as a claim, never tied. Each reading is named by its SHA-256 in a statement Trooth signs and logs, and the command checks that statement, its key and its log entry. `--cik`, `--lei` and `--ticker` name the identifier when the site does not. Rules in [docs/EVIDENCE.md](docs/EVIDENCE.md). New in 0.10.0; signed, with the new sources, in 0.11.0; SAM.gov, patents, state registries, merger review, RDAP, changes and subjects in 0.12.0. |
| `trooth mcp-tools [endpoint]` | The MCP servers whose tool lists Trooth reads and logs, or one server's reading: each tool's description and definition hash, the manifest hash, what changed since the last reading, and the signed statement and its log entry, all checked here. `--live` reads the server's tool list from your machine and says whether it is still the one Trooth logged, tool by tool. Rules in [docs/EVIDENCE.md](docs/EVIDENCE.md) section 9. New in 0.12.0. |
| `trooth guard decide` · `guard hook` · `guard ci` · `guard cache` | The guard: before your agent takes a consequential action, it checks the counterparty's signed Trooth records on your machine and applies your written policy, answering allow, hold for a person, or deny with reason codes. It never fails open and never sends the action to Trooth. `hook` is a Claude Code PreToolUse hook; `ci` fails a change that adds an unlisted destination (a URL's host, or a bare host as the whole value of a host-like key such as `host:` or `baseURL`); `cache` saves signed bundles for offline use. Library `trooth/guard` and adapters for the OpenAI Agents SDK, LangChain, LangGraph, plain HTTP and, in Python, CrewAI. Rules in [docs/GUARD.md](docs/GUARD.md); threats and residual risks in [docs/GUARD-THREAT-MODEL.md](docs/GUARD-THREAT-MODEL.md). New in 0.13.0; `ci` reads destinations, not dotted keys, since 0.15.0. |
| `trooth declare init` · `declare sign` · `declare check <domain>` | The domain-signed declaration: `init` makes an Ed25519 key for your domain and keeps it on your machine (mode 0600, never overwritten, never printed); `sign` writes the document you publish at `https://<domain>/.well-known/trooth.json`, naming that key, your products, your APIs (with an MCP server's manifest hash) and your code repositories, and prints the optional `_trooth-key` TXT pin; `check` reads a domain's declaration (no redirects, 64 KB at most) or a file and checks every rule, and reads the pin over DNS over HTTPS. A declaration that checks shows who controlled the site's content when it was read, not the legal entity. Library `trooth/declaration`. Rules in [docs/DECLARATION.md](docs/DECLARATION.md). New in 0.14.0. |
| `trooth log checkpoint` · `log monitor --state <file>` · `log receipt <index>` | Reads and checks the witness statement log ([docs/LOG.md](docs/LOG.md)): its signed checkpoint and which independent witnesses cosigned it, that it only grew since the checkpoint you saved, and the RFC 9942 COSE receipt for one entry. `--witnesses <n>` requires n cosignatures. New in 0.9.0; witnesses and receipts new in 0.11.0; the hardware key's signature reported in 0.12.0. |
| `trooth mirror <dir>` · `mirror --check <dir\|url>` | Keeps a full copy of the witness statement log in the C2SP tiles layout, so it can be served from any static host: every entry is rebuilt into its leaf hash and checked against the signed root before anything is written, the copy only grows by extension of what it holds, and `--from` copies from another mirror with the same checks. `--check` says whether a mirror is compatible: signed checkpoint, entries that hash to it, the tiles its entries make, and a live log that extends it. Rules in [docs/MIRRORS.md](docs/MIRRORS.md). New in 0.16.0. |
| `trooth lint [path]` | Reads the infrastructure the given directory declares and prints those declarations, a coverage report and an aggregate digest of the counts. Local and offline. `path` defaults to `.`. |
| `trooth --help` | Help. Also `-h` and `help`. `trooth <command> --help` (or `-h`, or `trooth help <command>`) prints one command's usage, flags and exit codes, subcommands included (`trooth log monitor --help`), and exits 0. |
| `trooth --version` | Version. Also `-v` and `version`. |

## Flags

`--json` is the flag every command takes; `profile` also takes `--section` and `--markdown`, `lint` takes `--allow-incomplete`, `verify` takes `--file`, `--keys`, `--mapping`, `--manifest`, `--offline`, `--save-bundle`, `--bundle`, `--no-log` and `--log-vkey`, `log monitor` takes `--state`, `log checkpoint` and `log monitor` take `--witnesses`, `log receipt` takes `--out`, every `log` command takes `--log-vkey`, `public-record` takes `--cik`, `--lei`, `--ticker` and `--log-vkey`, `mcp-tools` takes `--live` and `--log-vkey`, `declare` takes `--domain` and `--key`, `declare sign` also `--record`, `--days`, `--out` and the repeatable `--product`, `--api`, `--repo` and `--add-key`, and `declare check` takes `--file`, `--domain` and `--no-dns`. With `--json`, stdout carries exactly one JSON document and nothing else, and every diagnostic goes to stderr. On an error the document is `{"ok": false, "error": "...", "exit": N}`; a non-2xx response adds `http_status`, and `lint` with nothing to read adds `files_opened`. `--help` and `--version` print plain text whether or not `--json` is given.

`public-record` also takes `--timeout <seconds>` (default 45), `mirror` takes `--from` and `--check`, and `guard` takes `--policy`, `--tool`, `--host`, `--args`, `--cache`, `--max-age`, `--offline`, `--base`, `--witness`, `--timeout-ms` and `--log-vkey`. Every command takes `--help` and `-h`.

Any other flag is a usage error. The message names the flag, lists the flags the command takes, and points at `trooth <command> --help`.

## Exit codes

Every command's own codes are listed by `trooth <command> --help`. The table below is all of them.

| Code | Meaning |
|---|---|
| 0 | `check`: listed, and the record carries a dated reading Trooth witnessed. `profile`: a published record was found and printed. `lint`: a complete read of at least one declaration. `verify`: checked. `log checkpoint`, `log monitor`, `log receipt`, `mirror`, `mirror --check`, `mcp-tools`, `declare check`: it checks. `public-record`: the reading names at least one SEC filer (CIK) or LEI for the domain, whatever its status (corroborated, claimed by the site, contradicted). `guard decide`: allow, or the policy does not cover the tool. `guard ci`: no unlisted destination added. `guard cache`: every domain saved. `declare init`, `declare sign`: written. Help and version also exit 0. |
| 1 | No record, or nothing found, and never a judgment. `check`: no published record for the domain (on the labelled fallback read, also a revoked record). `profile`: no published record for the domain; the claim link is printed when the API gives one. `verify`: no published record for the domain, so no statement to check. `lint`: nothing to read. `public-record`: the reading names no SEC filer and no LEI for the domain. That is common (a private company files nothing with the SEC); the rest of the reading is printed, and it says nothing about the company. `log receipt`: the log has no entry with that index. `mcp-tools`: Trooth has no reading of that endpoint. `guard cache`: a domain has no Trooth record. `declare check`: the site answers 404 or 410. |
| 2 | Usage error: a missing argument, an unknown flag or command, input that is neither one domain nor the slug of a Trooth record, a path that does not exist, a file that would be overwritten, or a policy that does not parse. `public-record` also exits 2 when the service refuses the request as malformed (HTTP 400). |
| 3 | Service or contract error: Trooth unreachable or slower than the deadline (15 seconds; 45 for `public-record`, or `--timeout`; `TROOTH_TIMEOUT_MS` sets every command's), a status other than 2xx or the documented not-listed 404, `public-record` rate limited (HTTP 429), a body over its size limit, a body that is not JSON, or a record for a different domain. `mirror`: the log or the source could not be read, including a file missing from a directory. Never an answer about a company. An unexpected failure inside the CLI also exits 3. |
| 4 | `verify`: everything checked held, but the mapping or the manifest was not supplied, so the binding is only partially checked. `lint`: the read was incomplete. A selected file was over the size limit, did not parse or could not be read, or the walk stopped at its file limit. `--allow-incomplete` reports the same and exits 0 (or 1 when nothing was read). `mcp-tools --live`: the server could not be read from this machine. New in 0.5.0. |
| 5 | `check`: the company is listed, but its record carries no reading this CLI can confirm Trooth witnessed. `verify`: the record carries no signed statement to check. New in 0.5.0. |
| 6 | `check`, `profile`, `verify`: the record exists and is withheld while a report about it is reviewed. Neither an absence nor a finding. New in 0.6.0. |
| 7 | Output not delivered: stdout or stderr failed or was closed before everything was written, for example a reader that stopped early (EPIPE) or a full disk. The command's own result was not delivered, whatever it would have been, so this code replaces it. Nothing is retried. Every command but `guard hook`, which exits 2 instead. New in 0.6.1. |
| 8 | `verify`: the statement is malformed, its signature does not check, or its key is not trusted (compromised, revoked, retired before the statement's time, or not on the list). `public-record` and `mcp-tools`: the same, for the statement naming the reading. `declare check`: the signature does not check, or its `kid` is not one of its keys. New in 0.7.0. |
| 9 | `verify`: the signature checks and the key is trusted, but the domain, the check mapping, the evidence manifest or the signed counts do not match what was signed, or the log's receipt does not check. `log checkpoint`: the checkpoint does not check. `log monitor`: the log is not an extension of the checkpoint you saved. `log checkpoint` and `log monitor`: fewer pinned witnesses cosigned than `--witnesses` asks (today no witness follows the log, so any `--witnesses` above 0 exits 9). `log receipt`: the COSE receipt does not check, or `/.well-known/scitt-keys` does not list the log key. `mirror`: the source's entries do not hash to its signed checkpoint, or it does not extend the mirror; `mirror --check`: the mirror is not compatible. `public-record`: the reading is not the one its statement names, or its log receipt does not check. `mcp-tools`: a description or the manifest is not the one its hash names, the statement names another reading, its receipt does not check, or with `--live` the server lists other tools now. `declare check`: another rule fails, or the DNS pin names another key. New in 0.7.0. |
| 10 | `verify`: everything held, and a correction Trooth signed and entered in the log withdraws or replaces the statement. New in 0.9.0. |
| 11 | `declare check`: the declaration checks in every other way, and its `expires_at` has passed. `declare check` also uses 0 (it checks), 1 (the site publishes none), 3 (the site could not be read), 8 (its signature does not check, or its `kid` is not one of its keys) and 9 (another rule fails, or the DNS pin names another key). New in 0.14.0. |
| 20 | `guard decide`: hold. Route the action to a person. New in 0.13.0. |
| 21 | `guard decide`: deny. A proof failed, a rule the policy marks absolute failed, or the policy itself chose deny for an unknown counterparty or an unreachable source. New in 0.13.0. |
| 22 | `guard ci`: the change adds a destination host the policy's `destinations.allowed` does not list. New in 0.13.0. |

`guard hook` follows Claude Code's codes instead of these: 0 for a tool the policy does not cover, an allow, or a hold (the ask JSON on stdout), and 2 for a deny or any failure, because Claude Code lets a tool run on any other code ([docs/GUARD.md](docs/GUARD.md) section 8).

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

**What `check` accepts.** A bare domain or a URL. It is parsed with the standard URL parser, so case, a trailing dot, the default port (80 or 443), a path and an internationalized name (converted to its ASCII form) normalize to one domain, and a leading `www.` is dropped: `https://Trooth.co:443/path` reads `trooth.co`. A URL with a user name or password, a non-default port, an IP address, a scheme other than http or https, or a name with no dot that no Trooth record carries as its slug is a usage error (exit 2) rather than a guess.

**Domain or slug.** `check`, `verify` and `public-record` also take a Trooth slug, as the MCP connector and the A2A agent do: a bare name with no dot, such as `trooth`. It is resolved on the record projection (`GET https://trooth.co/api/network/profile?q=<slug>&contract=2`, one extra request) to the domain of the record that carries exactly that slug, which stderr names (`trooth is a Trooth slug: the record for trooth.co`), and the command then runs on that domain. A record the projection finds by name rather than by slug is offered as a suggestion, never used; a slug no record carries, or one that names more than one record, is exit 2 with the domain to pass when there is one; a projection that cannot be read is exit 3. A domain is never read as a slug. `verify --offline` and `verify --bundle` cannot resolve a slug and take a domain only, and `declare check` and `guard` take domains only, because they read the site or the host itself.

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

## `trooth profile`

```bash
trooth profile trooth.co                          # every section of the Trust Profile
trooth profile trooth --section security,privacy  # a slug works too; two sections
trooth profile trooth.co --json > profile.json    # one JSON document
trooth profile trooth.co --markdown > profile.md  # the same, as Markdown
```

`profile` prints a company's complete Trust Profile, section by section, from the same single request `check` sends: `GET https://trooth.co/api/network/profile?q=<domain>&contract=2` (`TROOTH_WEB` overrides the base). No key, no account. A bare name with no dot is read as a Trooth slug and resolved to its domain first, as for `check`.

Every section the record carries is printed, in the page's order, with its state and who said it, and then each fact with its value, who said it (the company, Trooth's own observation, a named public source) and its date when Trooth recorded one. A fact the record does not date prints **date unknown**: no date is borrowed from the record's update time, a reading's time or another fact. A section the company left empty prints **not published**, a section shared on request only says so, and a section Trooth could not read on that load says it is unavailable, not empty. Notes the record attaches to a section, group or item are printed with it. A fact two sources disagree about is marked contested and every account is listed; Trooth does not choose between them.

**The profile is the company's own declared record, and it is not signed.** Facts Trooth observed are labeled as such, but nothing in the profile carries a signature. Trooth signs one object, the witness statement for a reading it took of the company's public surface; `trooth verify <domain>` checks it on your machine. The output says this at the top, in every form.

```
Trooth   trooth.co   slug trooth
Trust Profile: https://trooth.co/network/company/trooth
record updated 2026-10-06T01:08:12.526Z · record version 8 · read 2026-10-09T20:56:41.921Z

This profile is the company's own declared record, as Trooth publishes it; facts Trooth observed are labeled as such. It is not signed: Trooth signs one object, the witness statement for a reading it took of the company's public surface, and that statement covers the reading, not these facts.
Check that statement yourself: trooth verify trooth.co

== Commercial & pricing (pricing) · published · the company (declared)
   Declared by the company. Trooth publishes it as written and does not certify it. Cite it as the company's own statement.
  Free plan or trial: Fully free
    said by the company (declared) · date unknown
  ...
  List price
    List price: USD 0 for every account
      said by the company (declared) · declared 2026-10-06 · pricing.list-price

== Customer proof (proof) · not published · named customers
   No customer endorsements have been published. ...
  not published
```

### Section names

`--section` takes one or more names, comma-separated or with the flag repeated; the output keeps the page's order. The names are the ones the MCP tool `trooth_public_trust_profile` takes, and they are the record's own section ids (`profile.sections[].id` in the contract 2 body). The record's typed facts (`facts[]`, keyed `<category>.<field>`, the only facts that carry a date) are shown in the section their category belongs to, and each category is also accepted as a section name:

| Section | Record section id | Typed fact categories shown in it (also accepted by `--section`) |
|---|---|---|
| `overview` | `overview` | |
| `identity` | `identity` | `identity`, `registration` |
| `history` | `history` | |
| `funding` | `funding` | |
| `product` | `product` | |
| `pricing` | `pricing` | `pricing`, `pricing-add-ons` |
| `stack` | `stack` | |
| `security` | `security` | `security` |
| `privacy` | `privacy` | `privacy`, `privacy-roles` |
| `ai` | `ai` | `ai-practices` |
| `hosting` | `hosting` | `hosting`, `recovery` |
| `infrastructure` | `infrastructure` | |
| `procurement` | `procurement` | |
| `relationships` | `relationships` | |
| `proof` | `proof` | |
| `people` | `people` | |
| `documents` | `documents` | |
| `evidence` | `evidence` | |
| `cards` | `cards` | |
| `faq` | `faq` | |

A row of the profile is joined to a typed fact only when the two have the same label and the same value in the same section; only then does the row carry the fact's key, origin, source and date (`claim.declaredAt` for a company declaration, else `claim.observedAt`). A typed fact the page does not show is added to its section under "Other recorded facts", so nothing the record carries is dropped; one whose category is in no row above is printed in a final `unsorted` section. A record whose facts run past one page is read to the end from the same record version, or not at all (exit 3).

### `--json` and `--markdown`

`--json` prints one document, described by [schemas/profile-output.v1.schema.json](schemas/profile-output.v1.schema.json) (types `ProfileOutput`, `ProfileSection`, `ProfileFact` in `types/trooth.d.ts`, the Pydantic models and the Go package):

```json
{
  "subject": "trooth.co",
  "query": "trooth",
  "contract": 2,
  "read_at": "2026-10-09T20:56:41.921Z",
  "found": true,
  "signed": false,
  "verify_with": "trooth verify trooth.co",
  "record": { "url": "https://trooth.co/network/company/trooth", "version": 8, "digest": "sha-256=…", "updated_at": "2026-10-06T01:08:12.526Z" },
  "sections": [
    {
      "name": "pricing", "title": "Commercial & pricing", "state": "published",
      "provenance": "company_declared", "said_by": "the company (declared)",
      "facts": [
        { "label": "List price", "value": "USD 0 for every account", "group": "List price", "item": null,
          "provenance": "company_declared", "said_by": "the company (declared)", "key": "pricing.list-price",
          "origin": "company-declared", "source": "https://trooth.co/network/company/trooth",
          "date": "2026-10-06T01:08:12.375Z", "date_kind": "declared", "contested": false, "accounts": [], "signed": false }
      ],
      "notes": [{ "group": "List price", "item": null, "text": "Scope not stated" }]
    }
  ]
}
```

(abridged: the document also carries `withheld`, `name`, `slug`, `claim_url`, `requested_sections`, `profile_present`, and each section its `meaning` and `url`). `date` is `null` where the text says "date unknown". With no published record the document has `"found": false`, empty `sections` and the `claim_url` the API gave, or `null`. `--markdown` prints the same profile as Markdown: a heading per section, a bullet per fact with who said it and its date. `--json` and `--markdown` together are a usage error.

Exit codes: 0, a published record was found and printed; 1, no published record (an honest absence, which says nothing about the company; the claim link is printed when the API gives one); 2, a usage error (not one domain, no record with that slug, an unknown section or flag); 3, Trooth could not be read or answered something that is not the record asked for; 6, the record is withheld while a report about it is reviewed; 7, the output was not delivered.

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
| `.tf` | The HCL reader in `bin/lib/hcl.mjs` (comments dropped, heredocs and templates understood, string escapes decoded, a repeated attribute in one body rejected) | One `resource` block, at any indentation |
| `.tf.json` | `JSON.parse`, with a repeated key in one object rejected and each `resource` level required to be an object or an array of objects | One resource |
| `terraform show -json` plan | `JSON.parse`, with `after_unknown` and `proposed_unknown` merged in, so a value known only after apply is unresolved | One planned managed resource; data sources are skipped |
| Kubernetes YAML (`apiVersion` and `kind`) | The `yaml` package, strict mode; a `List` must carry an `items` array | One document, classified by `kind` |
| Dockerfile | `ENV` and `ARG` instructions only, from logical lines formed as the build forms them: continuations joined with nothing inserted, comment lines inside a continuation dropped, the `# escape=` directive honored | The file |

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
| `TROOTH_API` | Base URL of api.trooth.co: the key list, the witness statement log, `public-record`, `mcp-tools`, `guard` and `check`'s labelled fallback. Defaults to `https://api.trooth.co`. `lint` ignores it, because `lint` makes no requests. |
| `TROOTH_WEB` | Base URL of the record projection (`/api/network/profile`), read by `check`, `profile`, `verify`, a slug's resolution and `guard`. Defaults to `https://trooth.co`. |
| `TROOTH_TIMEOUT_MS` | The deadline for each request, for every command. When unset: 15000, and 45000 for `public-record` (whose `--timeout <seconds>` takes precedence over this variable). The minimum is 1000. |
| `TROOTH_PROGRESS` | `1` prints `public-record`'s "reading in progress" note on stderr even when stderr is not a terminal; `0` never prints it. By default it is printed only on a terminal, after 5 seconds. |
| `TROOTH_LINT_MAX_FILES` | The number of selected files after which `lint` stops walking and reports the read as truncated. Defaults to 5000. |
| `TROOTH_DOH` | The DNS-over-HTTPS endpoint (`application/dns-json`) `declare check` reads the `_trooth-key` TXT record from. Defaults to `https://cloudflare-dns.com/dns-query`. |
| `NO_COLOR` | Disables ANSI color. Color is already off when stdout is not a TTY. |

There is no API key. The binary asks for no credential of any kind and has no write path.

## From an AI assistant

The same public Network powers Trooth's read-only MCP server, so ChatGPT, Claude, Cursor or any MCP client can ask about a company in plain words:

```
https://api.trooth.co/public/mcp
```

Five read-only tools on public data, no key. A sixth reads a signed-in company's own record with an OAuth access token from the authorization server the server's protected-resource metadata names; no scope is required, and the workspace is linked when that person signs in to trooth.co once with Continue with enterprise SSO. The pattern is written up at [trooth.co/docs/agents](https://trooth.co/docs/agents).

## `trooth verify`

```
$ trooth verify trooth.co
trooth.co  witness statement v2, read 2026-10-06
  signature  valid (Ed25519, key trooth-master-2026-09, active)
  subject    trooth.co, the domain asked about
  mapping    matches (check mapping 1.0.1, sha256:6fea8a0f…)
  manifest   matches (100 entries, sha256:726b6edc…)
  counts     hold (65 read, 65 as expected, 35 not read)

Checked. A valid v2 signature shows that Trooth's key signed these outcome bytes together with the digest of the exact check mapping, the evaluator version, the subject scope and the digest of the evidence manifest. It does not establish the company's identity, an independently established time, or anything the reading did not read.
```

It reads three things: the record (`trooth.co/api/network/profile`), the key list (`api.trooth.co/public/keys`) and the check mapping the statement names (only from `trooth.co/standard/check-mapping/`). Then it decides for itself. Every result names the statement by `trooth:statement:<sha256 of the payload bytes>` ([docs/IDS.md](docs/IDS.md)).

To keep what you checked, and check it again later with no network at all:

```
trooth verify trooth.co --save-bundle trooth.co.bundle.json
```

```
trooth verify --bundle trooth.co.bundle.json
```

A bundle carries the statement, the evidence manifest, the key list with the time it was read, and the exact mapping bytes. It is only as fresh as its key list. You can also save the inputs separately and run `trooth verify <domain> --file profile.json --keys keys.json --mapping 1.0.1.json --offline`.

`verify` exits 0 when the statement is checked, 1 when the domain has no published record (there is nothing to check), 2 for a usage error, 3 when the record, the key list or the mapping cannot be read, 4 when it is only partially checked (a mapping or manifest not supplied), 5 when the record carries no signed statement, 6 when the record is withheld, 8 when the statement is not trusted, 9 on a mismatch and 10 when it is superseded ([docs/VERIFY.md](docs/VERIFY.md) section 5).

### The witness statement log

Every statement Trooth publishes, and every correction it issues, is entered in one public append-only log ([docs/LOG.md](docs/LOG.md)): an RFC 9162 Merkle tree with a C2SP checkpoint signed by a log key that signs nothing else ([docs/KEY-CEREMONY.md](docs/KEY-CEREMONY.md)). `trooth verify` asks the log for the statement and adds a line:

```
  log        included, entry 41 of a signed tree of 42 (log key pinned in trooth 0.9.0)
```

If Trooth has signed and logged a correction withdrawing or replacing the statement, the verdict is **Superseded** and the exit code is 10. Anyone can check the log only ever grows:

```
trooth log monitor --state trooth-log-state.json
```

This repository runs that check every hour (`.github/workflows/log-monitor.yml`).

The log asks independent witnesses of the [witness network](https://witness-network.org) to cosign each checkpoint ([docs/LOG.md](docs/LOG.md) section 7): a witness cosigns only after checking the new tree extends the last one it saw, so a cosigned checkpoint cannot have been shown to you while a different history was shown to someone else. `trooth log checkpoint` says which of the witnesses pinned in this release cosigned, and `--witnesses <n>` makes it exit 9 unless at least n did. **Today no witness follows the log yet, so every checkpoint carries no cosignature and any `--witnesses` above 0, `--witnesses 2` included, exits 9.** The flag is there for when the witness network follows the log; until then, leave it out (or use `--witnesses 0`) in anything that must pass.

For SCITT tooling each entry also has an RFC 9942 COSE receipt, checked against the log key published at `https://api.trooth.co/.well-known/scitt-keys`:

```
trooth log receipt 0 --out entry-0.cose
```

### In your own code

The same checks, passing the same test vectors, in three languages:

| Language | Install | Call |
|---|---|---|
| JavaScript, TypeScript | `npm install trooth` | `import { verifyStatement, verifyBundle } from 'trooth/verify'` (types included) |
| Python 3.9+ | `pip install "git+https://github.com/troothllc/trooth-cli#subdirectory=sdk/python"` | `from trooth_verify import verify_bundle` ([sdk/python](sdk/python)) |
| Go 1.21+ | `go get github.com/troothllc/trooth-cli/sdk/go@latest` | `trooth.VerifyBundle(doc, nil)` ([sdk/go](sdk/go)) |

[schemas/](schemas) holds JSON Schema for every document involved (statement, payload v1 to v3, key list, evidence manifest, bundle, result, log receipt, correction, public record), each served at `https://trooth.co/schemas/<file>`, with TypeScript, Pydantic and Go types generated from them.

A checked statement means Trooth's key signed that reading for that domain. It does not mean the company is safe, compliant or authorized for anything; what to do with it is your decision.

## `trooth public-record`

```
$ trooth public-record apple.com
apple.com  public record, read 2026-10-07
  site names   Apple Inc. (https://apple.com/)
  entity       trooth:entity:lei:HWUPKR0MPOU8FGXBT394 Apple Inc. (the LEI binding is corroborated and so is the SEC filer binding)
  SEC filer    CIK 0000320193  corroborated the 10-K filed 2025-10-31 declares its extension taxonomy under www.apple.com
  LEI          HWUPKR0MPOU8FGXBT394  corroborated the LEI record and the SEC filer 0000320193 name the same entity, and the filer's own filing ties it to apple.com
  filings      10-K 2025-10-31 · 10-Q 2026-07-31 · 8-K 2026-07-30 · DEF 14A 2026-01-08
  revenue      416,161,000,000 USD (year ending 2025-09-27, 10-K filed 2025-10-31)
  certificates 5 unexpired for apple.com in CT logs · issuers Apple · soonest expiry 2026-10-20
  security.txt https://security.apple.com (expires 2027-07-10)
  sanctions    no OFAC SDN entity with the name Apple Inc.
  signature    signed by trooth-master-2026-09, and entry 12 of the log
```

Every fact carries the URL of the regulator or registry it came from (`--json`), and every response read is listed with its SHA-256. A filing is the company's own statement to its regulator, not Trooth's finding; a sanctions entry with the same name is not an identification. The statement naming the reading is checked here: the reading's RFC 8785 SHA-256, the signature and its key on `api.trooth.co/public/keys`, and its entry in the log ([docs/EVIDENCE.md](docs/EVIDENCE.md) section 5). The signature says what Trooth read and when, not that the sources are right. A reading is cached for a day. A first reading of a domain is taken live from every source and takes 20 to 40 seconds, so `public-record` waits up to 45 seconds for each request (`--timeout <seconds>` changes it, from 1 to 600; `TROOTH_TIMEOUT_MS` sets it in milliseconds when `--timeout` is not given), and on a terminal it prints a note on stderr after 5 seconds saying a reading is in progress (`TROOTH_PROGRESS=1` prints it anywhere, `TROOTH_PROGRESS=0` never). A reading that does not finish in time is exit 3; one that finishes is cached, so running the command again a minute later usually answers at once.

Exit 0 when the reading names at least one SEC filer (CIK) or LEI for the domain, whatever its status (corroborated, claimed by the site, contradicted). Exit 1 when it names neither: the rest of the reading is still printed, and it says nothing about the company (a private company files nothing with the SEC). Exit 2 for a usage error, including a request the service refuses as malformed (HTTP 400); 3 when the service cannot be read, does not answer in time, is rate limited (HTTP 429), or answers with something that is not a reading of the domain; 8 when the statement's signature or key does not hold; 9 when the reading is not the one its statement names or its log entry does not check. A reading that carries no signature does not change the exit code; the signature line says why.

## `trooth mcp-tools`

```
$ trooth mcp-tools https://api.trooth.co/public/mcp --live
https://api.trooth.co/public/mcp  trooth-mcp 1.4.1, read 2026-10-07
  tools      8 · manifest fedd1d2372462de065ba6046e45eac33c97ad628d13c910d3bcc2f8b8054e058
             trooth_ask                   description c4fd0e4105e1… definition aa35823cf04d…
             …
  signature  signed by trooth-master-2026-09, and entry 14 of the log
  live       the server lists the same tools now, byte for byte (8 tools)
```

An agent decides what a tool does from the description the server lists, and a server can change it after it was reviewed. Trooth reads the tool lists of MCP servers once a day with no credentials, hashes each tool's description and its whole definition, and signs and logs a statement naming the manifest whenever it changes, so the log is each server's history of tool changes. This command recomputes every hash, checks the statement and its receipt, and with `--live` compares the server's tools now with what Trooth logged: exit 9 when they differ. A hash says what the server listed, not what a tool does.

## Changed in 0.16.4

- New `trooth profile <domain|slug>`: the company's complete Trust Profile, section by section, each fact with its value, who said it and its date when one is recorded ("date unknown" otherwise), and "not published" for a section the company left empty. `--section` takes the MCP tool's section names; `--json` (schema `profile-output.v1`) and `--markdown` print the same profile. It says, in every form, that the profile is the company's own declared record and is not signed, and points at `trooth verify`.

## Changed in 0.16.3

- `trooth <command> --help` and `-h` work for every command and subcommand (`trooth log monitor --help`, `trooth guard decide -h`, `trooth declare check --help`), and so does `trooth help <command> [<subcommand>]`: each prints that command's usage, flags, exit codes and examples, and exits 0. Up to 0.16.2 every one of them exited 2 with "unknown flag --help".
- `public-record` waits up to 45 seconds for each request (a first reading takes 20 to 40), `--timeout <seconds>` changes it, and on a terminal a note after 5 seconds says a reading is in progress. A reading that runs out of time says what to do next. Other commands keep 15 seconds.
- `check`, `verify` and `public-record` accept a Trooth slug (`trooth check trooth`), as the MCP connector and the A2A agent do, resolved on the record projection to its domain. A name that is not a slug any record carries is a usage error that names the domain to pass when the projection suggests one.
- `trooth guard decide --json` for a tool the policy does not cover is now described by a schema: `GuardNotCovered` in `schemas/guard-decision.v1.schema.json`, and `schemas/guard-decide-output.v1.schema.json` accepts either a decision or that document. The output itself is unchanged.
- The exit codes are documented in full: 20, 21 and 22 in the table above, exit 1 for `verify`, `public-record` and `log receipt`, and every code each command uses in its own `--help`. The `--witnesses` examples say plainly that no witness follows the log yet, so any value above 0 exits 9 today.

## Changed in 0.16.0

- New `trooth mirror <dir>` and `trooth mirror --check <dir|url>`: a full, append-only copy of the witness statement log that anyone can serve and anyone can check ([docs/MIRRORS.md](docs/MIRRORS.md)). The trooth-cli repository runs one every day on GitHub's runners (`.github/workflows/log-mirror.yml`).
- [docs/DECLARATION.md](docs/DECLARATION.md) section 8: IANA considerations for `/.well-known/trooth.json` and the `_trooth-key` DNS node name, and how the format changes. Neither registration has been submitted.

## Changed in 0.15.0

- `trooth guard ci` reads destinations, not dotted keys: the host of an http(s) or ws(s) URL, always, and a bare host name only as the whole value of a host-like key or argument (`host`, `domain`, `endpoint`, `url`, `baseURL`, `to` and the rest), in lowercase with a top-level domain from a curated list. i18n keys and dotted identifiers such as `"page.docs.cli.guardTitle"` are no longer reported ([docs/GUARD.md](docs/GUARD.md) section 7).
- The guard's internal review gate: property-based fuzzing of the policy parser and the decision path in `npm test` (`tests/guard-fuzz.test.mjs`; four defects it found are fixed), GitHub CodeQL in CI, and a threat model with its residual risks ([docs/GUARD-THREAT-MODEL.md](docs/GUARD-THREAT-MODEL.md)).
- The Trooth-run pilots are in `pilots/` and run every night against the latest releases of the agent frameworks ([docs/GUARD-PILOTS.md](docs/GUARD-PILOTS.md)).
- Phase 4 exit, as amended on 2026-10-07: an internal review gate and Trooth as the first production user stand before launch; an outside security review and outside production use move to the launch phase. Neither has happened ([docs/GUARD.md](docs/GUARD.md) section 13).

## Changed in 0.14.0

- New `trooth declare init|sign|check` and the `trooth/declaration` library: a company signs, with its own Ed25519 key, a declaration it publishes at `/.well-known/trooth.json` naming that key, its products, its APIs and its repositories, with an optional DNS pin of the key ([docs/DECLARATION.md](docs/DECLARATION.md)). Exit 11 is new: the declaration expired.
- `trooth public-record` prints the reading's proofs (method and status: the domain bound to the company record, to the company's own key, to a repository) and its declaration line ([docs/EVIDENCE.md](docs/EVIDENCE.md) 1.4, section 11). New ids `company`, `product`, `person`, and a company key id ([docs/IDS.md](docs/IDS.md) 1.5).
- The guard reads `domain_control_confirmed` from the signed public record: a confirmed proof by `dns_txt`, `domain_email_code`, `identity_provider_sign_in` or `domain_signed_declaration` binding the domain to the company record or its declaration key ([docs/GUARD.md](docs/GUARD.md) section 4).

## Changed in 0.13.0

- New `trooth guard` and the `trooth/guard` library: a pre-execution check for consequential agent actions under your own policy, with adapters for the OpenAI Agents SDK, LangChain, LangGraph, plain HTTP and Claude Code, and a Python package for CrewAI and the Python frameworks ([docs/GUARD.md](docs/GUARD.md), [docs/GUARD-ADAPTERS.md](docs/GUARD-ADAPTERS.md)).
- `trooth public-record` readings carry the proof method of each binding, evidence classes with their freshness and what each does not establish, continuity with the previous reading, and representative and signing-authority subjects ([docs/EVIDENCE.md](docs/EVIDENCE.md) 1.3, [docs/IDS.md](docs/IDS.md) 1.4).

## Changed in 0.12.0

- New `trooth mcp-tools [endpoint] [--live]`: the MCP servers whose tool lists Trooth logs, and one server's description and definition hashes, checked, and compared with what the server lists now ([docs/EVIDENCE.md](docs/EVIDENCE.md) section 9). Log entries gain the kind `mcp_tools`; the Python and Go packages accept it.
- `trooth public-record` shows SAM.gov registrations and exclusions, patent applications, exact-name entries in the New York, Colorado, Connecticut and Oregon business registries, FTC merger review notices, the domain's registration from RDAP, the changes those sources record, and every subject the reading names ([docs/EVIDENCE.md](docs/EVIDENCE.md) 1.2, [docs/IDS.md](docs/IDS.md) 1.3).
- `trooth log checkpoint` reports whether the log's hardware key, made inside AWS KMS in ceremony v2 and pinned here as `HARDWARE_LOG_VKEY`, also signed the checkpoint ([docs/KEY-CEREMONY.md](docs/KEY-CEREMONY.md) 1.2, [docs/LOG.md](docs/LOG.md) 1.2).

## Changed in 0.11.0

- `trooth log checkpoint` and `trooth log monitor` report which of the witnesses pinned in this release cosigned the checkpoint (c2sp.org/tlog-cosignature), and `--witnesses <n>` requires n of them. New `trooth log receipt <index>` fetches and checks an entry's RFC 9942 COSE receipt and confirms the key set at `/.well-known/scitt-keys` lists the log key ([docs/LOG.md](docs/LOG.md) 1.1).
- `trooth public-record` checks the signed statement each reading now carries, shows the legal entity's id (`trooth:entity:lei:` or `trooth:entity:cik:`, [docs/IDS.md](docs/IDS.md) 1.2), certificates in CT logs, security.txt, the pages the home page links to, and an exact-name OFAC check ([docs/EVIDENCE.md](docs/EVIDENCE.md) 1.1).
- [docs/KEY-CEREMONY.md](docs/KEY-CEREMONY.md) 1.1 records the first key drills and the rule that a witnessed log changes key by changing origin. Vectors in `tests/vectors/witness-cose.json`.

## Changed in 0.10.0

- New `trooth public-record <domain>`: the company's SEC filer record and filings, annual XBRL values, LEI record and parents, and DNS mail authentication, each with its source, and each identifier tied to the domain only by evidence ([docs/EVIDENCE.md](docs/EVIDENCE.md), which also lists everything a company publishes and what Trooth reads of it).
- Schema `public-record.v1` with generated types; stable ids `trooth:cik:` and `trooth:lei:` ([docs/IDS.md](docs/IDS.md) 1.1).

## Changed in 0.9.0

- `trooth verify` checks the statement against Trooth's witness statement log: a receipt that checks against a checkpoint signed by the pinned log key, and any logged correction. New verdict `superseded`, exit 10. `--no-log` skips the log; `--log-vkey` checks against another key. Bundles carry the log's answer, so the log part is checked offline too.
- New `trooth log checkpoint` and `trooth log monitor --state <file>`.
- [docs/LOG.md](docs/LOG.md) (the log, receipts, corrections, monitoring) and [docs/KEY-CEREMONY.md](docs/KEY-CEREMONY.md); [docs/VERIFY.md](docs/VERIFY.md) is version 1.2.
- Two new schemas (log receipt, correction), the package exports `trooth/tlog`, and the Python (0.2.0) and Go verifiers check receipts and corrections too. 20 new log vectors, checked by Go's `golang.org/x/mod/sumdb` as well.

## Changed in 0.8.0

- `trooth verify --save-bundle <file>` writes every input to one portable file; `trooth verify --bundle <file>` checks it with no network. Every result now carries `statement_id`.
- Statement v3 is checked: RFC 8785 canonical bytes, the subject named by `trooth:domain:<domain>` and the signing key named inside the signed bytes. Trooth still signs v2; v1 and v2 check exactly as before. [docs/VERIFY.md](docs/VERIFY.md) is now version 1.1, and [docs/IDS.md](docs/IDS.md) defines stable ids.
- JSON Schemas in [schemas/](schemas), generated types, and the package exports `trooth/verify`, `trooth/jcs`, `trooth/ids` and `trooth/schemas/*` for use as a library. Python and Go verifiers in [sdk/](sdk) run the same vectors.
- 9 new vectors (27 in all) and 7 bundles, one of them a real bundle saved from trooth.co.

## Changed in 0.7.0

- New command `trooth verify <domain>`, with the normative rules in [docs/VERIFY.md](docs/VERIFY.md) and 18 test vectors in [tests/vectors](tests/vectors/vectors.json), reproducible byte for byte with `node tests/vectors/generate.mjs --check`. Exit codes 8 and 9 are new.
- `check` still checks no signature and still prints `signature_checked: false`; its closing line now names `trooth verify` as the way to check.

## Changed in 0.6.1

See [CHANGELOG.md](CHANGELOG.md) for the full entry.

- `--json` output is no longer cut short when stdout is a pipe. The CLI waits for its output to be written before it ends, and a reader that stops early gets exit 7, never a success code.
- `lint` reads four more cases correctly: malformed nested shapes and repeated attributes are invalid (exit 4), plan values unknown until apply are unresolved, HCL string escapes are decoded, and Dockerfile continuations are joined as the build joins them.
- The GitHub Action installs the CLI into a fresh directory on every run and never reuses one left by an earlier step or runner.

## Changed in 0.6.0

See [CHANGELOG.md](CHANGELOG.md) for the full entry.

- `check` reads the one record projection, `GET https://trooth.co/api/network/profile?q=<domain>&contract=2`, instead of the directory feed. Its output carries the same facts, the same per-fact provenance and the same record version as the website, the REST API, the MCP server and the llms.txt twin. `--json` carries the projection body whole under `record`, and `source` says where the answer was read and at which record version.
- The directory feed is read only when the projection cannot be reached, and that answer is labelled a fallback everywhere it appears. `--no-fallback` turns it off.
- Exit 6 is new: the record is withheld while a report about it is reviewed.
- `check --json` no longer emits `badge_id`, `attested`, `events`, `receipt_signature` or `first_published_at` from a projection read, because the projection does not carry them; a fallback read still does. It adds `slug`, `first_witnessed_at`, `coverage`, `facts_published`, `facts_contested`, `source` and `record`.
- Releases are published from GitHub Actions with npm trusted publishing and a provenance statement (`.github/workflows/publish.yml`).

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
