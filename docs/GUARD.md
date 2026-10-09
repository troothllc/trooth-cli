# The Trooth guard

`trooth/guard` (bin/lib/guard.mjs) and `trooth guard` (bin/trooth.mjs). Licensed under the Apache License, Version 2.0, like the rest of this repository.

## 1. What it is

The guard is a small library that runs inside your agent. Before a consequential tool call (a payment, a contract signature, sending data outside the company, creating an account with a vendor, installing an MCP server) it:

1. decides whether the call is one your policy covers (reads and everything else pass straight through),
2. finds the host the call is about, from typed arguments only,
3. reads Trooth's signed, logged artifacts for that host, from a cached bundle or the network,
4. checks every signature, key, log proof and witness cosignature on your machine,
5. applies your written policy and answers `allow`, `hold` (route to a person) or `deny`, with reason codes.

The answer is about the ACTION your agent is about to take, under YOUR policy. It is not a statement about the company. Missing or stale evidence routes to a person; only a failed proof or a rule you marked absolute stops the action.

```js
import { loadPolicy, createGuard } from 'trooth/guard';

const guard = createGuard({
  policy: await loadPolicy('./policies/vendor-payments.yaml'),
  cache: { dir: '.trooth-cache', maxAgeSeconds: 900 },
  failMode: 'hold',                       // 'allow' is refused
});

const d = await guard.decideToolCall({ name: 'stripe.create_payout', arguments: { url: 'https://api.acme.com/pay' } });
// d is null when the policy does not cover the tool; otherwise a decision
// that validates against schemas/guard-decision.v1.schema.json.
```

The public API is `parsePolicy`, `loadPolicy`, `createGuard` (with `applies`, `targetHost`, `decide`, `decideToolCall`, and `saveBundle` for the cache), `PolicyError` and `GUARD_DECISION_SCHEMA`. Types are in types/guard.d.ts.

## 2. Where it runs, and what it sends

The guard runs in your process (or as a CLI your agent's host calls). Trooth never sees the action. The requests it makes carry only a domain (the host being checked, or a parent domain of it) or a statement id:

| Request | Why |
|---|---|
| `GET {web}/api/network/profile?q=<domain>&contract=2` | whether a record exists, and its signed witness statement |
| `GET {api}/public/keys` | the key list, to check signatures and key status at signing time |
| `GET {api}/scan/log/v1/lookup?statement_id=…` and `/corrections?statement_id=…` | the log receipt and any correction |
| `GET {api}/scan/log/v1/checkpoint` and `/proof/consistency?first=…&second=…` | the checkpoint the witnesses cosigned, tied to the receipt's tree |
| `GET {api}/scan/public-record/<domain>?cached=only` | the signed public record reading, from the cache only; the guard never starts a reading |
| `GET {web}/standard/check-mapping/<file>.json` | the check mapping a witness statement names, and only under that prefix |

The tool name, the arguments, any amount and any data class stay on your machine; the decision's `action` field names the tool, the host and the argument names (never their values) and is stored only where you store the decision. Every request has a deadline (`timeoutMs`, default 10000) and a size limit, the whole decision has one deadline (`deadlineMs`, default 30000; past it the decision is `hold`, `SOURCE_UNREACHABLE`), uses `redirect: 'error'`, and never follows a URL found inside a record or a vendor's content. Every HTTPS request also carries your IP address, as any request does.

## 3. The policy

A policy is YAML (a strict subset, bin/lib/yaml-lite.mjs) or JSON, described by schemas/guard-policy.v1.schema.json:

```yaml
policy: vendor-payments
version: 3
applies_to:
  tools: ["stripe.create_payout", "mcp__bank__*"]
  http: [{ method: "POST", host: "*.example-bank.com" }]   # for the http adapter
host_from: ["url", "endpoint", "host", "domain", "base_url", "webhook_url", "email", "to"]
log: { required: true, min_witnesses: 1 }
rules:
  - id: legal-entity
    require: { claim: legal_entity_registry_record, max_age_days: 365 }
    on_fail: hold
  - id: no-sanctions-match
    require: { claim: no_sanctions_name_match, max_age_days: 7 }
    on_fail: hold
  - id: no-compromised-keys
    require: { signature: valid, key_status: [active, retired_before_use] }
    on_fail: deny
    absolute: true
destinations: { allowed: ["api.stripe.com"] }
unknown_counterparty: hold     # hold | deny
source_unreachable: hold       # hold | deny
```

The YAML subset takes block mappings, block lists (including lists of mappings), one-line flow lists and maps, plain and quoted scalars, comments, decimal integers, `true`, `false` and `null`. It refuses tabs in indentation, anchors, aliases, tags, block scalars, multiple documents, duplicate keys, fractions and words like `yes` and `on` that YAML readers disagree about, each with a line number.

The policy is refused (PolicyError) for an unknown key, a wrong type, a duplicate rule id, an unknown claim, `allow` for `source_unreachable` or `unknown_counterparty`, any `failMode` key in the policy (`failMode: allow` is named as refused), `on_fail: deny` without `absolute: true`, `absolute: true` with `on_fail: hold`, a wildcard host pattern other than `*.` followed by a domain of at least two labels, and a policy that covers nothing. Defaults: `log.required` true, `log.min_witnesses` 1, `on_fail` hold, `unknown_counterparty` hold, `source_unreachable` hold, `host_from` the list above.

The policy's `sha256` is the SHA-256 of the RFC 8785 canonical JSON of the document as parsed, so the YAML and JSON forms of one policy have one hash. Each decision names the policy by id, version and that hash.

### Interception

`applies(tool)` matches `applies_to.tools`, where `*` stands for any run of characters. To fail toward checking, a tool name is also covered when it matches once case and Unicode compatibility forms are folded (`STRIPE.create_payout`, fullwidth letters), and any tool name that is not plain printable ASCII is covered, because a look-alike letter cannot be told apart from the real one by rule.

`targetHost(toolCall)` reads only the fields in `host_from` (dotted paths such as `payee.website` are allowed). A value that is an http or https URL gives its host; an email address (also `Name <a@b>` and `mailto:`) gives its domain; a bare host name gives itself. Other schemes give nothing. A host field whose value could name a destination but gives no single host (`evil.com/pay`, `ftp://evil.com`, a list of addresses, a value with a backslash) makes the call ambiguous, so another field cannot decide the target alone. Prose fields (a description, a memo, a message body) are never read. When the typed fields name more than one host, or none, the decision is `hold` with `EVIDENCE_MISSING` and `needed: "target_host"`. An IP address, `localhost` or a single-label name has no Trooth record: `NO_RECORD`, with no request sent.

The guard looks up the exact host, then each parent domain down to two labels (`pay.eu.acme.com`, `eu.acme.com`, `acme.com`), and stops before a domain under which unrelated parties each get a name (`github.io`, `vercel.app`, `co.uk` and others in `SHARED_SUFFIXES`; this is a short list, not the Public Suffix List). If a source cannot be reached for one candidate, the guard does not move on to a parent; the decision is `SOURCE_UNREACHABLE`.

## 4. The claims, and where each comes from

Every claim comes from a signed artifact that the guard checked locally. A claim stands only on a valid signature by a key that was trusted when it signed.

| Claim | Source | Present when | Default freshness |
|---|---|---|---|
| `trooth_reading` | the witness statement in the projection, checked with `verifyStatement` | a signed reading of the domain exists; observed at its `read_at` | 30 days |
| `check:<check_id>` | the same statement | that check's outcome was "as expected" | 30 days |
| `legal_entity_registry_record` | the public record statement | `entity` is not null (a corroborated binding) | `registry_record` (365 days), else `regulator_filing` |
| `no_sanctions_name_match` | the public record statement | the sanctions list was read and no entry has the same name | `sanctions_list` (7 days) |
| `no_sam_exclusion_name_match` | the public record statement | SAM.gov was read and no exclusion has the same name | `procurement_exclusion` (7 days) |
| `domain_registration_record` | the public record statement | `domain_registration` is present | `domain_registration` (30 days) |
| `security_txt_published` | the public record statement | `security_txt` is present and not expired | `site_publication` (30 days) |
| `domain_control_confirmed` | the public record statement (since trooth 0.14.0) | a proof in `proofs` binds `trooth:domain:<domain>` to a `trooth:company:<slug>` record or to `trooth:key:<domain>#<thumbprint>`, by `dns_txt`, `domain_email_code`, `identity_provider_sign_in` or `domain_signed_declaration`, with status `confirmed`; observed at the proof's `observed_at` (never later than the reading) | `trooth_claim_record` (365 days) for the company record, `domain_declaration` (30 days) for the declaration key |

The public record statement is checked the way `trooth public-record` checks it: the record without `signed` is canonicalized with RFC 8785, its SHA-256 must equal `signed.record_sha256` and the statement payload's `record_sha256`; the payload must be RFC 8785 bytes signed with Ed25519, name the envelope key as its signer, and name this reading's domain, `read_at` and `subject_id`; the signature must check against the key list, and the key must have been trusted at `issued_at`; the log receipt (entry kind `public_record`) must check against the pinned log key.

Freshness: a rule's `max_age_days` when it gives one, else the stale-after time of the claim's evidence class from the record's `evidence_classes` (falling back to the scan worker's own default days when a record carries no `evidence_classes`). A claim with no known freshness window, or observed more than five minutes in the future, is stale.

Each claim carries `fact_id` (`trooth:statement:<sha256>#<claim>`), `statement_sha256`, `log_index`, `observed_at` and `stale_after`, and appears in the decision's `evidence`.

`domain_control_confirmed` is a signed claim since trooth 0.14.0. It comes from the `proofs` in the signed public record ([EVIDENCE.md](EVIDENCE.md) section 11), checked with the rest of that record, and nowhere else. A proof counts only when it binds the domain to the company record or to the company's own declaration key, its method is one of the four that show control of the domain, and its status is `confirmed`. A proof that is `claimed`, `not_found` or `not_read`, a proof by any other method (`repository_control`, `registry_record` and the rest), and a proof binding anything else (a repository, another domain's key, Trooth's own key) leave the claim missing, and a rule requiring it holds with `EVIDENCE_MISSING`. When several proofs qualify, the one that stays fresh longest counts. What the claim shows is control of the domain: at claim time for Trooth's record, or of the site's content when Trooth read the declaration. It does not establish the legal entity, or that a person may act for it.

## 5. The decision table

The decision is a pure function, `decideFrom(facts, policy)` in bin/lib/guard-decide.mjs, over abstract facts the evidence step produces. No model reads prose at this step.

0. No single host in the typed arguments: `hold`, `EVIDENCE_MISSING`, `needed: "target_host"`.
1. No record source reachable and no cached bundle: `source_unreachable` (hold by default), `SOURCE_UNREACHABLE`. A guard created with `failMode: 'deny'` makes this deny; it can never make it allow.
2. No record for the host or a parent domain: `unknown_counterparty` (hold by default), `NO_RECORD`.
3. A version this guard does not read (projection contract, witness statement version, public record format): `hold`, `SCHEMA_UNSUPPORTED`.
4. Signature invalid (including record bytes that are not the bytes signed, a binding or count that disagrees with what was signed, and a key id not on the list): `deny`, `SIGNATURE_INVALID`. Key not trusted at signing time (unknown, revoked, compromised, retired before the signature): `deny`, `KEY_NOT_TRUSTED`. A signed subject that is not the host or a parent of it: `deny`, `SUBJECT_MISMATCH`.
5. Log: a proof that does not check (a forged checkpoint, a wrong index, a changed proof hash): `deny`, `NOT_IN_LOG`. Not logged, the log not readable, or fewer than `min_witnesses` pinned witnesses cosigned a checkpoint covering the entry: `hold`, `NOT_IN_LOG`, with a detail. Even with `log.required: false`, a statement whose corrections the log could not be asked about gives no claims (a correction cannot be ruled out), so its rules hold with `EVIDENCE_MISSING`.
6. Each rule: claim missing: `EVIDENCE_MISSING` with `needed`; older than allowed: `EVIDENCE_STALE`; the statement superseded by a correction Trooth signed and logged, or the record withheld while a report about it is reviewed: `EVIDENCE_DISPUTED`; these hold. A rule marked absolute that fails: `deny`, `ABSOLUTE_RULE_FAILED`, with the cause in `detail`.
7. Any deny, deny; else any hold, hold; else allow, with `RULE_PASSED` per rule.

Witness cosignatures are counted on the checkpoint `/checkpoint` serves, when its tree is the receipt's tree or a consistency proof shows it extends it; cosignature lines on the receipt's own checkpoint also count. Only the pinned witnesses (bin/lib/log-trust.mjs `PINNED_WITNESSES`, or the `witnesses` option) count.

Invariants, checked exhaustively (section 9): allow implies every required check held; source unreachable never yields allow; deny happens only for a failed proof or an absolute rule, or where the customer's policy itself chose deny for no record or no source; the same inputs always give the same decision.

Reason `detail` strings are written by the guard. A value taken from a served document (a domain, a version string) is reduced to characters that cannot carry an instruction before it is placed in a detail; no vendor text is copied into a decision.

## 6. Offline mode and the cache

`createGuard({ cache: { dir, maxAgeSeconds } })` reads a cached bundle for each candidate domain before the network and uses it when it is younger than `maxAgeSeconds` (default 900). After a network read the guard saves the bundle there. A bundle (`trooth.guard-bundle.v1`) holds the projection's answer, the key list, the witness statement as a `trooth.verification-bundle.v1` (the existing bundle format, with its log receipt and corrections), the signed public record answer with its corrections, and the cosigned checkpoint with consistency proofs. Everything in it is checked again on every read, against the log key and witnesses pinned in the guard, never against a key the bundle carries.

`offline: true` reads only cached bundles, of any age, and sends nothing. The facts in a bundle are still held to their own freshness, so an old bundle ends in `EVIDENCE_STALE`. No bundle means `SOURCE_UNREACHABLE`, so hold. A key compromised after the bundle was saved is not known offline; refresh the cache (`trooth guard cache`) as often as your policy needs.

## 7. CI mode

`trooth guard ci --policy <file> [--base <ref>] [paths...]` reads the lines a change adds (`git diff --unified=0 <base>...HEAD`, default base `origin/main`) or the given files, and finds the destinations they name. Each destination not in `destinations.allowed` is printed with `file:line`, and the command exits 22. When the policy lists `destinations.watch`, only hosts a watch pattern covers are reported; with no watch list, every new destination that is not allowed is reported. It reads no network.

What counts as a destination, since trooth 0.15.0:

1. The host of an `http`, `https`, `ws` or `wss` URL, anywhere in a code or config file, always, whatever its top-level domain. A URL built from a template (`${host}`, `{{ host }}`, `%s`) is skipped, because its host is not in the text.
2. A bare host name only when all of these hold:
   - it is the whole value of a host-like key or argument: one whose name, or the last word of whose name, is `host`, `hostname`, `domain`, `endpoint`, `url`, `base_url` (or `baseURL`), `origin`, `webhook`, `to`, `from`, `redirect`, `server` or `api` (so `API_HOST`, `webhook_host`, `baseURL` and `apiServer` count), written as `key: value` in YAML, `"key": "value"` in JSON, `key = "value"` in TOML, `KEY=value` in a .env file, `key: "value"` in a JavaScript object literal or `--key value` on a command line;
   - in source code (JavaScript, TypeScript, Python and the other languages listed in bin/lib/guard-ci.mjs), the value is quoted, since an unquoted value there is an expression such as `to: msg.to`;
   - it is written in lowercase letters, digits, dots and hyphens only, with at least two labels: a value with an uppercase letter (camelCase) or an underscore is an identifier, not a host;
   - its last label is in the curated list of public suffixes kept in bin/lib/guard-ci.mjs (`PUBLIC_SUFFIXES`: the generic and country-code top-level domains most used by services, such as com, net, org, io, co, ai, dev, app, cloud, us, uk, de and jp). The list leaves out real top-level domains that are also common words at the end of keys and property paths, such as name, link, open, next, email and host.

A quoted dotted string on its own is not a destination. Before 0.15.0 any quoted dotted string whose last label looked like a top-level domain counted, and on the trooth.co repository that reported 323 i18n keys and dotted identifiers (`"page.docs.cli.guardTitle"`, `"lib.changelog.e2026.name"`, `"x.open"`) as hosts.

Never reported: anything in a prose file (Markdown, reStructuredText, AsciiDoc, text, SVG, lock files, licenses, changelogs), where a link is documentation, not a destination; IP literals; `localhost`; and the reserved names `example.com`, `example.net`, `example.org`, `.test`, `.example`, `.invalid`, `.localhost`, `.local`, `.internal` and `home.arpa`.

What it misses: a host assembled at run time, a host under a key with another name (`const VENDOR = "api.vendor.io"`), and a bare host whose top-level domain is not in the list. A URL is always found, so writing destinations as URLs keeps them in view.

## 8. The Claude Code hook

`trooth guard hook --policy <file> [--cache <dir>] [--offline]` is a Claude Code PreToolUse hook. It reads the hook's JSON on stdin (`tool_name`, `tool_input`):

- a tool the policy does not cover: exit 0, no output;
- allow: exit 0, no output, so Claude Code's normal permission flow still applies (the guard never grants a permission);
- hold: prints `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"…"}}` and exits 0, so a person confirms;
- deny: the reason codes on stderr, exit 2, which blocks the call.

Claude Code treats exit codes other than 0 and 2 as non-blocking errors and lets the tool run, so every failure of the hook itself (no policy, a policy that does not parse, input that is not JSON) exits 2. Claude Code also lets a tool run when a hook times out: set the hook's `timeout` above the guard's own deadline for a decision (`deadlineMs`, 30 seconds). An answer the hook cannot write (an ask on stdout, a deny reason on stderr) also exits 2. This follows the hooks reference at https://code.claude.com/docs/en/hooks as read on 2026-10-07.

```json
{ "hooks": { "PreToolUse": [ { "matcher": "mcp__.*", "hooks": [ { "type": "command", "command": "npx trooth guard hook --policy .trooth/policy.yaml --cache .trooth-cache", "timeout": 60 } ] } ] } }
```

## 9. Adversarial suite and model check

tests/guard-adversarial.test.mjs runs attacks on the guard in the style of AgentDojo's injection tasks, with real Ed25519 signatures, a real Merkle log and real witness cosignatures made with keys generated for the run: injection text in profile and vendor fields, spoofed context (a record for another domain served for this host), a malicious tool description, a replayed or expired statement, a revoked key, a compromised key, a confused-deputy call (a host only in prose, or a URL inside vendor content), policy-bypass attempts (tool name case and look-alikes, wildcard abuse, `failMode: allow`), a forged log proof, a correction superseding the statement, and unreachable sources.

tests/guard-model.test.mjs enumerates every combination of the abstract decision inputs and checks the decision against an independent statement of the table and the invariants. spec/GuardDecision.tla states the same table and invariants for TLC, with spec/GuardDecision.cfg.

tests/guard-fuzz.test.mjs (since 0.15.0) is property-based testing with a seeded generator and no dependency: mutated and truncated policies, random bytes, deep nesting, huge strings and numbers, Unicode look-alikes and prototype keys through parsePolicy (each must give a policy inside schemas/guard-policy.v1.schema.json or a PolicyError, within a per-case time bound); random facts through decideFrom and random cached bundles through factsFromBundle (allow never occurs unless every required check held, the invariants of the model check); an offline guard with no cache (never allow); and the hook (exit 0 or 2 only). It runs about 80,000 cases in under 20 seconds with a fixed seed; `TROOTH_FUZZ_SEED=<n>` runs another sequence. It found four defects, fixed in 0.15.0.

docs/GUARD-RESULTS.md holds the counts from an actual run, written by `node scripts/guard-results.mjs --tlc <tla2tools.jar>`. All of these run in `npm test` except TLC. docs/GUARD-THREAT-MODEL.md maps each threat to the code that answers it and the tests that cover it. GitHub CodeQL scans this repository through GitHub's default code scanning setup (the languages GitHub detects in it), turned on in the repository's Advanced Security settings; GitHub runs it on every push to main and every pull request, and on a weekly schedule, and its results are under Security, Code scanning. .github/workflows/guard-pilots.yml runs the pilots in pilots/ every night against the latest releases of the agent frameworks.

## 10. Adapters

Duck-typed adapters that import no framework package (documented with their code):

- `trooth/guard/openai-agents`
- `trooth/guard/langchain`
- `trooth/guard/langgraph`
- `trooth/guard/http`
- Python (CrewAI, LangGraph, LangChain, OpenAI Agents): sdk/python/trooth_guard, which calls `trooth guard decide --json`
- Claude Code: `trooth guard hook` (section 8)

## 11. What it does not do

- It does not label a company safe or unsafe, and it does not rate, score, rank or certify anyone. An allow says only that the evidence your policy requires was signed, logged, fresh and checked on your machine.
- It does not grant permission. An allow in the hook leaves Claude Code's own permission flow in place; in a framework, your own controls still apply.
- It does not read prose, and no model takes part in the decision.
- `domain_control_confirmed` shows control of the domain, not the legal entity and not a person's authority to act for it; a rule requiring it holds when the signed public record carries no confirmed proof by a qualifying method.
- A sanctions or SAM.gov name match is not an identification, and no match does not show that a company is not sanctioned or excluded under another name.
- It does not check what Trooth did not read, and it does not establish anything a claim's evidence class says it does not establish.

## 12. Exit codes

| Command | Code | Meaning |
|---|---|---|
| guard decide | 0 | allow, or the policy does not cover the tool (the JSON says `covered: false` and carries no decision: a `GuardNotCovered`, `$defs/notCovered` in schemas/guard-decision.v1.schema.json) |
| guard decide | 20 | hold |
| guard decide | 21 | deny |
| guard ci | 0 | no added destination outside `destinations.allowed` |
| guard ci | 22 | the change adds a destination host the policy does not list |
| guard cache | 0, 1, 3 | all saved; a domain has no record; a source could not be reached |
| guard hook | 0, 2 | Claude Code's codes: 0 allow or ask (the JSON on stdout says which), 2 deny or any failure |
| all | 2 | usage error (a missing flag, a policy that does not parse) |
| all | 7 | output not delivered |

20, 21 and 22 are outside the range the other commands use (0 to 11); the README's exit code table lists them with the rest, and `trooth guard <subcommand> --help` lists each subcommand's codes.

With `--json`, `guard decide` prints exactly one document on stdout: a `GuardDecision` when the policy covers the tool, a `GuardNotCovered` (`{"covered": false, "tool", "policy", "note"}`) when it does not. schemas/guard-decide-output.v1.schema.json accepts exactly those two, and tests/guard-cli.test.mjs validates every output against it. A usage error prints the CLI's error document (`{"ok": false, "error", "exit": 2}`) instead, as every command does.

## 13. Phase 4 exit, as amended on 2026-10-07

The brief set three exit conditions for Phase 4: open source under a permissive license, an outside security review, and use in production by at least three teams outside Trooth. On 2026-10-07 the founder decided to keep the guard confidential to Trooth until launch, and so amended the two conditions that need people outside Trooth. The amended conditions, and where they stand:

| Condition | Status |
|---|---|
| Open source under a permissive license | Done: this repository is under the Apache License, Version 2.0. |
| In place of an outside security review before launch: an internal review gate | In place: separate internal review passes, property-based fuzzing (tests/guard-fuzz.test.mjs, in `npm test`), GitHub CodeQL on every push and pull request and weekly (GitHub's default code scanning setup), and a threat model with its residual risks (docs/GUARD-THREAT-MODEL.md). |
| In place of three outside teams in production before launch: Trooth as the first production user | In place: the code-change check (`trooth guard ci`) on every trooth.co change, the Claude Code hook (`trooth guard hook`) in Trooth's own development (.claude/settings.json and .trooth/guard-policy.yaml in this repository), and the pilots run every night against the latest framework releases (.github/workflows/guard-pilots.yml, pilots/). |
| An outside security review | Moved to the launch phase. No outside party has reviewed the guard. |
| Use in production by teams outside Trooth | Moved to the launch phase. No team outside Trooth uses the guard in production. |

The internal gate and Trooth's own use are not an outside review and not outside adoption, and nothing here says they are. They are what stands before launch, by the founder's decision for confidentiality; the outside review and outside production use are launch-phase work.
