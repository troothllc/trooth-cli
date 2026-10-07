# Trooth guard: threat model

Version 1.0, October 7, 2026, for trooth 0.15.0. It covers the guard (`trooth/guard`, bin/lib/guard*.mjs, bin/lib/guard/, the `trooth guard` commands and sdk/python/trooth_guard) and names, for each threat, the code that answers it and the tests that cover it. Section numbers refer to [GUARD.md](GUARD.md) unless another file is named.

## 1. What the guard does, in one paragraph

Before a customer's agent takes a consequential action (a payout, a purchase order, a data export, a message), the guard reads the host the action is about from the tool call's typed arguments, reads Trooth's signed and logged statements about that host, checks them locally against keys pinned in the guard, and answers allow, hold or deny under the customer's own policy. It never labels a company, no model reads prose in the decision, and the action itself is never sent anywhere.

## 2. Assets

| Asset | Why it matters |
|---|---|
| The decision | An allow lets money, data or a message leave. A wrong allow is the main harm; a wrong hold costs a person's time; a wrong deny blocks work. |
| The customer's policy | It says which tools are covered and what evidence an allow needs. Its SHA-256 is in every decision, so a changed policy is visible. |
| The pinned trust anchors | The log verifier keys (`PINNED_LOG_VKEYS`) and witness keys (`PINNED_WITNESSES`) in bin/lib/log-trust.mjs. Whoever can change them can make forged evidence check. |
| The action's content | Tool arguments can hold amounts, account numbers and personal data. The guard keeps them local (`action` in a decision is "local only; never sent to Trooth"). |
| The cache | Saved bundles let the guard decide offline. A planted bundle must not lead to an allow. |
| The customer's agent run | The guard sits in the call path; a crash or a hang in it must not turn into an allow. |

## 3. Trust boundaries

| Party | Trusted for | Not trusted for |
|---|---|---|
| Customer agent (the model and its framework) | Nothing in the decision. It supplies the tool name and arguments. | Choosing the host by prose, describing its own tools, skipping the check. The model may be steered by injected text. |
| The guard (this code, on the customer's machine) | Running the decision table as written, with the pinned keys. | It holds no secret; a compromised host machine is out of scope (section 8). |
| Trooth API (`api.trooth.co`, `trooth.co`) | Serving bytes. | Their meaning: every statement is checked against a pinned key and a log proof before it counts. A served key list is read, but trust in a key comes only from the pinned keys and the signed key history. |
| The transparency log | Append-only history of Trooth's statements, as far as its checkpoints are signed by the pinned log key and cosigned by pinned witnesses. | A checkpoint by any other key, an inclusion proof that does not check. |
| Witnesses | Cosigning checkpoints they have seen. | Today no pinned witness cosigns Trooth's log (section 7, residual risks). |
| Vendor content (profile text, names, descriptions, documents a company wrote) | Nothing. | Any instruction in it. The decision never reads it, and reason details never copy it. |

## 4. Attacker capabilities considered

1. Writes text the agent or the guard will see: a company profile, a vendor field, a web page, a tool description, an email the agent reads (prompt injection).
2. Controls a domain, or registers one that looks like a customer's vendor.
3. Sits on the network path: can delay, drop, reset, replay or alter responses from Trooth's servers.
4. Has obtained an old or revoked Trooth signing key, or tries to forge signatures and log proofs.
5. Can write files the guard reads: a policy in a pull request, a cached bundle, hook input.
6. Sends malformed or adversarial input to every parser (policy text, JSON, hook stdin, tool arguments).
7. Changes a repository to add a new place data or money goes (`trooth guard ci`).

Not considered: an attacker with code execution on the machine running the guard, or with write access to the installed package; an attacker who controls Trooth's signing keys and its log key and every pinned witness at once.

## 5. Threats, mitigations and coverage (STRIDE)

| # | Threat (STRIDE) | Mitigation in code | Covered by |
|---|---|---|---|
| T1 | Spoofing: a record, statement or reading for another domain is served for the host | The signed subject must be the host or a parent of it, else deny `SUBJECT_MISMATCH` (guard-decide.mjs step 4; `isHostOrParent`, guard-policy.mjs) | ADV-02; pilots (spoofed-vendor.com, www.trooth.co live) |
| T2 | Spoofing: a look-alike domain or a platform subdomain inherits a parent's record | The parent walk stops at two labels and before shared suffixes (`hostCandidates`, `SHARED_SUFFIXES`) | "the walk does not reach a platform owner..." (tests/guard.test.mjs); "host candidates walk to two labels..." (tests/guard-policy.test.mjs) |
| T3 | Spoofing: the model names the host in prose, or a URL in vendor content becomes the target | Only typed argument fields (`host_from`) name the target; several hosts or an unreadable host field make the call ambiguous, so hold (`targetHosts`) | ADV-07; "targetHosts: typed fields only..."; "a host field the guard cannot read..." |
| T4 | Spoofing: a tool named to look like an uncovered one (case, Unicode look-alikes, invisible characters) | Coverage is decided on NFKC case-folded names and fails toward checking (`toolCovered`); Python mirrors it | ADV-08; "applies(): case and Unicode look-alikes..."; python covered() parity test; fuzz invariant 3a |
| T5 | Tampering: a forged signature or a changed record | Ed25519 signature checked against keys whose trust comes from the pinned keys; deny `SIGNATURE_INVALID` / `KEY_NOT_TRUSTED` (guard-evidence.mjs `factsFromBundle`) | ADV-06; fuzz invariant 3b (signed bytes changed: never allow) |
| T6 | Tampering: a forged log proof, a checkpoint by another key, unpinned cosigners | Inclusion proof checked against a checkpoint signed by a pinned log key; only pinned witnesses count (`cosignersFor`); deny `NOT_IN_LOG` on a failed proof, hold when not logged or too few witnesses | ADV-09; "witnesses: fewer cosigners than min_witnesses holds..." |
| T7 | Tampering: a planted or altered cached bundle | Every cached bundle is checked again on every read against the pinned keys, never against a key it carries (section 6) | "cache: ..." (tests/guard.test.mjs); fuzz invariant 3b |
| T8 | Tampering: a policy that changes meaning without changing its text visibly (duplicate keys, `__proto__`, fractions, look-alikes) | Strict parser: unknown keys, wrong types, duplicate keys and prototype keys refused; `failMode` and `source_unreachable` allow refused; the decision carries the policy's RFC 8785 SHA-256 | tests/guard-policy.test.mjs refusals; fuzz invariant 1 (about 42,000 policy cases); FUZZ-REG-3 |
| T9 | Tampering: a replayed or expired statement | Each claim has `observed_at` and a stale-after limit (rule `max_age_days` or the evidence class default); a date in the future beyond `FUTURE_SKEW_MS` is not fresh | ADV-04; "claims: missing, stale..." |
| T10 | Tampering: a statement Trooth later corrected | A correction Trooth signed and logged makes the claim `EVIDENCE_DISPUTED`; a forged correction is ignored; with `log.required: false` unreadable corrections leave no claim | ADV-10; "log.required false: corrections that cannot be read..." |
| T11 | Repudiation: no record of why an action was allowed | Every decision names its reasons, the policy id, version and hash, and each piece of evidence (fact id, statement hash, log index); it validates against schemas/guard-decision.v1.schema.json before it is returned (`validateDecision`) | "the schema is the published contract..."; fuzz invariant 2 (every decision inside the schema) |
| T12 | Information disclosure: the action or its arguments reach Trooth | Only the domain (or a statement id) is sent, only to Trooth, the public record with `cached=only`; the action stays local | "what is sent: only the domain or a statement id..." |
| T13 | Information disclosure: vendor text placed in a decision is later read by a model | Reason details are written by the guard; served values are reduced to characters that cannot carry an instruction (section 5) | ADV-01 |
| T14 | Denial of service turned into an allow: Trooth unreachable, slow, 5xx, oversized | Any failure to read is `SOURCE_UNREACHABLE`, hold by default and deny if the policy says so, never allow; size limits (`LIMITS`) and one deadline for the whole decision | ADV-11; "bounded: a body over the size limit..."; "one deadline for the whole decision..."; pilots (closed local port) |
| T15 | Denial of service: a policy or input that exhausts the stack or hangs a parser | Nesting limited to `MAX_DEPTH` (64) in YAML and JSON; `parsePolicy` throws only `PolicyError`; a per-case time bound in the fuzzer | FUZZ-REG-1; fuzz invariant 1 (deep nesting to 100,000 levels, 4 MB strings) |
| T16 | Elevation: a malformed facts object or a caller value passes as complete evidence | `decideFrom` reads facts strictly (exactly `true`, a number of witnesses, an own well-formed claim); a value with no String form is decided, not thrown | FUZZ-REG-2, FUZZ-REG-4; fuzz invariant 2; tests/guard-model.test.mjs (exhaustive) and spec/GuardDecision.tla |
| T17 | Elevation: an adapter lets a held or denied call run (framework wrappers, static graph edges, approval paths) | Adapters fail closed: a deny is never approvable; LangGraph routing needs `toolsGoto` and no static edge; `guardDecisionOf` finds the Decision inside wrapped errors; the hook exits 2 on any failure | tests/guard-adapters.test.mjs; sdk/python/tests; pilots against the real frameworks, nightly |
| T18 | Elevation: a change adds a new destination for money or data without review | `trooth guard ci` lists every added URL host and every bare host under a host-like key that the policy does not allow, and fails the build (section 7) | tests/guard-cli.test.mjs "guard ci" tests |
| T19 | Supply chain: a dependency or a workflow action is swapped | The guard imports only `node:` built-ins (the CLI's one pinned dependency, yaml, is not used by the guard); workflow actions are pinned by full commit SHA; CodeQL runs on every push | .github/workflows/codeql.yml; ci.yml dependency check |

## 6. What the decision table guarantees

Checked exhaustively over every combination of abstract inputs by tests/guard-model.test.mjs, and by TLC on spec/GuardDecision.tla: an allow implies every required check held; an unreachable source never yields allow; a deny happens only for a failed proof or an absolute rule (or where the customer's policy chose deny for no record or no source); the same inputs always give the same decision. tests/guard-fuzz.test.mjs checks the first two on random, malformed facts and bundles, which the abstract model cannot express.

## 7. Residual risks

These are not mitigated today, or only in part. They are stated so a customer can weigh them.

- Trooth is a single operator. Trooth runs the readers, signs the statements, runs the log and decides what it corrects. The log makes Trooth's history visible and hard to rewrite quietly; it does not make Trooth's readings correct.
- Witnesses do not yet cosign. No pinned witness cosigns Trooth's log today, so a policy that asks for `min_witnesses: 1` (the default) holds, and the policies Trooth itself uses set `min_witnesses: 0`. With zero witnesses, the log key alone vouches for the log's consistency; a Trooth that showed different log views to different customers would not be caught by the guard.
- Offline bundles cannot learn of a later key compromise. A bundle checked offline is checked against the key status it carries and the pinned keys; a compromise announced after it was saved is not known until the cache is refreshed (section 6).
- The shared-suffix list is a subset. `SHARED_SUFFIXES` in guard-policy.mjs, which stops the parent walk at platforms where customers choose their own names, is a short list, not the public suffix list. A platform not on it could let a customer-chosen subdomain inherit the platform owner's record. The CI scanner's `PUBLIC_SUFFIXES` is also a subset: a bare host with a top-level domain not on it is missed (a URL is always found).
- The guard checks what Trooth read, not the world. A name match on a sanctions list is not an identification, and no match does not show a company is not sanctioned under another name (section 11). Freshness limits bound how old a reading may be, not what changed since.
- The host is only as good as the typed arguments. A tool whose arguments carry no host field, or carry the destination somewhere the policy's `host_from` does not name, is held with `EVIDENCE_MISSING` or decided on the field it does name.
- A person approves holds. A hold asks a person; a person who approves without reading defeats the hold.
- The machine running the guard is trusted. Anyone who can change the installed package, the pinned keys or the policy file on that machine can change decisions.
- The pilots and fuzzing are Trooth's own. They are as good as the cases Trooth thought to write.

## 8. Review status

Reviewed internally by separate review passes on 2026-10-07 (9 defects fixed); Trooth-run pilots against the real frameworks (4 defects fixed); fuzzing (tests/guard-fuzz.test.mjs, in `npm test`, which found 4 further defects, fixed in 0.15.0) and CodeQL (.github/workflows/codeql.yml) in CI. No outside party has reviewed it. Outside review is planned for the launch phase (GUARD.md section 13).
