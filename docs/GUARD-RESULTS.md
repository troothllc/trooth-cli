# Guard results

Written by `node scripts/guard-results.mjs --tlc <tla2tools.jar>` on 2026-10-07T20:43:15.088Z (Node v22.22.0), from an actual run of the files below. Do not edit by hand; run the script again.

## Test files

| File | Tests | Pass | Fail | Skipped | Seconds |
|---|---|---|---|---|---|
| tests/guard-policy.test.mjs | 15 | 15 | 0 | 0 | 0.2 |
| tests/guard.test.mjs | 25 | 25 | 0 | 0 | 1.3 |
| tests/guard-cli.test.mjs | 9 | 9 | 0 | 0 | 6.4 |
| tests/guard-adapters.test.mjs | 26 | 26 | 0 | 0 | 0.2 |
| tests/guard-adversarial.test.mjs | 11 | 11 | 0 | 0 | 0.6 |
| tests/guard-model.test.mjs | 5 | 5 | 0 | 0 | 7.6 |
| all | 91 | 91 | 0 | 0 | |

## Adversarial suite (tests/guard-adversarial.test.mjs)

Each case is an attack on a pre-execution guardrail, in the style of AgentDojo's injection tasks: real Ed25519 signatures, a real RFC 9162 Merkle log with a signed checkpoint, and real witness cosignatures, made with keys generated for the run. A case passes only when the guard reaches the decision and reason code the case states.

| Result | Case |
|---|---|
| pass | ADV-01 injection text in profile and vendor fields does not change the decision or reach its reasons |
| pass | ADV-02 spoofed context: a record, statement or reading for another domain served for this host is denied SUBJECT_MISMATCH |
| pass | ADV-03 a malicious tool description neither skips nor triggers a check: only the tool name and typed arguments count |
| pass | ADV-04 a replayed or expired statement is stale; one dated in the future is not fresh either |
| pass | ADV-05 a revoked key is not trusted: deny KEY_NOT_TRUSTED |
| pass | ADV-06 a compromised key, a key not on the list, a forged signature and a tampered record are denied |
| pass | ADV-07 confused deputy: a host only in prose, or a URL inside vendor content, is never the target and never fetched |
| pass | ADV-08 policy bypass: case and look-alike tool names, wildcard abuse, failMode allow and source_unreachable allow |
| pass | ADV-09 a forged log proof is denied NOT_IN_LOG: wrong index, flipped proof hash, checkpoint by another key; unpinned cosigners do not count |
| pass | ADV-10 a correction Trooth signed and logged supersedes the statement: EVIDENCE_DISPUTED; a forged correction is ignored |
| pass | ADV-11 unreachable sources fail toward hold, never allow: down, 5xx, timeout, the log down |

11 of 11 cases passed. These are tasks written by Trooth against its own guard; they are not the AgentDojo benchmark itself, and no outside party has run them.

## Model check

JavaScript, exhaustive (tests/guard-model.test.mjs): 4534272 combinations checked (1008 allow, 2302800 hold, 2230464 deny); 164 rule multisets. Result: all 5 tests passed.

TLA+ (spec/GuardDecision.tla with spec/GuardDecision.cfg): TLC exit status 0. The lines TLC printed:

```
TLC2 Version 2026.10.06.014338 (rev: 94d0c50)
Finished computing initial states: 26873856 distinct states generated at 2026-10-07 20:42:28.
Model checking completed. No error has been found.
53747712 states generated, 26873856 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 1.
Finished in 02min 13s at (2026-10-07 20:43:13)
```

As a check that the invariants can fail, the same run model-checked a mutant of the spec with the absolute-rule branch removed (MaxRules = 1). TLC exit status 12:

```
Error: Invariant AllowOnlyWithEvidence is violated by the initial state:
```

The invariants, in both: allow implies every required check held; source unreachable never yields allow; deny happens only for a failed proof or an absolute rule (or where the customer's policy itself chose deny for no record or no source); missing, stale or disputed evidence alone never denies (TLA+); the same inputs always give the same decision.

## What these results do not show

They show that the guard, as written, reaches the stated decisions on these inputs. They are not an outside security review (OPEN) and not evidence of use in production by teams outside Trooth (OPEN).
