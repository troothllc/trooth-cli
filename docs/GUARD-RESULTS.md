# Guard results

Written by `node scripts/guard-results.mjs --tlc <tla2tools.jar>` on 2026-10-07T23:31:44.767Z (Node v22.22.0), from an actual run of the files below. Do not edit by hand; run the script again.

## Test files

| File | Tests | Pass | Fail | Skipped | Seconds |
|---|---|---|---|---|---|
| tests/guard-policy.test.mjs | 15 | 15 | 0 | 0 | 0.2 |
| tests/guard.test.mjs | 25 | 25 | 0 | 0 | 1.2 |
| tests/guard-cli.test.mjs | 10 | 10 | 0 | 0 | 6.1 |
| tests/guard-adapters.test.mjs | 26 | 26 | 0 | 0 | 0.2 |
| tests/guard-adversarial.test.mjs | 11 | 11 | 0 | 0 | 0.5 |
| tests/guard-model.test.mjs | 5 | 5 | 0 | 0 | 7.7 |
| tests/guard-fuzz.test.mjs | 10 | 10 | 0 | 0 | 10.9 |
| all | 102 | 102 | 0 | 0 | |

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
Finished computing initial states: 26873856 distinct states generated at 2026-10-07 23:30:58.
Model checking completed. No error has been found.
53747712 states generated, 26873856 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 1.
Finished in 02min 07s at (2026-10-07 23:31:42)
```

As a check that the invariants can fail, the same run model-checked a mutant of the spec with the absolute-rule branch removed (MaxRules = 1). TLC exit status 12:

```
Error: Invariant AllowOnlyWithEvidence is violated by the initial state:
```

The invariants, in both: allow implies every required check held; source unreachable never yields allow; deny happens only for a failed proof or an absolute rule (or where the customer's policy itself chose deny for no record or no source); missing, stale or disputed evidence alone never denies (TLA+); the same inputs always give the same decision.

## Malformed-input testing (tests/guard-fuzz.test.mjs)

A seeded, deterministic generator (seed 20261007) makes malformed and mutated policies, facts, tool calls, cached bundles and hook input, and checks that parsePolicy returns a policy inside its schema or throws PolicyError within a per-case time bound, that decideFrom never allows facts lacking required evidence, that an offline guard with no cached bundle never allows, that a bundle with its signed bytes changed never allows, and that the hook exits only 0 or 2. Result: all 10 tests passed. The lines the run printed:

```
policies 41849 cases (seed 20261007): 3802 accepted and inside the schema, 38040 refused with PolicyError; by kind seed 20, byte-flip 13527, truncation 13527, random-bytes 2500, structural 8000, duplicate-key 1000, prototype-key 150, lookalike 2500, deep-nesting 606, huge-string 12, not-text 7
facts 30000 cases: 2437 allow (each with every required piece of evidence), 20798 hold, 6063 deny, 702 refused with an error (malformed now); no allow without the evidence: true
offline guard, empty cache: 9748 tool calls and hosts: 2252 not covered (null), 3476 hold, 272 deny, 0 allow expected; failures 0
cached bundles 800 cases: 759 with signed bytes changed (none allowed), 19 allowed with only unsigned fields changed; failures 0
hook 64 runs: exit 0 20 (8 silent, each for a tool the policy does not cover; the rest ask), exit 2 44, any other exit 0
total 82461 cases in 10.7 s
```

## What these results do not show

They show that the guard, as written, reaches the stated decisions on these inputs. They come from Trooth's internal review gate (docs/GUARD-THREAT-MODEL.md, "Review status"); they are not an outside security review and not evidence of use in production by teams outside Trooth. Both of those are launch-phase items.
