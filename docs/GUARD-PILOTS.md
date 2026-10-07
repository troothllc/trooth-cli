# Trooth guard pilot integrations: results

Date: October 7, 2026 (runs between 19:42 and 20:00 UTC; the final full pass is the one recorded in `logs/*.json`, 19:59 UTC).

## What these are, and what they are not

These are pilots that Trooth ran itself, in a test harness on one machine, to see whether the guard adapters in trooth-cli 0.14.0 work against the real framework packages. Trooth engineering wrote the agents, the policies and the scripted models. They are not production use, no team outside Trooth took part, and they are not an outside review. The two Phase 4 exit conditions that need people outside Trooth (an outside security review, and use in production by at least three teams outside Trooth) remain OPEN.

No LLM API key was used. Each agent was driven by its framework's own model interface with a scripted model, so the framework's runner, guardrails, middleware, interrupts and checkpointer ran unchanged; only the model's choice of tool call was scripted.

## Setup

- Guard: trooth-cli (trooth 0.14.0), not modified. JavaScript imports it as `file:trooth-cli`; Python imports `trooth_guard` with `PYTHONPATH=trooth-cli/sdk/python`, which runs `node trooth-cli/bin/trooth.mjs guard decide --json` in a subprocess.
- Node v22.22.0, Python 3.13.16 (virtual environment in `py/.venv`).
- Live Trooth API (https://trooth.co, https://api.trooth.co), with the guard's pinned log key and witnesses. Live policies (`policies/*-live.yaml`) require `trooth_reading`, with `log.min_witnesses: 0`.
- Local fixture server (`fixture-server.mjs`): serves worlds built by `trooth-cli/tests/lib/guard-fixtures.mjs` `makeWorld` (keys, signed statements, Merkle log and witness cosignatures generated for the run; none is a Trooth key or record) under `http://127.0.0.1:<port>/<world>/{web,api}`. The CLI reaches it through `bin-trooth-fixture.sh` (`TROOTH_WEB`, `TROOTH_API`, `--log-vkey`, `--witness`). Fixture policies (`policies/*-fixture.yaml`) are the trooth-cli test policy: legal entity and sanctions rules (hold) and an absolute key rule (deny), `min_witnesses: 1`.
- `./run-all.sh` runs every pilot (needs the fixture server running).

| Package | Version |
|---|---|
| @openai/agents (and @openai/agents-core) | 0.19.0 |
| openai-agents (Python) | 0.20.0 (openai 2.54.0) |
| @langchain/langgraph | 1.4.21 (@langchain/langgraph-checkpoint 1.1.6) |
| langchain (JS) | 1.5.15 |
| @langchain/core | 1.2.17 |
| zod | 4.6.5 |
| crewai (Python) | 1.15.24 |
| langgraph (Python), used for one check | 1.2.14 (langchain-core 1.6.7) |
| Claude Code (installed, not run; no model key) | 2.1.293 |

## Counterparties and the decisions observed

| Host | Source | Decision | Reason code |
|---|---|---|---|
| trooth.co | live | allow | RULE_PASSED |
| pilot-unknown-7f3a9c2e.com | live | hold | NO_RECORD |
| www.trooth.co (the API serves the trooth.co record for it) | live | deny | SUBJECT_MISMATCH |
| acme-payments.com, export-partner.com | fixture | allow | RULE_PASSED |
| name-match-vendor.com (sanctions name match) | fixture | hold | EVIDENCE_MISSING |
| spoofed-vendor.com (record for other-vendor.com served) | fixture | deny | SUBJECT_MISMATCH |
| revoked-key-vendor.com (signed by a revoked key) | fixture | deny | KEY_NOT_TRUSTED |
| forged-log-vendor.com (forged inclusion proof) | fixture | deny | NOT_IN_LOG |
| any host, Trooth API unreachable (closed local port) | none | hold | SOURCE_UNREACHABLE |

Every one of these came out the same through every adapter that saw it. In the final pass the guard made 94 timed decisions: live 14 allow, 30 hold, 8 deny; fixture 6 allow, 7 hold, 29 deny. No failure produced an allow.

## The three open questions

1. Does LangChain JS accept the plain options object from `troothMiddleware`? Yes. `createAgent({ middleware: [createMiddleware(troothMiddleware(guard, { interrupt, ToolMessage }))] })` builds and runs in langchain 1.5.15. Passing the object without `createMiddleware` also ran in this version (recorded as information, not as a supported form).
2. Is `isToolApproved` reachable from an OpenAI Agents tool guardrail's context? Yes, in both SDKs. After `state.approve(interruption)` and a second run, the guardrail read `context.isToolApproved({ toolName, callId })` (JS) and `ctx.is_tool_approved(name, call_id)` (Python) as true and allowed the held call with `approved_by_person: true`; after `state.reject` the payout did not run.
3. Does `interrupt` inside `wrapToolCall` work in practice? Yes. With `MemorySaver`, a hold paused `createAgent` with a `trooth_guard_hold` interrupt carrying the Decision; `new Command({ resume: { type: 'approve' } })` on the same thread ran the tool once; a reject answered the model with an error `ToolMessage` and the run went on. The same held for the LangGraph guard node.

## What ran, by pilot

Full step lists, with expected and observed values, are in `logs/<name>.json` and `logs/<name>.out`.

Pilot 1, payments agent. `js/pilot1-payments-openai-agents.mjs` (15 steps, 14 pass) and `py/pilot1_payments_openai_agents.py` (12 steps, 11 pass). A `create_payout` tool built with `guardTool` (JS) or `needs_approval` plus `tool_input_guardrail` (Python), driven by a scripted `Model`. Observed: allow runs the payout; hold pauses with one interruption and runs only after approval; deny stops the run with the tool input tripwire for all four deny cases; the agent input guardrail (`troothAgentInputGuardrail`) passed trooth.co and tripped on the unknown domain.

Pilot 2, procurement agent. `js/pilot2-procurement-langgraph-langchain.mjs` (28 steps, 23 pass). LangGraph `StateGraph` with `createGuardNode`, `ToolNode` and `MemorySaver`; LangChain `createAgent` with the middleware; both driven by LangChain's own `FakeToolCallingModel`. Hold, interrupt and resume worked end to end in both; the guard decided again on resume, as documented. Throwing on deny worked. Routing on deny did not (failure B).

Pilot 3, data-export agent. `py/pilot3_export_crewai.py` (12 steps, 11 pass): CrewAI `Crew.kickoff()` with a scripted `BaseLLM` in CrewAI's ReAct format. The `before_tool_call` hook ran the export on allow, blocked it on hold (and ran it when `ask` approved), and blocked it on every deny even when `ask` would approve. The task guardrail could not be attached as shipped (failure D); with the fix it passed allow, failed hold on each retry, and failed deny. `hook/pilot3-claude-code-hook.mjs` (13 steps, 13 pass): `trooth guard hook` run as the settings.json command with PreToolUse input in the shape Claude Code documents (`session_id`, `transcript_path`, `cwd`, `permission_mode`, `hook_event_name`, `tool_name`, `tool_input`, `tool_use_id`). Allow exited 0 with no output; hold printed only `hookSpecificOutput` with `permissionDecision: "ask"`; deny exited 2 with the reason codes on stderr; an uncovered tool, malformed input, a missing policy and an unreachable API behaved as GUARD.md section 8 says. Claude Code itself was not run, because it needs a model.

## Failures, exactly

A. @openai/agents 0.19.0 does not surface the deny tripwire at the top level. `runner.run` rejects with `ToolCallError`; the `ToolInputGuardrailTripwireTriggered` is its `.error`, and the Decision is at `.error.result.output.outputInfo.decision`. The run stops and the payout does not run, so the guard holds; but GUARD-ADAPTERS.md says the SDK "raises ToolInputGuardrailTripwireTriggered", and a caller that tests `instanceof` misses it. The Python SDK raises the tripwire directly, as documented.

B. LangGraph routing on deny or hold runs the tools anyway. With the graph GUARD-ADAPTERS.md shows (`.addEdge('trooth_guard', 'tools')`) plus `Command` and `denyGoto` (destinations declared in `ends`), all three fixture denies routed to the deny node and the purchase order tool also ran (executed 1). A reject with `holdGoto` did the same. LangGraph runs a node's static edges in addition to a returned `Command`'s `goto`. The same happened with the Python `guard_node` and `deny_goto` on Python langgraph 1.2.14 (`py/check_langgraph_py_deny_goto.py`). Throwing on deny (the default) is not affected. This is the one failure where a denied action ran.

C. LangChain JS `createAgent` wraps `GuardDeny` in `MiddlewareError` (same `name` and message, the original in `.cause`), so `err instanceof GuardDeny` is false and `err.reasons` is undefined. The tool did not run.

D. CrewAI 1.15.24 refuses `Task(guardrail=task_guardrail(...))` with "If return type is annotated, it must be Tuple[bool, Any]". The adapter module uses `from __future__ import annotations`, so the return annotation is the string "Tuple[bool, Any]", and CrewAI checks it with `typing.get_origin`. The task guardrail cannot be used at all as shipped.

E. Python `needs_approval` crashes for a tool the policy does not cover: `decide()` returns None and the function reads `d["decision"]`. The SDK reports `UserError: ... 'NoneType' object is not subscriptable` and the tool does not run, where GUARD-ADAPTERS.md says such a tool runs without a decision.

F. Not a failure of the adapter, but a configuration to document: with the @openai/agents run option `toolExecution.preApprovalInputGuardrails: true`, the guardrail runs before approval and rejects a held call with a message to the model, so no person is asked. It fails closed.

## Proposed fixes (not applied to trooth-cli)

Patch files in `fixes/`, against trooth-cli 0.14.0, applied in order with `patch -p1` (0002 adds a test next to the one 0001 adds). Applied together to a copy of trooth-cli, `npm test` passed (guard-adapters: 26 tests) and the Python suite passed (27 tests); the new tests fail on the current code. `fixes/patched/` holds the patched modules the pilots import for the steps marked PATCHED, all of which passed against the real packages.

- `0001-guard-decision-of-wrapped-errors.patch` (A, C, F): `guardDecisionOf(err)` in `trooth/guard/errors`, which walks `.cause` and `.error` and matches by error code as well as class; types, tests, and doc text for the wrappers and for `preApprovalInputGuardrails`.
- `0002-langgraph-routing-needs-tools-goto.patch` (B): routing needs `toolsGoto` (`tools_goto` in Python) and no static edge from the guard node; the node then returns `Command({ goto: toolsGoto })` when the calls may run. Routing without it is refused with a TypeError. JS and Python, types, tests, docs.
- `0003-python-needs-approval-uncovered-tool.patch` (E): return False when `decide()` returns None.
- `0004-python-crewai-task-guardrail-annotation.patch` (D): give the guardrail function the real `Tuple[bool, Any]` return annotation.

## Decision latency

Measured around each decision call in the final pass. JS in-process times the guard's `decide`/`decideToolCall`; Python times `trooth_guard.decide`, which includes starting the CLI process; the hook times the whole hook process. No bundle cache was configured, so every live decision read the network.

| Source and path | Decisions | Median (ms) | Max (ms) |
|---|---|---|---|
| live, JS in-process | 34 | 141.7 | 1890.6 |
| live, Python to CLI subprocess | 15 | 575.2 | 1577.6 |
| live, Claude Code hook process | 3 | 919.5 | 1123.0 |
| fixture, JS in-process | 21 | 15.4 | 23.4 |
| fixture, Python to CLI subprocess | 16 | 277.2 | 335.8 |
| fixture, Claude Code hook process | 5 | 268.9 | 289.0 |
| all live | 52 | 442.8 | 1890.6 |
| all fixture | 42 | 144.2 | 335.8 |

A held call in the OpenAI Agents SDK is decided two or three times (needsApproval, then the guardrail after approval), and a resumed LangGraph node or LangChain middleware decides again, so a held action costs more than one decision.

## Other observations

- During an exploratory probe before the pilots, one live decision for api.trooth.co ended in hold with SOURCE_UNREACHABLE when the sandbox's outbound proxy reset a connection to trooth.co. That is the documented fail-closed behavior; it did not recur in the pilot runs.
- A resumed Python `RunResult` does not list `tool_input_guardrail_results`, so the pilot read the guardrail's outputs by wrapping the adapter's guardrail function.
- GUARD-ADAPTERS.md "What is open" still says the adapters were tested only against fakes. These pilots ran them against the real packages, in Trooth's own harness; use in production by teams outside Trooth and an outside review remain OPEN.

## After the pilots

The four proposed fixes (`0001` to `0004` above) were applied to trooth 0.14.0 before its release, each with the regression tests named in its patch: the Decision is found inside framework error wrappers (`guardDecisionOf`), LangGraph routing requires `toolsGoto` / `tools_goto` and no static edge from the guard node, the Python `needs_approval` lets a tool the policy does not cover run, and the CrewAI task guardrail carries a real return annotation. The harness itself (agents, policies, logs) is kept by Trooth and is not part of this repository; the paths above are relative to it.
