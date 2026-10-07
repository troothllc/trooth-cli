# Trooth guard adapters

Version 1.0, October 7, 2026. How to put the Trooth guard ([GUARD.md](GUARD.md)) in front of an agent's tool calls in each framework. The guard answers allow, hold or deny about an action your agent is about to take, under your policy. It never labels a company.

Every adapter follows the same rules:

- **allow**: the call runs.
- **hold**: the call does not run until a person approves it, through the framework's own approval path where it has one.
- **deny**: the call does not run.
- **A failure to decide** (the guard throws, the CLI cannot run, the answer is not a Decision) is a hold with `SOURCE_UNREACHABLE`. No adapter turns a failure into allow.
- A tool the policy does not cover runs without a decision.
- No adapter imports a framework package. Framework helpers (`interrupt`, `ToolMessage`, `Command`) are passed in.
- `GuardHold` and `GuardDeny` errors carry the Decision in `.decision` and its reason codes in `.reasons`. A framework may wrap what an adapter throws (LangChain JS `createAgent` and the OpenAI Agents SDK for JavaScript do); `guardDecisionOf(err)` from `trooth/guard/errors` finds the Decision inside such a wrapper, through `.cause` and `.error`.

Each section names the framework documentation the adapter follows and the date it was read. Where an adapter returns a framework object by shape rather than by class, the section says so.

## OpenAI Agents SDK (JavaScript and TypeScript)

`trooth/guard/openai-agents`. Followed: https://openai.github.io/openai-agents-js/guides/guardrails/ and https://openai.github.io/openai-agents-js/guides/human-in-the-loop/, with the SDK source they build from (`toolGuardrail.ts`, `tool.ts`, `runContext.ts`), read October 7, 2026.

```js
import { Agent, run, tool } from '@openai/agents';
import { createGuard, loadPolicy } from 'trooth/guard';
import { guardTool } from 'trooth/guard/openai-agents';

const guard = createGuard({ policy: await loadPolicy('policy.yaml') });
const payout = tool(guardTool(guard, {
  name: 'stripe.create_payout',
  description: 'Pay a vendor',
  parameters: PayoutArgs,
  execute: createPayout,
}));
let result = await run(new Agent({ name: 'ap', tools: [payout] }), 'Pay the invoice');
for (const item of result.interruptions) result.state.approve(item); // after a person reviews item and item's Decision
result = await run(agent, result.state);
```

`guardTool` sets `needsApproval` (true for a hold, so the run pauses with an interruption) and puts a tool input guardrail first in `inputGuardrails`. The guardrail returns the objects `ToolGuardrailFunctionOutputFactory` returns: `allow`; `throwException` for a deny, which raises `ToolInputGuardrailTripwireTriggered` and stops the run; and for a hold, `allow` when `context.isToolApproved` says a person approved this call, otherwise `rejectContent` with a plain message to the model. In @openai/agents 0.19.0 the run rejects with `ToolCallError`, whose `.error` is the `ToolInputGuardrailTripwireTriggered`; `guardDecisionOf(err)` returns the Decision from it. Leave the run option `toolExecution.preApprovalInputGuardrails` off (the default): with it on, the SDK runs the input guardrail before asking for approval, so a held call is rejected with a message to the model and no person is asked. The parts are exported on their own: `troothToolInputGuardrail(guard)`, `troothNeedsApproval(guard, toolName)`, and `troothAgentInputGuardrail(guard, { extract })`, an agent input guardrail (`runInParallel: false`) whose tripwire fires on any hold or deny for actions named in the run's input. An input guardrail has no approval path, so there a hold stops the run.

## LangChain JS (createAgent middleware)

`trooth/guard/langchain`. Followed: https://docs.langchain.com/oss/javascript/langchain/middleware/custom and https://docs.langchain.com/oss/javascript/langgraph/interrupts, read October 7, 2026.

```js
import { createAgent, createMiddleware } from 'langchain';
import { ToolMessage } from '@langchain/core/messages';
import { interrupt, Command } from '@langchain/langgraph';
import { troothMiddleware } from 'trooth/guard/langchain';

const agent = createAgent({
  model, tools, checkpointer,
  middleware: [createMiddleware(troothMiddleware(guard, { interrupt, ToolMessage }))],
});
// A hold pauses the run with { type: 'trooth_guard_hold', tool_call, decision }.
await agent.invoke(new Command({ resume: { type: 'approve' } }), config);
```

`troothMiddleware` returns the options for `createMiddleware`: a name and `wrapToolCall(request, handler)`. A hold calls `interrupt` when it is given; a resume of `true`, `'approve'`, `{ type: 'approve' }` or `{ decisions: [{ type: 'approve' }] }` runs the tool, and anything else answers the model with an error `ToolMessage` (or throws `GuardHold` without one). Without `interrupt`, a hold answers with an error `ToolMessage`, or throws. A deny throws `GuardDeny`; with `onDeny: 'message'` it answers with an error `ToolMessage` and the run goes on. `createAgent` (langchain 1.5.15) wraps the `GuardDeny` in a `MiddlewareError` that keeps its `name` and holds it in `.cause`, so test with `guardDecisionOf(err)` rather than `instanceof GuardDeny`.

## LangGraph JS

`trooth/guard/langgraph`. Followed: https://docs.langchain.com/oss/javascript/langgraph/interrupts, read October 7, 2026.

```js
import { StateGraph, MessagesAnnotation, interrupt, Command } from '@langchain/langgraph';
import { ToolNode } from '@langchain/langgraph/prebuilt';
import { createGuardNode } from 'trooth/guard/langgraph';

const graph = new StateGraph(MessagesAnnotation)
  .addNode('model', callModel)
  .addNode('trooth_guard', createGuardNode(guard, { interrupt }))
  .addNode('tools', new ToolNode(tools))
  .addConditionalEdges('model', (s) => (s.messages.at(-1).tool_calls?.length ? 'trooth_guard' : '__end__'))
  .addEdge('trooth_guard', 'tools')
  .addEdge('tools', 'model')
  .compile({ checkpointer });
```

The node decides every covered tool call in the last message, in order. A deny throws `GuardDeny` before any interrupt. Any hold calls `interrupt` once, with every held call and its Decision; resume with `new Command({ resume: { type: 'approve' } })` on the same `thread_id`. Anything other than approval throws `GuardHold`.

To route instead of throwing, pass `Command`, `denyGoto`, `holdGoto` or both, and `toolsGoto` (the tool node), and do not add a static edge from the guard node. LangGraph runs a node's static edges in addition to the `goto` of a `Command` the node returns, so with `.addEdge('trooth_guard', 'tools')` in place the tools would run after a routed deny. With routing, the node returns `new Command({ goto: toolsGoto })` when the calls may run:

```js
graph.addNode('trooth_guard', createGuardNode(guard, { interrupt, Command, denyGoto: 'denied', toolsGoto: 'tools' }), { ends: ['tools', 'denied'] })
// no .addEdge('trooth_guard', 'tools')
```
 The node runs again from the top on resume, so the guard decides again: a call that has become a deny is still stopped. `decisionsKey` writes the Decisions to a state key.

## HTTP (fetch)

`trooth/guard/http`. Followed: the WHATWG Fetch standard, https://fetch.spec.whatwg.org/#fetch-method, read October 7, 2026.

```js
import { guardFetch } from 'trooth/guard/http';
import { GuardHold } from 'trooth/guard/errors';

const guardedFetch = guardFetch(fetch, guard);
try {
  await guardedFetch('https://api.example-bank.com/v1/payouts', { method: 'POST', body });
} catch (e) {
  if (e instanceof GuardHold) queueForReview(e.decision);
  else throw e;
}
```

A request whose method and host match the policy's `applies_to.http` is decided on its destination host before it is sent (tool name `http:<METHOD>`). `*.example-bank.com` covers every subdomain of example-bank.com and not example-bank.com itself. Allow sends the request unchanged; hold throws `GuardHold`, deny throws `GuardDeny`, and the request is not sent. The guard is given the method and host only: the body, headers, path and query are never passed to it.

## Python: trooth_guard

`sdk/python/trooth_guard` runs `trooth guard decide --json` in a subprocess, so Python and JavaScript share one decision implementation. Exit 0 is allow, 20 hold, 21 deny; any other exit or output that is not a Decision is a hold with `SOURCE_UNREACHABLE`. The command is `npx --yes trooth@<version>` unless `trooth_cmd=` or the `TROOTH_CMD` environment variable names another. The tool arguments are passed to that local process on its command line. Every adapter takes `tools=`, the policy's `applies_to.tools` globs, so a call to a tool the policy does not cover runs without a decision; without it, every call is decided.

```python
from trooth_guard import decide
d = decide("policy.yaml", "stripe.create_payout", host="api.example.com", cache=".trooth-cache")
```

### CrewAI

`trooth_guard.crewai`. Followed: https://docs.crewai.com/en/concepts/tasks (task guardrails) and https://docs.crewai.com/en/learn/tool-hooks (before tool call hooks), read October 7, 2026.

```python
from crewai.hooks import before_tool_call
from trooth_guard.crewai import before_tool_call_hook, task_guardrail

before_tool_call(before_tool_call_hook("policy.yaml", tools=["stripe.*"], ask=ask_a_person))
task = Task(..., guardrail=task_guardrail("policy.yaml", "stripe.create_payout"))
```

The hook returns `False` to block a held or denied call; `ask(decision)` returning True lets a held call run. The task guardrail returns `(True, output)` on allow and `(False, message)` otherwise; CrewAI sends the message back to the agent and retries up to `guardrail_max_retries`.

### LangGraph (Python)

`trooth_guard.langgraph`. Followed: https://docs.langchain.com/oss/python/langgraph/interrupts, read October 7, 2026.

```python
from langgraph.types import interrupt, Command
from trooth_guard.langgraph import guard_node

builder.add_node("trooth_guard", guard_node("policy.yaml", interrupt=interrupt, tools=["stripe.*"]))
builder.add_edge("trooth_guard", "tools")
graph.invoke(Command(resume={"type": "approve"}), config)
```

Same behavior as the JavaScript node: a deny raises `GuardDeny`, a hold calls `interrupt` once for all held calls. To route, pass `command=Command`, `deny_goto=`, `hold_goto=` or both, and `tools_goto=`, declare `destinations=` in `add_node`, and add no static edge from the guard node, for the reason given for the JavaScript node.

### LangChain (Python)

`trooth_guard.langchain`. Followed: https://docs.langchain.com/oss/python/langchain/middleware/custom, read October 7, 2026.

```python
from langchain.agents import create_agent
from langchain.agents.middleware import wrap_tool_call
from langchain.messages import ToolMessage
from trooth_guard.langchain import tool_call_wrapper

agent = create_agent(model, tools=tools, middleware=[wrap_tool_call(tool_call_wrapper("policy.yaml", tool_message=ToolMessage))])
```

`tool_call_wrapper` returns a `(request, handler)` function; `atool_call_wrapper` is the async form; `middleware("policy.yaml", ...)` builds an `AgentMiddleware` with both and imports langchain only then. Hold and deny behave as in the JavaScript middleware.

### OpenAI Agents SDK (Python)

`trooth_guard.openai_agents`. Followed: https://openai.github.io/openai-agents-python/guardrails/ and https://openai.github.io/openai-agents-python/human_in_the_loop/, with `tool_guardrails.py`, `tool.py` and `run_context.py` in the SDK source, read October 7, 2026.

```python
from agents import function_tool
from trooth_guard.openai_agents import needs_approval, tool_input_guardrail

@function_tool(needs_approval=needs_approval("policy.yaml", "create_payout"),
               tool_input_guardrails=[tool_input_guardrail("policy.yaml")])
def create_payout(url: str, amount: int) -> str: ...
```

`needs_approval` is true for a hold, so the run pauses for a person. The guardrail returns `ToolGuardrailFunctionOutput.allow()`, `.raise_exception()` for a deny, and for a hold `.allow()` when `is_tool_approved` says a person approved the call, otherwise `.reject_content(message)`.

## What is open

- In `npm test` the adapters are tested against fakes in the shapes the documentation above describes (`tests/guard-adapters.test.mjs`, `sdk/python/tests/test_guard.py`). Against the framework packages themselves they are tested by the Trooth-run pilots in pilots/ (docs/GUARD-PILOTS.md), which .github/workflows/guard-pilots.yml runs every night against the latest framework releases.
- No team outside Trooth uses these adapters in production yet; that is a launch-phase item (GUARD.md section 13).
