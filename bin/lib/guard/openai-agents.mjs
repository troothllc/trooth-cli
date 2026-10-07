// bin/lib/guard/openai-agents.mjs - the Trooth guard for the OpenAI Agents SDK
// for JavaScript and TypeScript (@openai/agents). Copyright 2026 Trooth, LLC.
// Licensed under the Apache License, Version 2.0.
//
// Followed, read on October 7, 2026:
//   https://openai.github.io/openai-agents-js/guides/guardrails/  (tool guardrails, tripwires)
//   https://openai.github.io/openai-agents-js/guides/human-in-the-loop/  (needsApproval, interruptions)
//   and the SDK source those pages build from: packages/agents-core/src/toolGuardrail.ts
//   (defineToolInputGuardrail, ToolGuardrailFunctionOutputFactory), tool.ts
//   (ToolApprovalFunction(runContext, input, callId)), runContext.ts
//   (RunContext.isToolApproved({ toolName, callId })), on github.com/openai/openai-agents-js main.
//
// This module imports nothing from @openai/agents. It returns plain objects in
// the shapes the SDK reads:
//   a tool input guardrail   { type: 'tool_input', name, run(data) }
//     run returns           { behavior: { type: 'allow' | 'rejectContent' | 'throwException', message? }, outputInfo }
//     (exactly what ToolGuardrailFunctionOutputFactory.allow / rejectContent / throwException return)
//   an approval policy       async (runContext, input, callId) => boolean   (tool({ needsApproval }))
//   an agent input guardrail { name, runInParallel: false, execute({ agent, input, context }) }
//     returning { tripwireTriggered, outputInfo }
//
// Allow runs the tool. Hold goes to a person: needsApproval pauses the run
// with an interruption (result.interruptions; result.state.approve or reject).
// Deny throws the tool input tripwire, which stops the run.

import { decideToolCallSafely, decideSafely, describeDecision, failClosedDecision, parseArgs } from './errors.mjs';

const allow = (outputInfo) => ({ behavior: { type: 'allow' }, outputInfo });
const rejectContent = (message, outputInfo) => ({ behavior: { type: 'rejectContent', message }, outputInfo });
const throwException = (outputInfo) => ({ behavior: { type: 'throwException' }, outputInfo });

function approvedByPerson(data) {
  const ctx = data?.context;
  const call = data?.toolCall;
  if (!ctx || typeof ctx.isToolApproved !== 'function' || !call) return false;
  try {
    return ctx.isToolApproved({ toolName: call.name, callId: call.callId, ...(data.agent ? { agent: data.agent } : {}) }) === true;
  } catch {
    return false;
  }
}

/**
 * A tool input guardrail (`tool({ inputGuardrails: [troothToolInputGuardrail(guard)] })`).
 * allow -> allow. deny -> throwException, so the SDK raises
 * ToolInputGuardrailTripwireTriggered and the run stops. hold -> allow only
 * when a person already approved this call through needsApproval; otherwise
 * rejectContent (the tool is skipped and the model is told a person must
 * approve it), or throwException with `{ onHold: 'throw' }`.
 * A tool the policy does not cover is allowed with outputInfo { covered: false }.
 */
export function troothToolInputGuardrail(guard, { name = 'trooth_guard', onHold = 'reject' } = {}) {
  if (!guard || typeof guard.decideToolCall !== 'function') throw new TypeError('troothToolInputGuardrail needs a guard from createGuard');
  if (!['reject', 'throw'].includes(onHold)) throw new TypeError("onHold is 'reject' or 'throw'");
  return {
    type: 'tool_input',
    name,
    async run(data) {
      const call = data?.toolCall ?? {};
      const decision = await decideToolCallSafely(guard, { name: call.name, arguments: parseArgs(call.arguments) });
      if (decision === null) return allow({ covered: false });
      if (decision.decision === 'allow') return allow({ covered: true, decision });
      if (decision.decision === 'deny') return throwException({ covered: true, decision });
      if (approvedByPerson(data)) return allow({ covered: true, decision, approved_by_person: true });
      return onHold === 'throw' ? throwException({ covered: true, decision }) : rejectContent(describeDecision(decision), { covered: true, decision });
    },
  };
}

/**
 * An approval policy for `tool({ name, needsApproval })`: true when the guard
 * holds the call, so the SDK pauses the run with an interruption for a
 * person. The SDK does not pass the tool name to this function, so give it.
 * Deny answers false here: the input guardrail stops a denied call, and a
 * person cannot approve it. `onDecision` sees every Decision.
 */
export function troothNeedsApproval(guard, toolName, { onDecision } = {}) {
  if (!guard || typeof guard.decideToolCall !== 'function') throw new TypeError('troothNeedsApproval needs a guard from createGuard');
  if (typeof toolName !== 'string' || !toolName) throw new TypeError('troothNeedsApproval needs the tool name');
  return async (_runContext, input, _callId) => {
    const decision = await decideToolCallSafely(guard, { name: toolName, arguments: parseArgs(input) });
    if (decision === null) return false;
    if (onDecision) onDecision(decision);
    return decision.decision === 'hold';
  };
}

/**
 * Tool options with the guard added: needsApproval (kept true where the
 * options already asked for approval) and the input guardrail first in
 * inputGuardrails. Pass the result to tool() from @openai/agents.
 */
export function guardTool(guard, toolOptions, opts = {}) {
  if (!toolOptions || typeof toolOptions.name !== 'string') throw new TypeError('guardTool needs tool options with a name');
  const ours = troothNeedsApproval(guard, toolOptions.name, opts);
  const theirs = toolOptions.needsApproval;
  const needsApproval = theirs === true ? true
    : typeof theirs === 'function' ? async (ctx, input, callId) => (await ours(ctx, input, callId)) || (await theirs(ctx, input, callId))
    : ours;
  return { ...toolOptions, needsApproval, inputGuardrails: [troothToolInputGuardrail(guard, opts), ...(toolOptions.inputGuardrails ?? [])] };
}

/**
 * An agent input guardrail (`new Agent({ inputGuardrails: [...] })`) for an
 * action named in the run's input itself. `extract(input, context)` returns
 * the actions to check, [{ tool, host, args? }], or [] for none. Any hold or
 * deny trips the wire (InputGuardrailTripwireTriggered); outputInfo carries
 * every Decision. An input guardrail has no approval path, so a hold stops
 * the run here too; route held actions to a person through a tool instead.
 */
export function troothAgentInputGuardrail(guard, { name = 'trooth_guard_input', extract } = {}) {
  if (!guard || typeof guard.decide !== 'function') throw new TypeError('troothAgentInputGuardrail needs a guard from createGuard');
  if (typeof extract !== 'function') throw new TypeError('troothAgentInputGuardrail needs extract(input, context)');
  return {
    name,
    // Block the model until the check is done, so no tool runs first.
    runInParallel: false,
    async execute({ input, context } = {}) {
      const decisions = [];
      let actions;
      try {
        actions = await extract(input, context);
      } catch (e) {
        decisions.push(failClosedDecision(guard, {}, `extract failed: ${e?.message ?? e}`));
      }
      for (const a of Array.isArray(actions) ? actions : []) decisions.push(await decideSafely(guard, { tool: a.tool, host: a.host ?? null, args: a.args }));
      const tripped = decisions.some((d) => d.decision !== 'allow');
      return { tripwireTriggered: tripped, outputInfo: { decisions } };
    },
  };
}
