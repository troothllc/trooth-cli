// bin/lib/guard/langchain.mjs - the Trooth guard as LangChain JS v1 agent
// middleware (createAgent from "langchain"). Copyright 2026 Trooth, LLC.
// Licensed under the Apache License, Version 2.0.
//
// Followed, read on October 7, 2026:
//   https://docs.langchain.com/oss/javascript/langchain/middleware/custom
//     createMiddleware({ name, wrapToolCall(request, handler) }); request.toolCall is
//     { name, args, id }; a wrap hook may call the handler zero times (short-circuit),
//     once, or more; it returns what the handler returns (a ToolMessage or a Command).
//   https://docs.langchain.com/oss/javascript/langgraph/interrupts
//     interrupt(payload) pauses the graph; on resume it returns the value given to
//     new Command({ resume }). It works by throwing, so it is never called inside a try.
//
// This module imports nothing from langchain or @langchain/*. troothMiddleware()
// returns the options object for createMiddleware():
//   createAgent({ model, tools, middleware: [createMiddleware(troothMiddleware(guard, { interrupt, ToolMessage }))] })
// The caller passes interrupt (from @langchain/langgraph) and ToolMessage (from
// "langchain" or @langchain/core/messages) when it wants those paths.
//
// allow -> the tool runs. hold -> interrupt() for a person when interrupt is
// given (approve on resume runs the tool; anything else does not), otherwise a
// ToolMessage with status "error" telling the model a person must approve
// (when ToolMessage is given), otherwise GuardHold is thrown. deny -> GuardDeny
// is thrown (the run stops), or with { onDeny: 'message' } a ToolMessage with
// status "error" (the call stops, the run goes on).

import { GuardHold, GuardDeny, decideToolCallSafely, describeDecision, isApproval } from './errors.mjs';

export const HOLD_INTERRUPT_TYPE = 'trooth_guard_hold';

function toolMessage(ToolMessage, request, decision, extra = '') {
  return new ToolMessage({
    content: `${describeDecision(decision)}${extra}`,
    tool_call_id: request.toolCall.id,
    name: request.toolCall.name,
    status: 'error',
  });
}

/**
 * Options for createMiddleware(). opts:
 *   interrupt    the interrupt function from @langchain/langgraph; holds go to a person
 *   ToolMessage  the ToolMessage class; lets a hold or deny answer the model instead of throwing
 *   onHold       'interrupt' | 'message' | 'throw' (default: interrupt if given, else message if ToolMessage is given, else throw)
 *   onDeny       'throw' | 'message' (default 'throw')
 *   onDecision   called with every Decision
 */
export function troothMiddleware(guard, opts = {}) {
  if (!guard || typeof guard.decideToolCall !== 'function') throw new TypeError('troothMiddleware needs a guard from createGuard');
  const { interrupt, ToolMessage, onDecision, name = 'TroothGuardMiddleware' } = opts;
  const onHold = opts.onHold ?? (interrupt ? 'interrupt' : ToolMessage ? 'message' : 'throw');
  const onDeny = opts.onDeny ?? 'throw';
  if (!['interrupt', 'message', 'throw'].includes(onHold)) throw new TypeError("onHold is 'interrupt', 'message' or 'throw'");
  if (!['message', 'throw'].includes(onDeny)) throw new TypeError("onDeny is 'message' or 'throw'");
  if (onHold === 'interrupt' && typeof interrupt !== 'function') throw new TypeError("onHold 'interrupt' needs the interrupt function from @langchain/langgraph");
  if ((onHold === 'message' || onDeny === 'message') && typeof ToolMessage !== 'function') throw new TypeError("'message' needs the ToolMessage class");

  return {
    name,
    async wrapToolCall(request, handler) {
      const call = request?.toolCall ?? {};
      const decision = await decideToolCallSafely(guard, { name: call.name, arguments: call.args ?? {} });
      if (decision === null) return handler(request);
      if (onDecision) onDecision(decision);
      if (decision.decision === 'allow') return handler(request);
      if (decision.decision === 'deny') {
        if (onDeny === 'message') return toolMessage(ToolMessage, request, decision);
        throw new GuardDeny(decision);
      }
      if (onHold === 'interrupt') {
        // Not inside a try: interrupt pauses the graph by throwing.
        const resume = interrupt({ type: HOLD_INTERRUPT_TYPE, tool_call: { name: call.name, id: call.id ?? null }, decision, message: describeDecision(decision) });
        if (isApproval(resume)) return handler(request);
        if (ToolMessage) return toolMessage(ToolMessage, request, decision, ' A person did not approve it.');
        throw new GuardHold(decision);
      }
      if (onHold === 'message') return toolMessage(ToolMessage, request, decision);
      throw new GuardHold(decision);
    },
  };
}
