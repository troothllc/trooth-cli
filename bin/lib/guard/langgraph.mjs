// bin/lib/guard/langgraph.mjs - the Trooth guard as a LangGraph JS node that
// runs before the tool node. Copyright 2026 Trooth, LLC. Licensed under the
// Apache License, Version 2.0.
//
// Followed, read on October 7, 2026:
//   https://docs.langchain.com/oss/javascript/langgraph/interrupts
//     interrupt(payload) pauses the graph and, on resume, returns the value given to
//     graph.invoke(new Command({ resume: value }), config) with the same thread_id.
//     interrupt throws to pause, so it is never called inside a try; the node runs
//     again from the top on resume, so the calls in a node keep the same order.
//   https://docs.langchain.com/oss/javascript/langgraph/graph-api  (nodes return a
//     state update; new Command({ goto, update }) routes from a node)
//
// This module imports nothing from @langchain/langgraph. The caller passes
// interrupt and, when it wants routing instead of an error, Command.
//
//   const guardNode = createGuardNode(guard, { interrupt });
//   graph.addNode('trooth_guard', guardNode).addNode('tools', toolNode)
//        .addEdge('trooth_guard', 'tools')   // the model routes tool calls to trooth_guard
//
// Routing (denyGoto, holdGoto): LangGraph runs a node's static edges in
// addition to the goto of a Command it returns, so a static edge from this
// node to the tool node would run the tools after a deny. With routing, give
// toolsGoto, add NO static edge from this node, and declare
// { ends: [toolsGoto, denyGoto, holdGoto] } in addNode; the node then returns
// new Command({ goto: toolsGoto }) when every covered call may run.
//
// The node reads the tool calls of the last message in state.messages
// (tool_calls: [{ name, args, id }]) and decides each one the policy covers,
// in order. Any deny -> GuardDeny is thrown, or with Command and denyGoto the
// node returns new Command({ goto: denyGoto, update }). Any hold, and no deny ->
// one interrupt() for all held calls; a resume that approves lets the tool
// node run, anything else throws GuardHold or routes to holdGoto. All allowed
// -> the node returns an empty update, or { [decisionsKey]: decisions }.

import { GuardHold, GuardDeny, decideToolCallSafely, describeDecision, isApproval } from './errors.mjs';

export const HOLD_INTERRUPT_TYPE = 'trooth_guard_hold';

function toolCallsOf(state, messagesKey) {
  const msgs = state?.[messagesKey];
  const last = Array.isArray(msgs) ? msgs[msgs.length - 1] : null;
  const calls = last?.tool_calls ?? last?.toolCalls ?? [];
  return Array.isArray(calls) ? calls : [];
}

/**
 * A node function for StateGraph.addNode. opts:
 *   interrupt     the interrupt function from @langchain/langgraph (required)
 *   messagesKey   the state key holding messages (default 'messages')
 *   decisionsKey  when set, the node writes the Decisions to this state key
 *   Command       the Command class, to route instead of throwing
 *   denyGoto      the node to go to on deny (needs Command)
 *   holdGoto      the node to go to when a person does not approve (needs Command)
 *   toolsGoto     the tool node to go to when the calls may run (required with denyGoto or holdGoto)
 */
export function createGuardNode(guard, opts = {}) {
  if (!guard || typeof guard.decideToolCall !== 'function') throw new TypeError('createGuardNode needs a guard from createGuard');
  const { interrupt, messagesKey = 'messages', decisionsKey, Command, denyGoto, holdGoto, toolsGoto, onDecision } = opts;
  if (typeof interrupt !== 'function') throw new TypeError('createGuardNode needs the interrupt function from @langchain/langgraph');
  if ((denyGoto || holdGoto) && typeof Command !== 'function') throw new TypeError('denyGoto and holdGoto need the Command class');
  // A static edge to the tool node would also run after a routed deny, so routing needs toolsGoto and no static edge.
  if ((denyGoto || holdGoto) && (typeof toolsGoto !== 'string' || !toolsGoto)) throw new TypeError('denyGoto and holdGoto need toolsGoto, and the graph must have no static edge from this node');

  const update = (decisions) => (decisionsKey ? { [decisionsKey]: decisions } : {});
  return async function troothGuardNode(state) {
    const decisions = [];
    for (const call of toolCallsOf(state, messagesKey)) {
      const d = await decideToolCallSafely(guard, { name: call.name, arguments: call.args ?? {} });
      if (d === null) continue;
      if (onDecision) onDecision(d);
      decisions.push({ tool_call: { name: call.name, id: call.id ?? null }, decision: d });
    }
    const denied = decisions.find((x) => x.decision.decision === 'deny');
    if (denied) {
      if (denyGoto) return new Command({ goto: denyGoto, update: update(decisions) });
      throw new GuardDeny(denied.decision);
    }
    const held = decisions.filter((x) => x.decision.decision === 'hold');
    if (held.length) {
      // Not inside a try: interrupt pauses the graph by throwing.
      const resume = interrupt({ type: HOLD_INTERRUPT_TYPE, held, message: held.map((x) => describeDecision(x.decision)).join(' ') });
      if (!isApproval(resume)) {
        if (holdGoto) return new Command({ goto: holdGoto, update: update(decisions) });
        throw new GuardHold(held[0].decision);
      }
    }
    if (toolsGoto) return new Command({ goto: toolsGoto, update: update(decisions) });
    return update(decisions);
  };
}
