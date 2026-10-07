"""The Trooth guard as a LangGraph node that runs before the tool node.

Followed, read on October 7, 2026:
  https://docs.langchain.com/oss/python/langgraph/interrupts  (interrupt(value) pauses the
    graph; graph.invoke(Command(resume=...), config) with the same thread_id resumes it and
    interrupt returns the resume value; interrupt raises to pause, so it is never called
    inside a try; the node runs again from the top on resume)

    from langgraph.types import interrupt, Command
    from trooth_guard.langgraph import guard_node

    builder.add_node("trooth_guard", guard_node("policy.yaml", interrupt=interrupt))
    builder.add_edge("trooth_guard", "tools")

The node reads the tool calls of the last message in state["messages"] and
decides each in order. Any deny raises GuardDeny (or routes to deny_goto with
Command). Any hold, and no deny, calls interrupt once for all held calls; a
resume that approves lets the tool node run, anything else raises GuardHold
(or routes to hold_goto). This module imports nothing from langgraph unless
interrupt is not passed, when it imports langgraph.types.interrupt.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Mapping, Optional

from .core import GuardDeny, GuardHold, covered, decide, describe, is_approval

HOLD_INTERRUPT_TYPE = "trooth_guard_hold"


def _tool_calls(state: Any, key: str) -> List[Mapping[str, Any]]:
    msgs = state.get(key) if isinstance(state, Mapping) else getattr(state, key, None)
    if not msgs:
        return []
    last = msgs[-1]
    calls = last.get("tool_calls") if isinstance(last, Mapping) else getattr(last, "tool_calls", None)
    return list(calls or [])


def guard_node(
    policy_path: str,
    *,
    interrupt: Optional[Callable[[Any], Any]] = None,
    tools: Optional[List[str]] = None,
    messages_key: str = "messages",
    decisions_key: Optional[str] = None,
    command: Optional[Callable[..., Any]] = None,
    deny_goto: Optional[str] = None,
    hold_goto: Optional[str] = None,
    on_decision: Optional[Callable[[dict], None]] = None,
    **decide_kw: Any,
) -> Callable[[Any], Any]:
    """A node function for StateGraph.add_node. tools: the policy's applies_to.tools
    globs; calls to other tools are not decided. None decides every call."""
    if interrupt is None:
        from langgraph.types import interrupt as _interrupt  # optional; only when not passed

        interrupt = _interrupt
    if (deny_goto or hold_goto) and command is None:
        raise TypeError("deny_goto and hold_goto need command (langgraph.types.Command)")

    def update(decisions: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {decisions_key: decisions} if decisions_key else {}

    def trooth_guard_node(state: Any) -> Any:
        decisions: List[Dict[str, Any]] = []
        for call in _tool_calls(state, messages_key):
            name = call.get("name") if isinstance(call, Mapping) else getattr(call, "name", None)
            args = call.get("args") if isinstance(call, Mapping) else getattr(call, "args", None)
            cid = call.get("id") if isinstance(call, Mapping) else getattr(call, "id", None)
            if not covered(name, tools):
                continue
            d = decide(policy_path, str(name), None, args if args is not None else {}, **decide_kw)
            if d is None:
                continue
            if on_decision:
                on_decision(d)
            decisions.append({"tool_call": {"name": name, "id": cid}, "decision": d})
        denied = [x for x in decisions if x["decision"]["decision"] == "deny"]
        if denied:
            if deny_goto:
                return command(goto=deny_goto, update=update(decisions))
            raise GuardDeny(denied[0]["decision"])
        held = [x for x in decisions if x["decision"]["decision"] == "hold"]
        if held:
            # Not inside a try: interrupt pauses the graph by raising.
            resume = interrupt({"type": HOLD_INTERRUPT_TYPE, "held": held, "message": " ".join(describe(x["decision"]) for x in held)})
            if not is_approval(resume):
                if hold_goto:
                    return command(goto=hold_goto, update=update(decisions))
                raise GuardHold(held[0]["decision"])
        return update(decisions)

    return trooth_guard_node
