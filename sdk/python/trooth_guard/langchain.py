"""The Trooth guard as LangChain v1 agent middleware (create_agent).

Followed, read on October 7, 2026:
  https://docs.langchain.com/oss/python/langchain/middleware/custom  (wrap_tool_call:
    a function (request, handler) -> ToolMessage | Command; request.tool_call is a dict with
    "name", "args" and "id"; the decorator langchain.agents.middleware.wrap_tool_call makes
    middleware of it; AgentMiddleware subclasses define wrap_tool_call and awrap_tool_call)
  https://docs.langchain.com/oss/python/langgraph/interrupts  (interrupt and Command(resume=...))

    from langchain.agents import create_agent
    from langchain.agents.middleware import wrap_tool_call
    from langchain.messages import ToolMessage
    from trooth_guard.langchain import tool_call_wrapper

    guard = wrap_tool_call(tool_call_wrapper("policy.yaml", tool_message=ToolMessage))
    agent = create_agent(model, tools=tools, middleware=[guard])

allow runs the tool. hold: interrupt for a person when interrupt is passed
(approve on resume runs the tool), else an error ToolMessage telling the model
a person must approve (when tool_message is passed), else GuardHold is raised.
deny: GuardDeny is raised, or with on_deny="message" an error ToolMessage.
middleware() builds an AgentMiddleware subclass and imports langchain only then.
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Optional, Sequence

from .core import GuardDeny, GuardHold, covered, decide, describe, is_approval

HOLD_INTERRUPT_TYPE = "trooth_guard_hold"


def _call_of(request: Any) -> dict:
    tc = getattr(request, "tool_call", None)
    if tc is None and isinstance(request, dict):
        tc = request.get("tool_call")
    return tc if isinstance(tc, dict) else {}


class _Plan:
    def __init__(self, policy_path, interrupt, tool_message, on_hold, on_deny, tools, on_decision, decide_kw):
        self.policy_path = policy_path
        self.interrupt = interrupt
        self.tool_message = tool_message
        self.on_hold = on_hold or ("interrupt" if interrupt else "message" if tool_message else "raise")
        self.on_deny = on_deny
        self.tools = tools
        self.on_decision = on_decision
        self.decide_kw = decide_kw
        if self.on_hold not in ("interrupt", "message", "raise"):
            raise ValueError('on_hold is "interrupt", "message" or "raise"')
        if self.on_deny not in ("raise", "message"):
            raise ValueError('on_deny is "raise" or "message"')
        if self.on_hold == "interrupt" and interrupt is None:
            raise ValueError('on_hold="interrupt" needs interrupt (langgraph.types.interrupt)')
        if "message" in (self.on_hold, self.on_deny) and tool_message is None:
            raise ValueError('"message" needs tool_message (the ToolMessage class)')

    def decision(self, call: dict) -> Optional[dict]:
        if not covered(call.get("name"), self.tools):
            return None
        d = decide(self.policy_path, str(call.get("name")), None, call.get("args") or {}, **self.decide_kw)
        if d is None:
            return None
        if self.on_decision:
            self.on_decision(d)
        return d

    def message(self, call: dict, d: dict, extra: str = "") -> Any:
        return self.tool_message(content=describe(d) + extra, tool_call_id=call.get("id"), name=call.get("name"), status="error")

    def after(self, call: dict, d: Optional[dict]) -> Any:
        """None to run the tool; otherwise the ToolMessage to return. Raises for raise paths."""
        if d is None or d["decision"] == "allow":
            return None
        if d["decision"] == "deny":
            if self.on_deny == "message":
                return self.message(call, d)
            raise GuardDeny(d)
        if self.on_hold == "interrupt":
            # Not inside a try: interrupt pauses the graph by raising.
            resume = self.interrupt({"type": HOLD_INTERRUPT_TYPE, "tool_call": {"name": call.get("name"), "id": call.get("id")}, "decision": d, "message": describe(d)})
            if is_approval(resume):
                return None
            if self.tool_message is not None:
                return self.message(call, d, " A person did not approve it.")
            raise GuardHold(d)
        if self.on_hold == "message":
            return self.message(call, d)
        raise GuardHold(d)


def tool_call_wrapper(
    policy_path: str,
    *,
    interrupt: Optional[Callable[[Any], Any]] = None,
    tool_message: Optional[Callable[..., Any]] = None,
    on_hold: Optional[str] = None,
    on_deny: str = "raise",
    tools: Optional[Sequence[str]] = None,
    on_decision: Optional[Callable[[dict], None]] = None,
    **decide_kw: Any,
) -> Callable[[Any, Callable[[Any], Any]], Any]:
    """A (request, handler) function for langchain.agents.middleware.wrap_tool_call.

    tools: the policy's applies_to.tools globs; other tools run without asking.
    """
    plan = _Plan(policy_path, interrupt, tool_message, on_hold, on_deny, tools, on_decision, decide_kw)

    def trooth_guard(request: Any, handler: Callable[[Any], Any]) -> Any:
        call = _call_of(request)
        out = plan.after(call, plan.decision(call))
        return handler(request) if out is None else out

    trooth_guard.__name__ = "trooth_guard"
    return trooth_guard


def atool_call_wrapper(policy_path: str, **kw: Any) -> Callable[[Any, Callable[[Any], Awaitable[Any]]], Awaitable[Any]]:
    """The async form of tool_call_wrapper; the CLI runs in a worker thread."""
    plan = _Plan(policy_path, kw.pop("interrupt", None), kw.pop("tool_message", None), kw.pop("on_hold", None), kw.pop("on_deny", "raise"), kw.pop("tools", None), kw.pop("on_decision", None), kw)

    async def trooth_guard(request: Any, handler: Callable[[Any], Awaitable[Any]]) -> Any:
        call = _call_of(request)
        d = await asyncio.to_thread(plan.decision, call)
        out = plan.after(call, d)
        return await handler(request) if out is None else out

    trooth_guard.__name__ = "trooth_guard"
    return trooth_guard


def middleware(policy_path: str, **kw: Any) -> Any:
    """An AgentMiddleware instance with wrap_tool_call and awrap_tool_call. Imports langchain."""
    from langchain.agents.middleware import AgentMiddleware  # optional; only here

    sync_fn = tool_call_wrapper(policy_path, **dict(kw))
    async_fn = atool_call_wrapper(policy_path, **dict(kw))

    class TroothGuardMiddleware(AgentMiddleware):
        def wrap_tool_call(self, request, handler):
            return sync_fn(request, handler)

        async def awrap_tool_call(self, request, handler):
            return await async_fn(request, handler)

    return TroothGuardMiddleware()
