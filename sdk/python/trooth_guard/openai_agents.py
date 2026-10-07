"""The Trooth guard for the OpenAI Agents SDK for Python (openai-agents).

Followed, read on October 7, 2026:
  https://openai.github.io/openai-agents-python/guardrails/  (tool guardrails:
    @tool_input_guardrail functions get ToolInputGuardrailData whose context is a ToolContext
    with tool_name, tool_call_id and tool_arguments (a JSON string); they return
    ToolGuardrailFunctionOutput.allow(), .reject_content(message) or .raise_exception();
    attached with @function_tool(tool_input_guardrails=[...]))
  https://openai.github.io/openai-agents-python/human_in_the_loop/  (needs_approval: True or
    an async function (run_context, params, call_id) -> bool; result.interruptions,
    state.approve / state.reject)
  and src/agents/tool_guardrails.py, tool.py and run_context.py
  (RunContextWrapper.is_tool_approved(tool_name, call_id)) on github.com/openai/openai-agents-python main.

    from agents import function_tool
    from trooth_guard.openai_agents import needs_approval, tool_input_guardrail

    @function_tool(needs_approval=needs_approval("policy.yaml", "create_payout"),
                   tool_input_guardrails=[tool_input_guardrail("policy.yaml")])
    def create_payout(url: str, amount: int) -> str: ...

allow runs the tool. hold: needs_approval pauses the run for a person; the
guardrail then allows a call a person approved and otherwise rejects it with
a message to the model. deny: the guardrail raises the tripwire
(ToolInputGuardrailTripwireTriggered), which stops the run.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Callable, Dict, Optional, Sequence

from .core import covered, decide, describe


class _Output:
    """The shape of agents.ToolGuardrailFunctionOutput, for use without the SDK installed."""

    def __init__(self, behavior: Dict[str, Any], output_info: Any = None):
        self.behavior = behavior
        self.output_info = output_info

    @classmethod
    def allow(cls, output_info: Any = None) -> "_Output":
        return cls({"type": "allow"}, output_info)

    @classmethod
    def reject_content(cls, message: str, output_info: Any = None) -> "_Output":
        return cls({"type": "reject_content", "message": message}, output_info)

    @classmethod
    def raise_exception(cls, output_info: Any = None) -> "_Output":
        return cls({"type": "raise_exception"}, output_info)


def _factory(output_factory: Any) -> Any:
    if output_factory is not None:
        return output_factory
    try:
        from agents import ToolGuardrailFunctionOutput  # optional

        return ToolGuardrailFunctionOutput
    except Exception:  # noqa: BLE001 - the SDK is optional
        return _Output


def _parse(args: Any) -> Any:
    if not isinstance(args, str):
        return args if args is not None else {}
    try:
        return json.loads(args or "{}")
    except ValueError:
        return args


def _approved(ctx: Any, name: Any, call_id: Any) -> bool:
    fn = getattr(ctx, "is_tool_approved", None)
    if not callable(fn) or name is None or call_id is None:
        return False
    try:
        return fn(name, call_id) is True
    except Exception:  # noqa: BLE001
        return False


def tool_input_guardrail_function(
    policy_path: str,
    *,
    on_hold: str = "reject",
    tools: Optional[Sequence[str]] = None,
    output_factory: Any = None,
    on_decision: Optional[Callable[[dict], None]] = None,
    **decide_kw: Any,
) -> Callable[[Any], Any]:
    """The guardrail function: async (ToolInputGuardrailData) -> ToolGuardrailFunctionOutput.

    on_hold "reject" (default) rejects a held call no person approved with a
    message to the model; "raise" raises the tripwire instead. tools: the
    policy's applies_to.tools globs; other tools are allowed without asking.
    """
    if on_hold not in ("reject", "raise"):
        raise ValueError('on_hold is "reject" or "raise"')
    F = _factory(output_factory)

    async def trooth_guard(data: Any) -> Any:
        ctx = getattr(data, "context", None)
        name = getattr(ctx, "tool_name", None)
        if not covered(name, tools):
            return F.allow({"covered": False})
        args = _parse(getattr(ctx, "tool_arguments", None))
        d = await asyncio.to_thread(decide, policy_path, str(name), None, args, **decide_kw)
        if d is None:
            return F.allow({"covered": False})
        if on_decision:
            on_decision(d)
        info = {"covered": True, "decision": d}
        if d["decision"] == "allow":
            return F.allow(info)
        if d["decision"] == "deny":
            return F.raise_exception(info)
        if _approved(ctx, name, getattr(ctx, "tool_call_id", None)):
            return F.allow({**info, "approved_by_person": True})
        return F.raise_exception(info) if on_hold == "raise" else F.reject_content(describe(d), info)

    trooth_guard.__name__ = "trooth_guard"
    return trooth_guard


def tool_input_guardrail(policy_path: str, *, name: str = "trooth_guard", **kw: Any) -> Any:
    """An agents.ToolInputGuardrail. Imports the SDK."""
    from agents import ToolInputGuardrail  # optional; only here

    return ToolInputGuardrail(guardrail_function=tool_input_guardrail_function(policy_path, **kw), name=name)


def needs_approval(
    policy_path: str,
    tool_name: str,
    *,
    on_decision: Optional[Callable[[dict], None]] = None,
    **decide_kw: Any,
) -> Callable[[Any, Dict[str, Any], str], Any]:
    """An approval policy for function_tool(needs_approval=...): True when the guard holds the call.

    Deny answers False: the guardrail stops a denied call; a person cannot approve it.
    """

    async def policy(run_context: Any, params: Dict[str, Any], call_id: str) -> bool:
        d = await asyncio.to_thread(decide, policy_path, tool_name, None, params, **decide_kw)
        if on_decision:
            on_decision(d)
        return d["decision"] == "hold"

    return policy
