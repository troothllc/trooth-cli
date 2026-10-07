"""The Trooth guard for CrewAI. Imports nothing from crewai.

Followed, read on October 7, 2026:
  https://docs.crewai.com/en/concepts/tasks  (task guardrails: a function that takes the
    TaskOutput and returns Tuple[bool, Any]; (True, result) passes, (False, "message") sends
    the message back to the agent and retries up to guardrail_max_retries, default 3)
  https://docs.crewai.com/en/learn/tool-hooks  (before_tool_call hooks: the hook gets a
    ToolCallHookContext with tool_name and tool_input; returning False blocks the call)

    from crewai.hooks import before_tool_call
    from trooth_guard.crewai import before_tool_call_hook, task_guardrail

    before_tool_call(before_tool_call_hook("policy.yaml"))            # every tool call
    Task(..., guardrail=task_guardrail("policy.yaml", "stripe.create_payout"))

allow runs (or passes). deny blocks. hold blocks unless `ask(decision)` returns
True, which is where a person approves; a failure to decide is a hold.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Iterable, Mapping, Optional, Tuple

from .core import covered, decide, describe


def _default_extract(output: Any) -> Optional[Mapping[str, Any]]:
    """The task output as typed arguments: json_dict, pydantic, or raw parsed as JSON."""
    jd = getattr(output, "json_dict", None)
    if isinstance(jd, Mapping):
        return {"host": None, "args": dict(jd)}
    pd = getattr(output, "pydantic", None)
    if pd is not None and hasattr(pd, "model_dump"):
        return {"host": None, "args": pd.model_dump()}
    raw = getattr(output, "raw", output)
    try:
        args = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        args = raw
    return {"host": None, "args": args}


def task_guardrail(
    policy_path: str,
    tool: str,
    *,
    extract: Optional[Callable[[Any], Optional[Mapping[str, Any]]]] = None,
    ask: Optional[Callable[[dict], bool]] = None,
    on_decision: Optional[Callable[[dict], None]] = None,
    **decide_kw: Any,
) -> Callable[[Any], Tuple[bool, Any]]:
    """A CrewAI task guardrail for a task whose output is an action to check.

    extract(output) returns {"host": ..., "args": ...} for the action, or None
    when the output names no action (then it passes). By default the output is
    read as typed arguments and the CLI finds the host in them.
    """
    ex = extract or _default_extract

    def guardrail(output: Any) -> Tuple[bool, Any]:
        try:
            action = ex(output)
        except Exception as e:  # noqa: BLE001 - a failure to read the action is a hold
            return (False, f"Trooth guard: hold. The action could not be read from the output: {e}")
        if action is None:
            return (True, output)
        d = decide(policy_path, tool, action.get("host"), action.get("args"), **decide_kw)
        if d is None:
            return (True, output)
        if on_decision:
            on_decision(d)
        if d["decision"] == "allow":
            return (True, output)
        if d["decision"] == "hold" and ask is not None and ask(d) is True:
            return (True, output)
        return (False, describe(d))

    # CrewAI checks the return annotation with typing.get_origin when the Task
    # is built. Under `from __future__ import annotations` the annotation is the
    # string "Tuple[bool, Any]", which that check refuses, so give it the real type.
    guardrail.__annotations__["return"] = Tuple[bool, Any]
    guardrail.__annotations__["output"] = Any
    return guardrail


def before_tool_call_hook(
    policy_path: str,
    *,
    tools: Optional[Iterable[str]] = None,
    ask: Optional[Callable[[dict], bool]] = None,
    on_decision: Optional[Callable[[dict], None]] = None,
    **decide_kw: Any,
) -> Callable[[Any], Optional[bool]]:
    """A CrewAI before_tool_call hook: returns False to block the call, None to let it run.

    tools: the policy's applies_to.tools globs; a call to any other tool runs
    without asking the CLI. None asks about every call. ask(decision) is called for a hold; True lets
    the call run.
    """
    only = list(tools) if tools is not None else None

    def hook(context: Any) -> Optional[bool]:
        name = getattr(context, "tool_name", None)
        if not covered(name, only):
            return None
        d = decide(policy_path, str(name), None, getattr(context, "tool_input", None), **decide_kw)
        if d is None:
            return None
        if on_decision:
            on_decision(d)
        if d["decision"] == "allow":
            return None
        if d["decision"] == "hold" and ask is not None and ask(d) is True:
            return None
        return False

    return hook
