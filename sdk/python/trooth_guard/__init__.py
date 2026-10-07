"""trooth_guard: the Trooth guard for Python agent frameworks.

    from trooth_guard import decide
    d = decide("policy.yaml", "stripe.create_payout", host="api.example.com")
    d["decision"]  # "allow", "hold" or "deny"

One decision implementation: this package runs `trooth guard decide --json`
(the npm package `trooth`) in a subprocess and parses its Decision. It needs
no Python package. Adapters, each importing nothing from its framework:
trooth_guard.crewai, trooth_guard.langgraph, trooth_guard.langchain and
trooth_guard.openai_agents. Licensed under the Apache License 2.0.

The guard answers allow, hold or deny about an action under the caller's
policy. It never labels a company.
"""

from .core import (
    EXIT_ALLOW,
    EXIT_DENY,
    EXIT_HOLD,
    TROOTH_VERSION,
    GuardDeny,
    GuardError,
    GuardHold,
    decide,
    decide_tool_call,
    describe,
    covered,
    error_for,
    fail_closed,
    is_approval,
    reason_codes,
    trooth_command,
)

__all__ = [
    "EXIT_ALLOW",
    "EXIT_DENY",
    "EXIT_HOLD",
    "TROOTH_VERSION",
    "GuardDeny",
    "GuardError",
    "GuardHold",
    "decide",
    "decide_tool_call",
    "describe",
    "covered",
    "error_for",
    "fail_closed",
    "is_approval",
    "reason_codes",
    "trooth_command",
]
