"""Pilot 1 (Python), "Payments agent" (Trooth-run, test harness): the OpenAI
Agents SDK for Python (openai-agents, the real package) with a payout tool
guarded by trooth_guard.openai_agents. No LLM key: a scripted Model subclass
of agents.models.interface.Model drives the SDK's real Runner, needs_approval
interruptions, tool input guardrails and RunState approval.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from agents import Agent, Runner, ToolInputGuardrail, function_tool, set_tracing_disabled
from agents.exceptions import ToolInputGuardrailTripwireTriggered
from agents.items import ModelResponse
from agents.models.interface import Model
from agents.usage import Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

import trooth_guard.openai_agents as toa
from common import FIXTURE_CMD, LIVE_CMD, POLICIES, codes, instrument, save, step, version

set_tracing_disabled(True)
instrument(toa)
P = "payments-openai-agents-py"
LIVE = str(POLICIES / "payments-live.yaml")
FIX = str(POLICIES / "payments-fixture.yaml")


class ScriptedModel(Model):
    """First turn: call `tool` with `args`. After a tool result: answer in text."""

    def __init__(self, tool: str, args: dict):
        self.tool, self.args, self.n, self.saw = tool, args, 0, []

    async def get_response(self, system_instructions, input, model_settings, tools, output_schema, handoffs, tracing, *, previous_response_id=None, conversation_id=None, prompt=None, **kw):
        self.n += 1
        items = input if isinstance(input, list) else []
        outs = [i for i in items if isinstance(i, dict) and i.get("type") == "function_call_output"]
        if outs:
            self.saw.append(outs[-1].get("output"))
            msg = ResponseOutputMessage(id=f"msg_{self.n}", type="message", role="assistant", status="completed", content=[ResponseOutputText(type="output_text", text="Payout step finished.", annotations=[])])
            return ModelResponse(output=[msg], usage=Usage(), response_id=None)
        call = ResponseFunctionToolCall(type="function_call", id=f"fc_{self.n}", call_id=f"call_{self.n}", name=self.tool, arguments=json.dumps(self.args), status="completed")
        return ModelResponse(output=[call], usage=Usage(), response_id=None)

    def stream_response(self, *a, **kw):
        raise NotImplementedError("streaming is not used in this pilot")


GR_OUT: list = []


def agent_for(policy: str, cmd, args: dict, executed: list, tool_name: str = "create_payout", mod=None):
    mod = mod or toa
    # The adapter's own ToolInputGuardrail, with its function wrapped so the pilot
    # sees every output (a resumed RunResult does not list tool_input_guardrail_results).
    real = mod.tool_input_guardrail(policy, tools=["create_payout", "stripe.create_payout"], trooth_cmd=cmd)
    assert isinstance(real, ToolInputGuardrail)
    inner = real.guardrail_function

    async def observed(data):
        out = await inner(data)
        GR_OUT.append(out)
        return out

    @function_tool(
        name_override=tool_name,
        needs_approval=mod.needs_approval(policy, tool_name, trooth_cmd=cmd),
        tool_input_guardrails=[ToolInputGuardrail(guardrail_function=observed, name=real.name)],
    )
    def create_payout(url: str, amount: int) -> str:
        """Send a payout to a vendor."""
        executed.append((url, amount))
        return f"payout of {amount} sent to {url}"

    model = ScriptedModel(tool_name, args)
    return Agent(name="payments", instructions="Pay vendors.", model=model, tools=[create_payout]), model


async def scenario(policy, cmd, args, approve=None, tool_name="create_payout", mod=None):
    executed: list = []
    GR_OUT.clear()
    agent, model = agent_for(policy, cmd, args, executed, tool_name, mod)
    res, err, n_int, before = None, None, 0, 0
    try:
        res = await Runner.run(agent, "Pay the invoice.")
        n_int = len(res.interruptions)
        before = len(executed)
        if n_int and approve is not None:
            state = res.to_state()
            (state.approve if approve else state.reject)(res.interruptions[0])
            res = await Runner.run(agent, state)
    except Exception as e:  # noqa: BLE001 - recorded
        err = e
    last = GR_OUT[-1] if GR_OUT else None
    info = (last.output_info if last else None) or {}
    if isinstance(err, ToolInputGuardrailTripwireTriggered):
        info = err.output.output_info or {}
    return {"executed": len(executed), "before": before, "interruptions": n_int, "err": type(err).__name__ if err else None, "err_msg": str(err)[:160] if err else None,
            "behavior": (last.behavior if last else None), "approved_by_person": info.get("approved_by_person", False), "decision": (info.get("decision") or {}).get("decision"), "codes": codes(info.get("decision")), "model_saw": model.saw[-1] if model.saw else None}


async def main() -> int:
    o = await scenario(LIVE, LIVE_CMD, {"url": "https://trooth.co/pay", "amount": 25})
    step(P, "live trooth.co: allow, payout runs", expected="executed 1, no interruption", observed=f"executed {o['executed']}, interruptions {o['interruptions']}, decision {o['decision']}, err {o['err']}", ok=o["executed"] == 1 and o["interruptions"] == 0 and not o["err"])

    o = await scenario(LIVE, LIVE_CMD, {"url": "https://pilot-unknown-7f3a9c2e.com/pay", "amount": 40}, approve=True)
    step(P, "live unknown domain: hold interrupts via needs_approval", expected="1 interruption, executed 0 before approval", observed=f"interruptions {o['interruptions']}, executed before {o['before']}", ok=o["interruptions"] == 1 and o["before"] == 0)
    step(P, "live unknown domain: after state.approve, is_tool_approved is reachable from the guardrail context and allows", expected="executed 1, approved_by_person True, decision hold NO_RECORD", observed=f"executed {o['executed']}, approved_by_person {o['approved_by_person']}, decision {o['decision']} {o['codes']}, err {o['err']}", ok=o["executed"] == 1 and o["approved_by_person"] is True and "NO_RECORD" in o["codes"])

    o = await scenario(LIVE, LIVE_CMD, {"url": "https://pilot-unknown-7f3a9c2e.com/pay", "amount": 40}, approve=False)
    step(P, "live unknown domain: state.reject, payout does not run", expected="executed 0", observed=f"executed {o['executed']}, model saw {str(o['model_saw'])[:80]}", ok=o["executed"] == 0)

    o = await scenario(LIVE, LIVE_CMD, {"url": "https://www.trooth.co/pay", "amount": 40})
    step(P, "live www.trooth.co: deny SUBJECT_MISMATCH raises the tool input tripwire", expected="ToolInputGuardrailTripwireTriggered, executed 0", observed=f"{o['err']}, decision {o['decision']} {o['codes']}, executed {o['executed']}", ok=o["err"] == "ToolInputGuardrailTripwireTriggered" and o["executed"] == 0 and "SUBJECT_MISMATCH" in o["codes"])

    for host, code, world in [("spoofed-vendor.com", "SUBJECT_MISMATCH", "main"), ("revoked-key-vendor.com", "KEY_NOT_TRUSTED", "main"), ("forged-log-vendor.com", "NOT_IN_LOG", "forged")]:
        os.environ["TROOTH_FIXTURE_WORLD"] = world
        o = await scenario(FIX, FIXTURE_CMD, {"url": f"https://{host}/pay", "amount": 10})
        step(P, f"fixture {host}: deny {code}", expected="ToolInputGuardrailTripwireTriggered, executed 0", observed=f"{o['err']}, decision {o['decision']} {o['codes']}, executed {o['executed']}", ok=o["err"] == "ToolInputGuardrailTripwireTriggered" and o["executed"] == 0 and code in o["codes"])
    os.environ["TROOTH_FIXTURE_WORLD"] = "main"

    o = await scenario(FIX, FIXTURE_CMD, {"url": "https://name-match-vendor.com/pay", "amount": 10}, approve=True)
    step(P, "fixture name-match-vendor.com: hold EVIDENCE_MISSING, approved, runs", expected="interruption, executed 1, approved_by_person True", observed=f"interruptions {o['interruptions']}, executed {o['executed']}, approved_by_person {o['approved_by_person']}, codes {o['codes']}", ok=o["interruptions"] == 1 and o["executed"] == 1 and o["approved_by_person"] is True)

    # A tool the policy does not cover, with needs_approval from the adapter: the CLI says covered: false and decide() returns None.
    o = await scenario(LIVE, LIVE_CMD, {"url": "https://trooth.co/x", "amount": 1}, tool_name="lookup_vendor")
    step(P, "needs_approval on a tool the policy does not cover: the tool runs without a decision", expected="executed 1, no error (GUARD-ADAPTERS.md: a tool the policy does not cover runs)", observed=f"executed {o['executed']}, err {o['err']}: {o['err_msg']}", ok=o["executed"] == 1 and not o["err"], detail="regression check for the 0.14.0 fix")
    o = await scenario(LIVE, LIVE_CMD, {"url": "https://pilot-unknown-7f3a9c2e.com/pay", "amount": 40})
    step(P, "needs_approval, covered tool: a hold still interrupts", expected="1 interruption, executed 0", observed=f"interruptions {o['interruptions']}, executed {o['executed']}", ok=o["interruptions"] == 1 and o["executed"] == 0)
    return save("pilot1-py", packages={"openai-agents": version("openai-agents"), "openai": version("openai")}, python=sys.version.split()[0])


if __name__ == "__main__":
    sys.exit(1 if asyncio.run(main()) else 0)
