"""Pilot 3 (CrewAI part), "Data-export agent" (Trooth-run, test harness):
CrewAI (the real package) with trooth_guard.crewai's before_tool_call hook
and task guardrail. No LLM key: a scripted subclass of crewai's BaseLLM
answers in CrewAI's ReAct text format, so CrewAI's real agent executor,
tool-call hooks, task guardrail and retry machinery run.
"""

from __future__ import annotations

import json
import os
import sys

os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")

from crewai import Agent, Crew, Task  # noqa: E402
from crewai.hooks import before_tool_call, clear_before_tool_call_hooks  # noqa: E402
from crewai.llms.base_llm import BaseLLM  # noqa: E402
from crewai.tools import tool  # noqa: E402

import trooth_guard.crewai as tgc  # noqa: E402
from common import FIXTURE_CMD, LIVE_CMD, POLICIES, codes, instrument, save, step, version  # noqa: E402

instrument(tgc)
P = "data-export-crewai"
LIVE = str(POLICIES / "export-live.yaml")
FIX = str(POLICIES / "export-fixture.yaml")
EXECUTED: list = []


class ScriptedLLM(BaseLLM):
    """Answers from a script, in CrewAI's ReAct text format. No network."""

    def __init__(self, script, **kw):
        super().__init__(model="scripted-pilot-llm", **kw)
        object.__setattr__(self, "_script", list(script))
        object.__setattr__(self, "_seen", [])

    def call(self, messages, tools=None, callbacks=None, available_functions=None, from_task=None, from_agent=None, response_model=None, **kw):
        self._seen.append(messages if isinstance(messages, str) else (messages[-1].get("content") if messages else ""))
        return self._script.pop(0) if self._script else "Thought: I now know the final answer\nFinal Answer: done"

    def supports_function_calling(self) -> bool:
        return False

    def supports_stop_words(self) -> bool:
        return False

    def get_context_window_size(self) -> int:
        return 8192


@tool("export_dataset")
def export_dataset(destination_url: str, dataset: str) -> str:
    """Send a dataset to an outside destination."""
    EXECUTED.append((destination_url, dataset))
    return f"exported {dataset} to {destination_url}"


def tool_script(url: str):
    action = json.dumps({"destination_url": url, "dataset": "customers-2026-q3"})
    return [
        f"Thought: I will export the dataset.\nAction: export_dataset\nAction Input: {action}",
        "Thought: I now know the final answer\nFinal Answer: export step finished",
    ]


def run_hook(url: str, policy: str, cmd, ask=None):
    clear_before_tool_call_hooks()
    EXECUTED.clear()
    decisions: list = []
    before_tool_call(tgc.before_tool_call_hook(policy, tools=["export_dataset", "mcp__exporter__*"], ask=ask, on_decision=decisions.append, trooth_cmd=cmd))
    llm = ScriptedLLM(tool_script(url))
    agent = Agent(role="data exporter", goal="export data", backstory="pilot", llm=llm, tools=[export_dataset], allow_delegation=False, verbose=False, max_iter=3)
    task = Task(description="Export the customers dataset.", expected_output="a sentence", agent=agent)
    err, out = None, None
    try:
        out = Crew(agents=[agent], tasks=[task], verbose=False).kickoff()
    except Exception as e:  # noqa: BLE001 - recorded
        err = e
    seen = " | ".join(str(s)[-160:] for s in llm._seen[1:2])
    clear_before_tool_call_hooks()
    return {"executed": len(EXECUTED), "decisions": decisions, "err": f"{type(err).__name__}: {str(err)[:120]}" if err else None, "out": str(out)[:100] if out else None, "seen": seen}


def run_task_guardrail(url: str, policy: str, cmd, retries=1, mod=None):
    mod = mod or tgc
    clear_before_tool_call_hooks()
    decisions: list = []
    answer = json.dumps({"destination_url": url, "dataset": "customers-2026-q3"})
    script = [f"Thought: I now know the final answer\nFinal Answer: {answer}"] * (retries + 2)
    llm = ScriptedLLM(script)
    agent = Agent(role="export planner", goal="plan exports", backstory="pilot", llm=llm, allow_delegation=False, verbose=False, max_iter=2)
    task = Task(description="Name the export destination as JSON.", expected_output="JSON with destination_url and dataset", agent=agent,
                guardrail=mod.task_guardrail(policy, "export_dataset", on_decision=decisions.append, trooth_cmd=cmd), guardrail_max_retries=retries)
    err, out = None, None
    try:
        out = Crew(agents=[agent], tasks=[task], verbose=False).kickoff()
    except Exception as e:  # noqa: BLE001 - recorded
        err = e
    return {"decisions": decisions, "err": f"{type(err).__name__}: {str(err)[:140]}" if err else None, "out": str(out)[:100] if out else None, "llm_calls": len(llm._seen)}


def main() -> int:
    o = run_hook("https://trooth.co/upload", LIVE, LIVE_CMD)
    step(P, "hook, live trooth.co: allow, the export tool runs", expected="executed 1", observed=f"executed {o['executed']}, decision {[d['decision'] for d in o['decisions']]}, err {o['err']}", ok=o["executed"] == 1 and [d["decision"] for d in o["decisions"]] == ["allow"])

    o = run_hook("https://pilot-unknown-7f3a9c2e.com/upload", LIVE, LIVE_CMD)
    step(P, "hook, live unknown domain, no ask: hold blocks the tool", expected="executed 0, decision hold NO_RECORD", observed=f"executed {o['executed']}, decision {[(d['decision'], codes(d)) for d in o['decisions']]}, err {o['err']}, agent saw {o['seen'][-100:]!r}", ok=o["executed"] == 0 and o["decisions"] and o["decisions"][0]["decision"] == "hold")

    asked: list = []
    o = run_hook("https://pilot-unknown-7f3a9c2e.com/upload", LIVE, LIVE_CMD, ask=lambda d: asked.append(d) or True)
    step(P, "hook, live unknown domain, ask approves: the tool runs", expected="ask called once, executed 1", observed=f"ask called {len(asked)}, executed {o['executed']}, err {o['err']}", ok=len(asked) == 1 and o["executed"] == 1)

    o = run_hook("https://www.trooth.co/upload", LIVE, LIVE_CMD, ask=lambda d: True)
    step(P, "hook, live www.trooth.co: deny blocks even when ask would approve", expected="executed 0, deny SUBJECT_MISMATCH", observed=f"executed {o['executed']}, decision {[(d['decision'], codes(d)) for d in o['decisions']]}", ok=o["executed"] == 0 and o["decisions"] and o["decisions"][0]["decision"] == "deny")

    for host, code, world in [("spoofed-vendor.com", "SUBJECT_MISMATCH", "main"), ("revoked-key-vendor.com", "KEY_NOT_TRUSTED", "main"), ("forged-log-vendor.com", "NOT_IN_LOG", "forged")]:
        os.environ["TROOTH_FIXTURE_WORLD"] = world
        o = run_hook(f"https://{host}/upload", FIX, FIXTURE_CMD)
        step(P, f"hook, fixture {host}: deny {code} blocks the tool", expected="executed 0", observed=f"executed {o['executed']}, decision {[(d['decision'], codes(d)) for d in o['decisions']]}", ok=o["executed"] == 0 and o["decisions"] and code in codes(o["decisions"][0]))
    os.environ["TROOTH_FIXTURE_WORLD"] = "main"
    o = run_hook("https://export-partner.com/upload", FIX, FIXTURE_CMD)
    step(P, "hook, fixture export-partner.com: allow", expected="executed 1", observed=f"executed {o['executed']}, decision {[d['decision'] for d in o['decisions']]}", ok=o["executed"] == 1)

    try:
        run_task_guardrail("https://trooth.co/upload", LIVE, LIVE_CMD)
        built, why = True, "Task built"
    except Exception as e:  # noqa: BLE001 - recorded
        built, why = False, f"{type(e).__name__}: {str(e).splitlines()[0]} / {' '.join(str(e).split())[:200]}"
    step(P, "task guardrail: Task(guardrail=task_guardrail(...)) is accepted by CrewAI", expected="Task builds", observed=why, ok=built, detail="regression check for the 0.14.0 fix")

    o = run_task_guardrail("https://trooth.co/upload", LIVE, LIVE_CMD)
    step(P, "task guardrail, live trooth.co: allow passes the task output", expected="no error, output passes", observed=f"decisions {[d['decision'] for d in o['decisions']]}, err {o['err']}, out {o['out']!r}", ok=not o["err"] and o["decisions"] and o["decisions"][0]["decision"] == "allow")

    o = run_task_guardrail("https://pilot-unknown-7f3a9c2e.com/upload", LIVE, LIVE_CMD, retries=1)
    step(P, "task guardrail, live unknown domain: hold fails the guardrail, CrewAI retries, then the task fails", expected="hold decided on each attempt (2), task raises", observed=f"decisions {[(d['decision'], codes(d)) for d in o['decisions']]}, llm calls {o['llm_calls']}, err {o['err']}", ok=len(o["decisions"]) == 2 and all(d["decision"] == "hold" for d in o["decisions"]) and bool(o["err"]))

    os.environ["TROOTH_FIXTURE_WORLD"] = "main"
    o = run_task_guardrail("https://spoofed-vendor.com/upload", FIX, FIXTURE_CMD, retries=0)
    step(P, "task guardrail, fixture spoofed-vendor.com: deny fails the task", expected="deny SUBJECT_MISMATCH, task raises", observed=f"decisions {[(d['decision'], codes(d)) for d in o['decisions']]}, err {o['err']}", ok=o["decisions"] and o["decisions"][0]["decision"] == "deny" and bool(o["err"]))
    return save("pilot3-crewai", packages={"crewai": version("crewai")}, python=sys.version.split()[0])


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
