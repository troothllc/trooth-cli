"""Shared harness for the Trooth-run guard pilots (Python).

The trooth_guard package is imported from this repository's sdk/python
(PYTHONPATH=sdk/python). It runs `trooth guard decide --json` in a subprocess;
the command is this repository's bin/trooth.mjs (live API) or
bin-trooth-fixture.sh (the local fixture server). Every decide() call made by an adapter is timed here by
wrapping the module-level `decide` the adapter imported.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import time
from typing import Any, Dict, List

PILOTS = pathlib.Path(__file__).resolve().parent.parent
POLICIES = PILOTS / "policies"
LOGS = PILOTS / "logs"
REPO = PILOTS.parent
LIVE_CMD = ["node", str(REPO / "bin" / "trooth.mjs")]
FIXTURE_CMD = [str(PILOTS / "bin-trooth-fixture.sh")]

STEPS: List[Dict[str, Any]] = []
TIMINGS: List[Dict[str, Any]] = []


def instrument(module: Any, source_of=None) -> None:
    """Replace module.decide with a timed wrapper around it."""
    original = module.decide

    def timed(*a: Any, **kw: Any) -> Any:
        t0 = time.perf_counter()
        d = original(*a, **kw)
        ms = (time.perf_counter() - t0) * 1000
        cmd = kw.get("trooth_cmd")
        source = "fixture" if cmd == FIXTURE_CMD else "live"
        if d is not None:
            TIMINGS.append({"source": source, "kind": "cli-subprocess", "ms": round(ms, 1), "decision": d.get("decision"), "host": (d.get("action") or {}).get("host"), "codes": [r.get("code") for r in d.get("reasons", [])]})
        return d

    module.decide = timed


def codes(d: Any) -> List[str]:
    if not isinstance(d, dict):
        return []
    return [r.get("code") for r in d.get("reasons", []) if r.get("code") != "RULE_PASSED"]


def step(pilot: str, name: str, *, expected: str, observed: str, ok: bool, detail: str | None = None) -> None:
    STEPS.append({"pilot": pilot, "name": name, "expected": expected, "observed": observed, "pass": bool(ok), "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'}  [{pilot}] {name}: expected {expected}; observed {observed}" + (f" ({detail})" if detail else ""), flush=True)


def save(name: str, **extra: Any) -> int:
    LOGS.mkdir(parents=True, exist_ok=True)
    trooth = json.loads((REPO / "package.json").read_text())["version"]
    out = {"name": name, "ran_at": dt.datetime.now(dt.timezone.utc).isoformat(), "trooth": trooth, "steps": STEPS, "timings": TIMINGS, **extra}
    (LOGS / f"{name}.json").write_text(json.dumps(out, indent=2, default=str))
    failed = sum(1 for s in STEPS if not s["pass"])
    print(f"\n{len(STEPS)} steps, {failed} failed; {len(TIMINGS)} decisions timed. Wrote logs/{name}.json")
    return failed


def version(dist: str) -> str:
    from importlib.metadata import version as v

    try:
        return v(dist)
    except Exception:  # noqa: BLE001
        return "not installed"


os.environ.setdefault("NODE_NO_WARNINGS", "1")
