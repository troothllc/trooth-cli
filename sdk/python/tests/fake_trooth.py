"""A stand-in for `trooth guard decide --json`, for test_guard.py.

It answers from the host (--host, or url / host / to in --args): good.example
allow (exit 0), bad.example deny (21), anything else hold (20). crash.example
exits 3, garbage.example prints text with exit 0, mismatch.example prints an
allow Decision with exit 20, slow.example sleeps. With FAKE_TROOTH_LOG set it
appends its argv as one JSON line to that file.
"""

import json
import os
import sys
import time

argv = sys.argv[1:]
if os.environ.get("FAKE_TROOTH_LOG"):
    with open(os.environ["FAKE_TROOTH_LOG"], "a", encoding="utf-8") as f:
        f.write(json.dumps(argv) + "\n")


def opt(name):
    return argv[argv.index(name) + 1] if name in argv else None


assert argv[:2] == ["guard", "decide"], argv
tool = opt("--tool")
host = opt("--host")
if host is None and opt("--args"):
    a = json.loads(opt("--args"))
    if isinstance(a, dict):
        v = a.get("url") or a.get("host") or a.get("to")
        if isinstance(v, str):
            host = v.split("@")[-1].replace("https://", "").split("/")[0]
if tool == "uncovered.tool":
    print(json.dumps({"covered": False, "tool": tool, "policy": {"id": "p", "version": 1, "sha256": "0" * 64}}))
    sys.exit(0)
if host == "crash.example":
    print("trooth: something broke", file=sys.stderr)
    sys.exit(3)
if host == "garbage.example":
    print("not json")
    sys.exit(0)
if host == "slow.example":
    time.sleep(5)
d = {"good.example": "allow", "bad.example": "deny", "mismatch.example": "allow"}.get(host, "hold")
code = {"allow": 0, "hold": 20, "deny": 21}[d]
if host == "mismatch.example":
    code = 20
reasons = [{"code": "RULE_PASSED", "rule_id": "legal-entity"}] if d == "allow" else [{"code": "SIGNATURE_INVALID"}] if d == "deny" else [{"code": "EVIDENCE_MISSING", "rule_id": "legal-entity", "needed": "legal_entity_registry_record"}]
print(json.dumps({
    "decision": d,
    "reasons": reasons,
    "subject": host or "",
    "policy": {"id": "vendor-payments", "version": 3, "sha256": "a" * 64},
    "evidence": [],
    "action": {"tool": tool, "host": host},
    "decided_at": "2026-10-07T00:00:00.000Z",
}))
sys.exit(code)
