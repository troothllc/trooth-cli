"""Run `trooth guard decide --json` and read its Decision.

Exit codes of `trooth guard decide` (PHASE34 spec): 0 allow, 20 hold, 21 deny.
Any other exit, a timeout, a missing command, output that is not a Decision,
or a Decision that disagrees with the exit code gives a hold with
SOURCE_UNREACHABLE. Nothing here ever turns a failure into allow.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import shlex
import subprocess
import unicodedata
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

# The trooth release whose CLI has `trooth guard`. TROOTH_CMD or trooth_cmd overrides it.
TROOTH_VERSION = "0.14.0"

EXIT_ALLOW = 0
EXIT_HOLD = 20
EXIT_DENY = 21
_BY_EXIT = {EXIT_ALLOW: "allow", EXIT_HOLD: "hold", EXIT_DENY: "deny"}

Decision = Dict[str, Any]
Command = Union[str, Sequence[str]]


def trooth_command(trooth_cmd: Optional[Command] = None) -> List[str]:
    """The command that runs the trooth CLI: trooth_cmd, else $TROOTH_CMD, else npx trooth@TROOTH_VERSION."""
    cmd: Optional[Command] = trooth_cmd if trooth_cmd is not None else os.environ.get("TROOTH_CMD") or None
    if cmd is None:
        return ["npx", "--yes", f"trooth@{TROOTH_VERSION}"]
    if isinstance(cmd, str):
        parts = shlex.split(cmd)
    else:
        parts = [str(x) for x in cmd]
    if not parts:
        raise ValueError("the trooth command is empty")
    return parts


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def fail_closed(tool: Optional[str], host: Optional[str], detail: str) -> Decision:
    """A hold Decision with SOURCE_UNREACHABLE, made locally when no Decision could be read."""
    return {
        "decision": "hold",
        "reasons": [{"code": "SOURCE_UNREACHABLE", "detail": f"the guard gave no decision: {str(detail)[:300]}"}],
        "subject": host or "",
        "policy": {"id": None, "version": None, "sha256": None},
        "evidence": [],
        "action": {"tool": tool, "host": host},
        "decided_at": _now(),
    }


def reason_codes(decision: Mapping[str, Any]) -> List[str]:
    """The reason codes of a Decision, in order."""
    reasons = decision.get("reasons") if isinstance(decision, Mapping) else None
    if not isinstance(reasons, list):
        return []
    return [r["code"] for r in reasons if isinstance(r, Mapping) and isinstance(r.get("code"), str)]


def describe(decision: Mapping[str, Any]) -> str:
    """One plain sentence for a Decision, for a log line, an error or the model."""
    d = decision.get("decision", "hold") if isinstance(decision, Mapping) else "hold"
    action = decision.get("action") if isinstance(decision, Mapping) and isinstance(decision.get("action"), Mapping) else {}
    tool = action.get("tool")
    host = action.get("host") or (decision.get("subject") if isinstance(decision.get("subject"), str) and decision.get("subject") else None)
    what = " ".join(x for x in [f"the call to {tool}" if tool else "this action", f"for {host}" if host else ""] if x)
    pol = decision.get("policy") if isinstance(decision.get("policy"), Mapping) else {}
    under = f" under policy {pol['id']}" + (f" version {pol['version']}" if pol.get("version") is not None else "") if pol.get("id") else ""
    codes = reason_codes(decision)
    why = f" Reasons: {', '.join(codes)}." if codes else ""
    if d == "allow":
        return f"Trooth guard: allow {what}{under}.{why}"
    if d == "deny":
        return f"Trooth guard: deny {what}{under}. The call was stopped.{why}"
    return f"Trooth guard: hold {what}{under}. A person must approve it before it runs.{why}"


class GuardError(Exception):
    """A hold or deny, carrying the Decision."""

    def __init__(self, decision: Decision, message: Optional[str] = None):
        super().__init__(message or describe(decision))
        self.decision = decision
        self.reasons = reason_codes(decision)


class GuardHold(GuardError):
    """The policy needs a person to approve the action before it runs."""

    code = "TROOTH_GUARD_HOLD"


class GuardDeny(GuardError):
    """The policy stops the action."""

    code = "TROOTH_GUARD_DENY"


def error_for(decision: Decision) -> Optional[GuardError]:
    """GuardDeny for deny, None for allow, GuardHold for anything else."""
    d = decision.get("decision") if isinstance(decision, Mapping) else None
    if d == "allow":
        return None
    if d == "deny":
        return GuardDeny(decision)
    return GuardHold(decision)


def is_approval(resume: Any) -> bool:
    """Whether a resume value approves a held action: True, "approve", {"type": "approve"},
    {"approved": True}, or {"decisions": [...]} when every decision has type "approve"."""
    if resume is True or resume == "approve":
        return True
    if not isinstance(resume, Mapping):
        return False
    if resume.get("type") == "approve" or resume.get("approved") is True:
        return True
    ds = resume.get("decisions")
    if isinstance(ds, list) and ds:
        return all(isinstance(x, Mapping) and x.get("type") == "approve" for x in ds)
    return False


def decide(
    policy_path: Union[str, "os.PathLike[str]"],
    tool: str,
    host: Optional[str] = None,
    args: Any = None,
    *,
    cache: Optional[Union[str, "os.PathLike[str]"]] = None,
    offline: bool = False,
    trooth_cmd: Optional[Command] = None,
    timeout: float = 120.0,
) -> Optional[Decision]:
    """Run `trooth guard decide --policy <p> --tool <t> [--host h] [--args json] --json` and return the Decision.

    None when the policy does not cover the tool (the CLI exits 0 and says
    covered: false); the caller lets such a call run unchecked, as the policy
    intends. allow only when the CLI exits 0 and prints an allow Decision. The arguments
    are passed on the command line to a local process; they are not sent
    anywhere by this function.
    """
    try:
        cmd = trooth_command(trooth_cmd) + ["guard", "decide", "--policy", os.fspath(policy_path), "--tool", str(tool)]
        if host:
            cmd += ["--host", str(host)]
        if args is not None:
            cmd += ["--args", json.dumps(args, separators=(",", ":"), default=str)]
        if offline:
            cmd.append("--offline")
        if cache is not None:
            cmd += ["--cache", os.fspath(cache)]
        cmd.append("--json")
    except Exception as e:  # noqa: BLE001 - any failure here is a hold
        return fail_closed(tool, host, f"could not build the command: {e}")
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError:
        return fail_closed(tool, host, f"the trooth command was not found: {cmd[0]}")
    except subprocess.TimeoutExpired:
        return fail_closed(tool, host, f"the trooth command did not finish within {timeout} seconds")
    except OSError as e:
        return fail_closed(tool, host, f"the trooth command could not run: {e}")
    expected = _BY_EXIT.get(p.returncode)
    if expected is None:
        err = (p.stderr or "").strip().splitlines()
        return fail_closed(tool, host, f"trooth guard decide exited {p.returncode}" + (f": {err[-1][:200]}" if err else ""))
    try:
        d = json.loads(p.stdout)
    except ValueError:
        return fail_closed(tool, host, "the output was not JSON")
    if p.returncode == 0 and isinstance(d, dict) and d.get("covered") is False and "decision" not in d:
        return None  # the policy does not cover this tool; nothing was decided
    if not isinstance(d, dict) or d.get("decision") not in ("allow", "hold", "deny") or not isinstance(d.get("reasons"), list):
        return fail_closed(tool, host, "the output was not a Decision")
    if d["decision"] != expected:
        return fail_closed(tool, host, f"the exit code says {expected} and the Decision says {d['decision']}")
    return d


def covered(tool: Optional[str], tools: Optional[Sequence[str]]) -> bool:
    """Whether a tool name matches one of the globs (* matches any characters); every tool when tools is None.

    The adapters ask the CLI only about covered tools. Give them the policy's
    applies_to.tools so a tool the policy does not cover is not held.
    """
    if tools is None:
        return True
    if tool is None:
        return False
    globs = list(tools)
    if not globs:
        return False
    name = str(tool)
    # The same rule as the CLI's toolCovered (bin/lib/guard-policy.mjs): "*" is the
    # only wildcard; a name also matches once case and Unicode compatibility forms
    # are folded; and a name that is not plain printable ASCII is covered whenever
    # tools are listed, so a look-alike letter cannot slip past.
    if any(_glob_re(g).match(name) for g in globs):
        return True
    if any(_glob_re(_fold(g)).match(_fold(name)) for g in globs):
        return True
    return not _PRINTABLE.match(name)


_PRINTABLE = re.compile(r"[\x21-\x7e]+\Z")


def _fold(s: str) -> str:
    return unicodedata.normalize("NFKC", s).lower()


def _glob_re(glob: str) -> "re.Pattern[str]":
    return re.compile("".join(".*" if part == "*" else re.escape(part) for part in re.split(r"(\*)", glob)) + r"\Z", re.DOTALL)


def decide_tool_call(policy_path: Union[str, "os.PathLike[str]"], tool: str, args: Any = None, **kw: Any) -> Optional[Decision]:
    """decide() for a tool call: the CLI finds the host in the typed arguments (the policy's host_from)."""
    return decide(policy_path, tool, None, args, **kw)
