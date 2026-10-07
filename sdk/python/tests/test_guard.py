"""trooth_guard against a fake `trooth guard decide` (fake_trooth.py): no network, no npm,
no framework package. Framework pieces (interrupt, ToolMessage, Command, contexts) are
small fakes in the shapes the frameworks document."""

import asyncio
import json
import os
import pathlib
import sys
import tempfile
import unittest
from types import SimpleNamespace

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from trooth_guard import (  # noqa: E402
    TROOTH_VERSION,
    GuardDeny,
    GuardError,
    GuardHold,
    covered,
    decide,
    decide_tool_call,
    describe,
    error_for,
    fail_closed,
    is_approval,
    trooth_command,
)
from trooth_guard import crewai as tg_crewai  # noqa: E402
from trooth_guard import langchain as tg_langchain  # noqa: E402
from trooth_guard import langgraph as tg_langgraph  # noqa: E402
from trooth_guard import openai_agents as tg_openai  # noqa: E402

FAKE = [sys.executable, str(HERE / "fake_trooth.py")]
KW = {"trooth_cmd": FAKE}
POLICY = "policy.yaml"  # the fake never opens it


class FakeToolMessage:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class FakeCommand:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class Core(unittest.TestCase):
    def test_exit_codes_map_to_decisions(self):
        self.assertEqual(decide(POLICY, "pay.out", "good.example", **KW)["decision"], "allow")
        self.assertEqual(decide(POLICY, "pay.out", "unknown.example", **KW)["decision"], "hold")
        d = decide(POLICY, "pay.out", "bad.example", **KW)
        self.assertEqual(d["decision"], "deny")
        self.assertEqual(d["reasons"][0]["code"], "SIGNATURE_INVALID")

    def test_uncovered_tool_decides_nothing(self):
        self.assertIsNone(decide(POLICY, "uncovered.tool", "bad.example", **KW))
        ok, out = tg_crewai.task_guardrail(POLICY, "uncovered.tool", extract=lambda o: {"host": "bad.example"}, **KW)("x")
        self.assertTrue(ok)
        self.assertEqual(out, "x")

    def test_failures_hold_never_allow(self):
        for host, why in [("crash.example", "exited 3"), ("garbage.example", "not JSON"), ("mismatch.example", "exit code says hold")]:
            with self.subTest(host):
                d = decide(POLICY, "pay.out", host, **KW)
                self.assertEqual(d["decision"], "hold")
                self.assertEqual(d["reasons"][0]["code"], "SOURCE_UNREACHABLE")
                self.assertIn(why, d["reasons"][0]["detail"])
        d = decide(POLICY, "pay.out", "slow.example", timeout=0.5, **KW)
        self.assertEqual((d["decision"], d["reasons"][0]["code"]), ("hold", "SOURCE_UNREACHABLE"))
        d = decide(POLICY, "pay.out", "good.example", trooth_cmd=["/nonexistent/trooth-cli-for-test"])
        self.assertEqual((d["decision"], d["reasons"][0]["code"]), ("hold", "SOURCE_UNREACHABLE"))
        self.assertIn("not found", d["reasons"][0]["detail"])
        d = decide(POLICY, "pay.out", "good.example", trooth_cmd=[sys.executable, "-c", "import sys; print('{\"decision\": \"allow\"}'); sys.exit(0)"])
        self.assertEqual(d["decision"], "hold", "an allow without reasons is not a Decision")

    def test_command_line(self):
        with tempfile.TemporaryDirectory() as t:
            log = os.path.join(t, "argv.jsonl")
            os.environ["FAKE_TROOTH_LOG"] = log
            try:
                decide(POLICY, "pay.out", "good.example", {"amount": 5}, cache=t, offline=True, **KW)
                decide_tool_call(POLICY, "send_email", {"to": "ap@good.example"}, **KW)
            finally:
                del os.environ["FAKE_TROOTH_LOG"]
            a, b = [json.loads(x) for x in pathlib.Path(log).read_text().splitlines()]
        self.assertEqual(a, ["guard", "decide", "--policy", POLICY, "--tool", "pay.out", "--host", "good.example", "--args", '{"amount":5}', "--offline", "--cache", t, "--json"])
        self.assertEqual(b, ["guard", "decide", "--policy", POLICY, "--tool", "send_email", "--args", '{"to":"ap@good.example"}', "--json"])

    def test_trooth_command(self):
        old = os.environ.pop("TROOTH_CMD", None)
        try:
            self.assertEqual(trooth_command(), ["npx", "--yes", f"trooth@{TROOTH_VERSION}"])
            os.environ["TROOTH_CMD"] = "node /opt/trooth/bin/trooth.mjs"
            self.assertEqual(trooth_command(), ["node", "/opt/trooth/bin/trooth.mjs"])
            self.assertEqual(trooth_command(["x", "y"]), ["x", "y"], "the argument wins over the environment")
            self.assertEqual(decide(POLICY, "pay.out", "good.example", trooth_cmd=" ".join(FAKE))["decision"], "allow")
            with self.assertRaises(ValueError):
                trooth_command("")
        finally:
            os.environ.pop("TROOTH_CMD", None)
            if old is not None:
                os.environ["TROOTH_CMD"] = old

    def test_errors_and_helpers(self):
        h = error_for(decide(POLICY, "pay.out", "unknown.example", **KW))
        self.assertIsInstance(h, GuardHold)
        self.assertIsInstance(h, GuardError)
        self.assertEqual(h.reasons, ["EVIDENCE_MISSING"])
        self.assertIsInstance(error_for(decide(POLICY, "pay.out", "bad.example", **KW)), GuardDeny)
        self.assertIsNone(error_for(decide(POLICY, "pay.out", "good.example", **KW)))
        self.assertIsInstance(error_for({}), GuardHold)
        m = describe(decide(POLICY, "pay.out", "unknown.example", **KW))
        self.assertTrue(m.startswith("Trooth guard: hold the call to pay.out for unknown.example under policy vendor-payments version 3."), m)
        for v in ("allow", "hold", "deny"):
            s = describe({"decision": v, "reasons": [], "action": {"tool": "t", "host": "h.example"}})
            for bad in ("safe", "verified", "trusted", "score", "!", "n't"):
                self.assertNotIn(bad, s.lower())
        f = fail_closed("t", None, "x")
        self.assertEqual((f["decision"], f["subject"]), ("hold", ""))
        for yes in (True, "approve", {"type": "approve"}, {"approved": True}, {"decisions": [{"type": "approve"}]}):
            self.assertTrue(is_approval(yes), yes)
        for no in (None, False, "yes", {"type": "reject"}, {"decisions": []}, {"decisions": [{"type": "approve"}, {"type": "edit"}]}):
            self.assertFalse(is_approval(no), no)
        self.assertTrue(covered("pay.out", None))
        self.assertTrue(covered("mcp__bank__send", ["pay.*", "mcp__bank__*"]))
        self.assertFalse(covered("search", ["pay.*"]))
        self.assertFalse(covered(None, ["*"]))

    def test_covered_matches_the_cli_rule(self):
        # The CLI covers these (bin/lib/guard-policy.mjs toolCovered); with tools= given,
        # an adapter that said "not covered" would run the call without asking.
        tools = ["stripe.create_payout", "mcp__bank__*"]
        for name in ("Stripe.create_payout", "STRIPE.CREATE_PAYOUT", "ｓtripe.create_payout", "stripe.create_payout ", "mcp__BANK__pay", "mcp__bank__x\n"):
            self.assertTrue(covered(name, tools), repr(name))
        self.assertFalse(covered("stripe.list_payouts", tools))
        self.assertFalse(covered("mcp__bank", tools))
        self.assertTrue(covered("a[b]", ["a[b]"]), "only * is a wildcard; [ ] are literal")
        self.assertFalse(covered("a.b", ["a?b"]), "? is literal, as in the CLI")
        hook = tg_crewai.before_tool_call_hook(POLICY, tools=["pay.*"], **KW)
        self.assertIs(hook(SimpleNamespace(tool_name="PAY.out", tool_input={"url": "bad.example"})), False)


class CrewAI(unittest.TestCase):
    def test_task_guardrail(self):
        g = tg_crewai.task_guardrail(POLICY, "pay.out", **KW)
        out = SimpleNamespace(raw=json.dumps({"url": "https://good.example/pay"}), json_dict=None, pydantic=None)
        self.assertEqual(g(out), (True, out))
        ok, msg = g(SimpleNamespace(raw='{"url": "https://bad.example/x"}', json_dict=None, pydantic=None))
        self.assertFalse(ok)
        self.assertIn("deny", msg)
        ok, msg = g(SimpleNamespace(raw="", json_dict={"url": "unknown.example"}, pydantic=None))
        self.assertFalse(ok)
        self.assertIn("A person must approve it", msg)
        asked = []
        approve = tg_crewai.task_guardrail(POLICY, "pay.out", ask=lambda d: asked.append(d) or True, **KW)
        self.assertTrue(approve(SimpleNamespace(raw='{"url": "unknown.example"}', json_dict=None, pydantic=None))[0])
        self.assertTrue(approve(SimpleNamespace(raw='{"url": "bad.example"}', json_dict=None, pydantic=None))[0] is False, "a person cannot approve a deny")
        self.assertEqual(len(asked), 1)
        skip = tg_crewai.task_guardrail(POLICY, "pay.out", extract=lambda o: None, **KW)
        self.assertEqual(skip("x"), (True, "x"))
        broken = tg_crewai.task_guardrail(POLICY, "pay.out", extract=lambda o: 1 / 0, **KW)
        self.assertFalse(broken("x")[0])

    def test_before_tool_call_hook(self):
        seen = []
        hook = tg_crewai.before_tool_call_hook(POLICY, tools=["pay.*"], on_decision=lambda d: seen.append(d["decision"]), **KW)
        ctx = lambda name, inp: SimpleNamespace(tool_name=name, tool_input=inp)  # noqa: E731
        self.assertIsNone(hook(ctx("pay.out", {"url": "good.example"})))
        self.assertIs(hook(ctx("pay.out", {"url": "bad.example"})), False)
        self.assertIs(hook(ctx("pay.out", {"url": "unknown.example"})), False)
        self.assertIs(hook(ctx("pay.out", {"url": "crash.example"})), False)
        self.assertIsNone(hook(ctx("search", {"q": "x"})), "an uncovered tool runs without asking")
        self.assertEqual(seen, ["allow", "deny", "hold", "hold"])
        ask = tg_crewai.before_tool_call_hook(POLICY, ask=lambda d: True, **KW)
        self.assertIsNone(ask(ctx("pay.out", {"url": "unknown.example"})))
        self.assertIs(ask(ctx("pay.out", {"url": "bad.example"})), False)


class LangGraph(unittest.TestCase):
    def state(self, *calls):
        return {"messages": [{"type": "human"}, SimpleNamespace(tool_calls=list(calls))]}

    def test_allow_and_skip(self):
        node = tg_langgraph.guard_node(POLICY, interrupt=lambda p: self.fail("no interrupt"), tools=["pay.*"], **KW)
        self.assertEqual(node(self.state({"name": "pay.out", "args": {"url": "good.example"}, "id": "a"}, {"name": "search", "args": {}, "id": "b"})), {})
        self.assertEqual(node({"messages": []}), {})
        keyed = tg_langgraph.guard_node(POLICY, interrupt=lambda p: None, decisions_key="trooth", **KW)
        u = keyed(self.state({"name": "pay.out", "args": {"url": "good.example"}, "id": "a"}))
        self.assertEqual(u["trooth"][0]["decision"]["decision"], "allow")
        with self.assertRaises(TypeError):
            tg_langgraph.guard_node(POLICY, interrupt=lambda p: None, deny_goto="x")

    def test_hold_interrupts_once(self):
        payloads = []
        s = self.state({"name": "pay.out", "args": {"url": "unknown.example"}, "id": "a"}, {"name": "send_email", "args": {"to": "x@unknown.example"}, "id": "b"}, {"name": "pay.out", "args": {"url": "good.example"}, "id": "c"})
        node = lambda resume, **kw: tg_langgraph.guard_node(POLICY, interrupt=lambda p: payloads.append(p) or resume, **kw, **KW)  # noqa: E731
        self.assertEqual(node({"type": "approve"})(s), {})
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["type"], "trooth_guard_hold")
        self.assertEqual([x["tool_call"]["id"] for x in payloads[0]["held"]], ["a", "b"])
        with self.assertRaises(GuardHold):
            node({"type": "reject"})(s)
        c = node(False, command=FakeCommand, hold_goto="review")(s)
        self.assertEqual(c.goto, "review")

    def test_deny_before_interrupt(self):
        s = self.state({"name": "pay.out", "args": {"url": "unknown.example"}, "id": "a"}, {"name": "pay.out", "args": {"url": "bad.example"}, "id": "b"})
        asked = []
        with self.assertRaises(GuardDeny):
            tg_langgraph.guard_node(POLICY, interrupt=lambda p: asked.append(p), **KW)(s)
        c = tg_langgraph.guard_node(POLICY, interrupt=lambda p: asked.append(p), command=FakeCommand, deny_goto="blocked", decisions_key="d", **KW)(s)
        self.assertEqual((c.goto, len(c.update["d"])), ("blocked", 2))
        self.assertEqual(asked, [])


class LangChain(unittest.TestCase):
    def req(self, name, args, id_="tc1"):
        return SimpleNamespace(tool_call={"name": name, "args": args, "id": id_}, tool=None, state={}, runtime=None)

    def test_allow_deny_hold(self):
        ran = []
        handler = lambda r: ran.append(r.tool_call["name"]) or "ran"  # noqa: E731
        w = tg_langchain.tool_call_wrapper(POLICY, tools=["pay.*"], **KW)
        self.assertEqual(w(self.req("pay.out", {"url": "good.example"}), handler), "ran")
        self.assertEqual(w(self.req("search", {}), handler), "ran")
        with self.assertRaises(GuardDeny):
            w(self.req("pay.out", {"url": "bad.example"}), handler)
        with self.assertRaises(GuardHold):
            w(self.req("pay.out", {"url": "unknown.example"}), handler)
        m = tg_langchain.tool_call_wrapper(POLICY, tool_message=FakeToolMessage, on_deny="message", **KW)
        msg = m(self.req("pay.out", {"url": "bad.example"}, "id9"), handler)
        self.assertEqual((msg.status, msg.tool_call_id, msg.name), ("error", "id9", "pay.out"))
        self.assertIn("SIGNATURE_INVALID", msg.content)
        msg = m(self.req("pay.out", {"url": "unknown.example"}), handler)
        self.assertIn("A person must approve it", msg.content)
        self.assertEqual(ran, ["pay.out", "search"])

    def test_interrupt(self):
        ran = []
        handler = lambda r: ran.append(1) or "ran"  # noqa: E731
        payloads = []
        mk = lambda resume, **kw: tg_langchain.tool_call_wrapper(POLICY, interrupt=lambda p: payloads.append(p) or resume, **kw, **KW)  # noqa: E731
        self.assertEqual(mk({"type": "approve"})(self.req("pay.out", {"url": "unknown.example"}), handler), "ran")
        self.assertEqual(payloads[0]["tool_call"], {"name": "pay.out", "id": "tc1"})
        with self.assertRaises(GuardHold):
            mk({"type": "reject"})(self.req("pay.out", {"url": "unknown.example"}), handler)
        msg = mk(None, tool_message=FakeToolMessage)(self.req("pay.out", {"url": "unknown.example"}), handler)
        self.assertIn("did not approve", msg.content)
        self.assertEqual(ran, [1])

        class Pause(Exception):
            pass

        def pause(_p):
            raise Pause()

        with self.assertRaises(Pause):
            tg_langchain.tool_call_wrapper(POLICY, interrupt=pause, **KW)(self.req("pay.out", {"url": "unknown.example"}), handler)
        for bad in ({"on_hold": "interrupt"}, {"on_deny": "message"}, {"on_hold": "allow"}):
            with self.assertRaises(ValueError):
                tg_langchain.tool_call_wrapper(POLICY, **bad)

    def test_async(self):
        async def handler(r):
            return "ran"

        w = tg_langchain.atool_call_wrapper(POLICY, **KW)
        self.assertEqual(asyncio.run(w(self.req("pay.out", {"url": "good.example"}), handler)), "ran")
        with self.assertRaises(GuardHold):
            asyncio.run(w(self.req("pay.out", {"url": "crash.example"}), handler))


class OpenAIAgents(unittest.TestCase):
    def data(self, name, args, call_id="c1", approved=None):
        ctx = SimpleNamespace(tool_name=name, tool_call_id=call_id, tool_arguments=json.dumps(args), is_tool_approved=lambda t, c: (approved or {}).get((t, c)))
        return SimpleNamespace(context=ctx, agent=None)

    def run_g(self, g, d):
        return asyncio.run(g(d))

    def test_guardrail(self):
        g = tg_openai.tool_input_guardrail_function(POLICY, tools=["pay.*"], output_factory=tg_openai._Output, **KW)
        self.assertEqual(self.run_g(g, self.data("pay.out", {"url": "good.example"})).behavior, {"type": "allow"})
        self.assertEqual(self.run_g(g, self.data("pay.out", {"url": "bad.example"})).behavior, {"type": "raise_exception"})
        r = self.run_g(g, self.data("pay.out", {"url": "unknown.example"}))
        self.assertEqual(r.behavior["type"], "reject_content")
        self.assertIn("A person must approve it", r.behavior["message"])
        self.assertEqual(r.output_info["decision"]["decision"], "hold")
        u = self.run_g(g, self.data("search", {"q": 1}))
        self.assertEqual((u.behavior, u.output_info), ({"type": "allow"}, {"covered": False}))
        f = self.run_g(g, self.data("pay.out", {"url": "crash.example"}))
        self.assertEqual(f.behavior["type"], "reject_content")
        raise_on_hold = tg_openai.tool_input_guardrail_function(POLICY, on_hold="raise", output_factory=tg_openai._Output, **KW)
        self.assertEqual(self.run_g(raise_on_hold, self.data("pay.out", {"url": "unknown.example"})).behavior, {"type": "raise_exception"})
        with self.assertRaises(ValueError):
            tg_openai.tool_input_guardrail_function(POLICY, on_hold="allow")

    def test_approved_hold_runs_but_approved_deny_does_not(self):
        g = tg_openai.tool_input_guardrail_function(POLICY, output_factory=tg_openai._Output, **KW)
        ok = {("pay.out", "c9"): True}
        r = self.run_g(g, self.data("pay.out", {"url": "unknown.example"}, "c9", ok))
        self.assertEqual(r.behavior, {"type": "allow"})
        self.assertTrue(r.output_info["approved_by_person"])
        self.assertEqual(self.run_g(g, self.data("pay.out", {"url": "unknown.example"}, "c8", ok)).behavior["type"], "reject_content")
        self.assertEqual(self.run_g(g, self.data("pay.out", {"url": "bad.example"}, "c9", ok)).behavior, {"type": "raise_exception"})

    def test_needs_approval(self):
        na = tg_openai.needs_approval(POLICY, "pay.out", **KW)
        self.assertTrue(asyncio.run(na(None, {"url": "unknown.example"}, "c1")))
        self.assertFalse(asyncio.run(na(None, {"url": "good.example"}, "c2")))
        self.assertFalse(asyncio.run(na(None, {"url": "bad.example"}, "c3")))
        self.assertTrue(asyncio.run(na(None, {"url": "crash.example"}, "c4")))

    def test_duck_output_matches_sdk_names(self):
        self.assertEqual(tg_openai._Output.allow().behavior, {"type": "allow"})
        self.assertEqual(tg_openai._Output.reject_content("m").behavior, {"type": "reject_content", "message": "m"})
        self.assertEqual(tg_openai._Output.raise_exception({"x": 1}).output_info, {"x": 1})


if __name__ == "__main__":
    unittest.main()
