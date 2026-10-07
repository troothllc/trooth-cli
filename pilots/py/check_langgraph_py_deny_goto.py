"""Trooth-run check (Python langgraph): routing with deny_goto. Since trooth
0.14.0, deny_goto without tools_goto is refused (a static edge trooth_guard ->
tools would also run after a routed deny); with tools_goto and no static edge,
a deny routes and the tool does not run. Fixture server, scripted AI message."""
import os, sys
from typing import Annotated, TypedDict
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.tools import tool
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from langgraph.types import Command, interrupt
import trooth_guard.langgraph as tgl
from common import FIXTURE_CMD, POLICIES, instrument, save, step, version
instrument(tgl)
FIX = str(POLICIES / "procurement-fixture.yaml")
P = "procurement-langgraph-py"

class S(TypedDict):
    messages: Annotated[list, add_messages]

def run(host):
    executed, routed = [], []
    @tool
    def create_purchase_order(vendor_url: str, amount: int) -> str:
        """Place a purchase order."""
        executed.append(vendor_url); return "ok"
    def model(s):
        if any(getattr(m, "type", "") == "tool" for m in s["messages"]):
            return {"messages": [AIMessage("done")]}
        return {"messages": [AIMessage("", tool_calls=[{"name": "create_purchase_order", "args": {"vendor_url": f"https://{host}/orders", "amount": 5}, "id": "call_1"}])]}
    b = StateGraph(S)
    b.add_node("model", model)
    b.add_node("trooth_guard", tgl.guard_node(FIX, interrupt=interrupt, command=Command, deny_goto="denied", tools_goto="tools", trooth_cmd=FIXTURE_CMD), destinations=("tools", "denied"))
    b.add_node("tools", ToolNode([create_purchase_order]))
    b.add_node("denied", lambda s: routed.append(1) or {})
    b.add_edge(START, "model")
    b.add_conditional_edges("model", lambda s: "trooth_guard" if s["messages"][-1].tool_calls else END, ["trooth_guard", END])
    b.add_edge("tools", "model"); b.add_edge("denied", END)
    g = b.compile(checkpointer=MemorySaver())
    g.invoke({"messages": [HumanMessage("order")]}, {"configurable": {"thread_id": host}})
    return len(executed), len(routed)

os.environ["TROOTH_FIXTURE_WORLD"] = "main"
try:
    tgl.guard_node(FIX, interrupt=interrupt, command=Command, deny_goto="denied", trooth_cmd=FIXTURE_CMD)
    refused = "built"
except TypeError as e:
    refused = f"TypeError: {e}"
step(P, "deny_goto without tools_goto is refused", expected="TypeError", observed=refused, ok=refused.startswith("TypeError"))
e, r = run("spoofed-vendor.com")
step(P, "tools_goto, no static edge: deny SUBJECT_MISMATCH routes to denied, the tool does not run", expected="routed 1, executed 0", observed=f"routed {r}, executed {e}", ok=(r == 1 and e == 0))
e, r = run("acme-payments.com")
step(P, "tools_goto, no static edge: allow routes to tools", expected="executed 1, routed 0", observed=f"routed {r}, executed {e}", ok=(r == 0 and e == 1))
sys.exit(1 if save("check-langgraph-py", packages={"langgraph": version("langgraph"), "langchain-core": version("langchain-core")}, python=sys.version.split()[0]) else 0)
