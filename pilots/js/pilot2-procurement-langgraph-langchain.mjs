// Pilot 2, "Procurement agent" (Trooth-run, test harness): LangGraph JS
// (@langchain/langgraph StateGraph + ToolNode + MemorySaver) with
// trooth/guard/langgraph's guard node, and LangChain JS v1 (createAgent from
// "langchain") with trooth/guard/langchain's middleware. No LLM key: the model
// is LangChain's own FakeToolCallingModel (exported by "langchain"), which
// emits scripted tool calls through the real bindTools/invoke path, so the
// real graph, checkpointer, interrupt and Command({ resume }) machinery runs.
import { z } from 'zod';
import { StateGraph, MessagesAnnotation, MemorySaver, interrupt, Command, START, END, isGraphInterrupt } from '@langchain/langgraph';
import { ToolNode } from '@langchain/langgraph/prebuilt';
import { tool } from '@langchain/core/tools';
import { HumanMessage, ToolMessage, AIMessage } from '@langchain/core/messages';
import { createAgent, createMiddleware, FakeToolCallingModel } from 'langchain';
import { createGuardNode } from '../../bin/lib/guard/langgraph.mjs';
import { troothMiddleware } from '../../bin/lib/guard/langchain.mjs';
import { GuardDeny, GuardHold, guardDecisionOf } from '../../bin/lib/guard/errors.mjs';
import { liveGuard, fixtureGuard, step, codesOf, save, pkgVersion } from './common.mjs';

const PG = 'procurement-langgraph';
const PC = 'procurement-langchain';

function poTool(executed) {
  return tool(async ({ vendor_url, amount }) => { executed.push({ vendor_url, amount }); return `purchase order for ${amount} placed with ${vendor_url}`; }, {
    name: 'create_purchase_order',
    description: 'Place a purchase order with a vendor.',
    schema: z.object({ vendor_url: z.string(), amount: z.number() }),
  });
}
const callFor = (host, i = 1) => [{ name: 'create_purchase_order', args: { vendor_url: `https://${host}/orders`, amount: 1200 }, id: `call_po_${i}` }];
const interruptsOf = (r) => r?.__interrupt__ ?? [];
let thread = 0;
const cfg = () => ({ configurable: { thread_id: `pilot2-${++thread}` } });

/* ------------------------------------------------------------- LangGraph -- */
function buildGraph(guard, executed, { host, guardOpts = {}, extraNodes = [] } = {}) {
  const model = new FakeToolCallingModel({ toolCalls: [callFor(host), []] });
  const tools = [poTool(executed)];
  const bound = model.bindTools(tools);
  const decisions = [];
  const g = new StateGraph(MessagesAnnotation)
    .addNode('model', async (s) => ({ messages: [await bound.invoke(s.messages)] }))
    .addNode('trooth_guard', createGuardNode(guard, { interrupt, onDecision: (d) => decisions.push(d), ...guardOpts }), guardOpts.denyGoto || guardOpts.holdGoto ? { ends: ['tools', ...[guardOpts.denyGoto, guardOpts.holdGoto].filter(Boolean)] } : undefined)
    .addNode('tools', new ToolNode(tools));
  for (const [name, fn] of extraNodes) g.addNode(name, fn);
  g.addEdge(START, 'model')
    .addConditionalEdges('model', (s) => (s.messages.at(-1).tool_calls?.length ? 'trooth_guard' : END), ['trooth_guard', END])
    .addEdge('tools', 'model');
  // As GUARD-ADAPTERS.md shows: without routing, a static edge from the guard node to
  // the tool node; with routing (denyGoto or holdGoto, which need toolsGoto), no static
  // edge, because the node returns Command({ goto: toolsGoto }) when the calls may run.
  const routing = !!(guardOpts.denyGoto || guardOpts.holdGoto);
  if (!routing) g.addEdge('trooth_guard', 'tools');
  for (const [name] of extraNodes) g.addEdge(name, END);
  return { app: g.compile({ checkpointer: new MemorySaver() }), decisions };
}

async function graphRun(guard, host, { resume, guardOpts, extraNodes } = {}) {
  const executed = [];
  const { app, decisions } = buildGraph(guard, executed, { host, guardOpts, extraNodes });
  const c = cfg();
  let r1, r2, err1, err2;
  try { r1 = await app.invoke({ messages: [new HumanMessage('Order the parts.')] }, c); } catch (e) { err1 = e; }
  const ints = interruptsOf(r1);
  const executedBefore = executed.length;
  if (ints.length && resume !== undefined) {
    try { r2 = await app.invoke(new Command({ resume }), c); } catch (e) { err2 = e; }
  }
  const st = await app.getState(c);
  return { executed, executedBefore, decisions, ints, r1, r2, err1, err2, state: st };
}

const live = await liveGuard('procurement-live.yaml');
const fx = await fixtureGuard('procurement-fixture.yaml');
const fxForged = await fixtureGuard('procurement-fixture.yaml', 'forged');

{
  const o = await graphRun(live, 'trooth.co');
  step(PG, 'live trooth.co: allow, tool node runs, graph ends', { expected: 'executed 1, no interrupt, final AI message', observed: `executed ${o.executed.length}, interrupts ${o.ints.length}, decision ${o.decisions[0]?.decision}, last ${o.r1?.messages?.at(-1)?.constructor?.name}`, pass: o.executed.length === 1 && o.ints.length === 0 && o.decisions[0]?.decision === 'allow' });
}
{
  const o = await graphRun(live, 'pilot-unknown-7f3a9c2e.com', { resume: { type: 'approve' } });
  const v = o.ints[0]?.value;
  step(PG, 'live unknown domain: hold interrupts with MemorySaver, payload carries the Decision', { expected: '1 interrupt of type trooth_guard_hold, executed 0 before resume', observed: `${o.ints.length} interrupt(s), type ${v?.type}, held ${v?.held?.length}, codes ${codesOf(v?.held?.[0]?.decision)}, executed before resume ${o.executedBefore}, next ${JSON.stringify(o.state?.next)}`, pass: o.ints.length === 1 && v?.type === 'trooth_guard_hold' && o.executedBefore === 0 });
  step(PG, 'live unknown domain: Command({ resume: { type: "approve" } }) on the same thread runs the tool', { expected: 'executed 1, guard node decided again on resume (2 decisions)', observed: `executed ${o.executed.length}, decisions ${o.decisions.length}, error ${o.err2?.name ?? null}, last ${o.r2?.messages?.at(-1)?.content}`, pass: o.executed.length === 1 && o.decisions.length === 2 && !o.err2 });
}
{
  const o = await graphRun(live, 'pilot-unknown-7f3a9c2e.com', { resume: { type: 'reject' } });
  step(PG, 'live unknown domain: resume with reject throws GuardHold, tool does not run', { expected: 'GuardHold, executed 0', observed: `${o.err2?.constructor?.name}, executed ${o.executed.length}`, pass: o.err2 instanceof GuardHold && o.executed.length === 0 });
}
{
  const o = await graphRun(live, 'www.trooth.co');
  step(PG, 'live www.trooth.co: deny throws GuardDeny out of invoke, no interrupt', { expected: 'GuardDeny SUBJECT_MISMATCH, executed 0', observed: `${o.err1?.constructor?.name} ${o.err1?.reasons}, interrupts ${o.ints.length}, executed ${o.executed.length}`, pass: o.err1 instanceof GuardDeny && o.err1.reasons.includes('SUBJECT_MISMATCH') && o.executed.length === 0 });
}
{
  // Routing without toolsGoto is refused (since 0.14.0): a static edge to the tool node would run it after a routed deny.
  let err = null;
  try { createGuardNode(fx, { interrupt, Command, denyGoto: 'denied' }); } catch (e) { err = e; }
  step(PG, 'denyGoto without toolsGoto is refused with a TypeError', { expected: 'TypeError', observed: `${err?.constructor?.name}: ${err?.message}`, pass: err instanceof TypeError });
}
for (const [g, host, code] of [[fx, 'spoofed-vendor.com', 'SUBJECT_MISMATCH'], [fx, 'revoked-key-vendor.com', 'KEY_NOT_TRUSTED'], [fxForged, 'forged-log-vendor.com', 'NOT_IN_LOG']]) {
  const routed = [];
  const o = await graphRun(g, host, { guardOpts: { Command, denyGoto: 'denied', toolsGoto: 'tools' }, extraNodes: [['denied', async () => { routed.push(host); return { messages: [new AIMessage('The purchase order was stopped by the policy.')] }; }]] });
  step(PG, `fixture ${host}: deny ${code} routes with Command({ goto: 'denied' }) and the tool does not run`, { expected: 'routed to denied, executed 0', observed: `routed ${routed.length}, error ${o.err1?.message ?? null}, decision ${o.decisions[0]?.decision} ${codesOf(o.decisions[0])}, executed ${o.executed.length}`, pass: routed.length === 1 && o.executed.length === 0 && codesOf(o.decisions[0]).includes(code) });
}
{
  const o = await graphRun(live, 'trooth.co', { guardOpts: { Command, denyGoto: 'denied', toolsGoto: 'tools' }, extraNodes: [['denied', async () => ({})]] });
  step(PG, 'routing node, live trooth.co: allow goes to the tool node with Command({ goto: toolsGoto })', { expected: 'executed 1', observed: `executed ${o.executed.length}, error ${o.err1?.message ?? null}`, pass: o.executed.length === 1 });
  const routed = [];
  const h = await graphRun(live, 'pilot-unknown-7f3a9c2e.com', { resume: { type: 'reject' }, guardOpts: { Command, holdGoto: 'held', toolsGoto: 'tools' }, extraNodes: [['held', async () => { routed.push(1); return {}; }]] });
  step(PG, 'routing node, live unknown domain: resume reject routes to held, the tool does not run', { expected: 'routed 1, executed 0', observed: `routed ${routed.length}, executed ${h.executed.length}, error ${h.err2?.message ?? null}`, pass: routed.length === 1 && h.executed.length === 0 });
  const a = await graphRun(live, 'pilot-unknown-7f3a9c2e.com', { resume: { type: 'approve' }, guardOpts: { Command, holdGoto: 'held', toolsGoto: 'tools' }, extraNodes: [['held', async () => ({})]] });
  step(PG, 'routing node, live unknown domain: resume approve runs the tool once', { expected: 'executed 1', observed: `executed ${a.executed.length}`, pass: a.executed.length === 1 });
}
{
  const o = await graphRun(fx, 'name-match-vendor.com', { resume: true });
  step(PG, 'fixture name-match-vendor.com: hold EVIDENCE_MISSING, resume true runs the tool', { expected: 'interrupt, then executed 1', observed: `interrupts ${o.ints.length}, codes ${codesOf(o.decisions[0])}, executed ${o.executed.length}`, pass: o.ints.length === 1 && o.executed.length === 1 });
}

/* ------------------------------------------------------- LangChain v1 ----- */
async function agentRun(guard, host, { mwOpts = {}, resume, raw = false } = {}) {
  const executed = [];
  const decisions = [];
  const opts = troothMiddleware(guard, { onDecision: (d) => decisions.push(d), ...mwOpts });
  const model = new FakeToolCallingModel({ toolCalls: [callFor(host), []] });
  let agent, buildErr;
  try {
    agent = createAgent({ model, tools: [poTool(executed)], checkpointer: new MemorySaver(), middleware: [raw ? opts : createMiddleware(opts)] });
  } catch (e) { buildErr = e; }
  if (buildErr) return { buildErr, executed, decisions, ints: [] };
  const c = cfg();
  let r1, r2, err1, err2;
  try { r1 = await agent.invoke({ messages: [new HumanMessage('Order the parts.')] }, c); } catch (e) { err1 = e; }
  const ints = interruptsOf(r1);
  const executedBefore = executed.length;
  if (ints.length && resume !== undefined) {
    try { r2 = await agent.invoke(new Command({ resume }), c); } catch (e) { err2 = e; }
  }
  return { executed, executedBefore, decisions, ints, r1, r2, err1, err2 };
}
const toolMsgs = (r) => (r?.messages ?? []).filter((m) => ToolMessage.isInstance ? ToolMessage.isInstance(m) : m instanceof ToolMessage);

{
  const o = await agentRun(live, 'trooth.co', { mwOpts: { interrupt, ToolMessage } });
  step(PC, 'createMiddleware(troothMiddleware(...)) is accepted by createAgent; live trooth.co allow runs the tool', { expected: 'no build error, executed 1', observed: `build ${o.buildErr?.message ?? 'ok'}, executed ${o.executed.length}, decision ${o.decisions[0]?.decision}, error ${o.err1?.message ?? null}`, pass: !o.buildErr && o.executed.length === 1 && o.decisions[0]?.decision === 'allow' });
}
{
  const o = await agentRun(live, 'trooth.co', { mwOpts: { interrupt, ToolMessage }, raw: true });
  step(PC, 'the plain options object passed straight to createAgent middleware (no createMiddleware)', { expected: 'record what happens', observed: `build ${o.buildErr ? `${o.buildErr.constructor.name}: ${o.buildErr.message}` : 'ok'}, executed ${o.executed.length}, decisions ${o.decisions.length}, error ${o.err1?.message ?? null}`, pass: true, detail: 'informational' });
}
{
  const o = await agentRun(live, 'pilot-unknown-7f3a9c2e.com', { mwOpts: { interrupt, ToolMessage }, resume: { type: 'approve' } });
  const v = o.ints[0]?.value;
  step(PC, 'live unknown domain: interrupt() inside wrapToolCall pauses the agent with MemorySaver', { expected: '1 interrupt trooth_guard_hold, executed 0', observed: `${o.ints.length} interrupt(s), type ${v?.type}, codes ${codesOf(v?.decision)}, executed before ${o.executedBefore}, error ${o.err1?.message ?? null}`, pass: o.ints.length === 1 && v?.type === 'trooth_guard_hold' && o.executedBefore === 0 });
  step(PC, 'live unknown domain: Command({ resume: { type: "approve" } }) runs the tool and the agent finishes', { expected: 'executed 1, decided again on resume', observed: `executed ${o.executed.length}, decisions ${o.decisions.length}, error ${o.err2?.message ?? null}, tool message ${JSON.stringify(toolMsgs(o.r2).at(-1)?.content)}`, pass: o.executed.length === 1 && !o.err2 });
}
{
  const o = await agentRun(live, 'pilot-unknown-7f3a9c2e.com', { mwOpts: { interrupt, ToolMessage }, resume: { type: 'reject' } });
  const tm = toolMsgs(o.r2).at(-1);
  step(PC, 'live unknown domain: resume reject answers the model with an error ToolMessage, run continues', { expected: 'executed 0, ToolMessage status error', observed: `executed ${o.executed.length}, status ${tm?.status}, content ${JSON.stringify(tm?.content)?.slice(0, 100)}, error ${o.err2?.message ?? null}`, pass: o.executed.length === 0 && tm?.status === 'error' && !o.err2 });
}
{
  const o = await agentRun(live, 'www.trooth.co', { mwOpts: { interrupt, ToolMessage } });
  step(PC, 'live www.trooth.co: deny stops the run before the tool runs', { expected: 'agent.invoke throws, executed 0', observed: `${o.err1?.constructor?.name} (name ${o.err1?.name}), cause ${o.err1?.cause?.constructor?.name}, executed ${o.executed.length}`, pass: !!o.err1 && o.executed.length === 0 });
  step(PC, 'the error class createAgent rejects with (recorded; GUARD-ADAPTERS.md says langchain may wrap GuardDeny)', { expected: 'record what happens', observed: `${o.err1?.constructor?.name}, instanceof GuardDeny ${o.err1 instanceof GuardDeny}, cause ${o.err1?.cause?.constructor?.name}`, pass: true, detail: 'informational' });
  const d = guardDecisionOf(o.err1);
  step(PC, 'guardDecisionOf(err) finds the Decision whether or not langchain wraps GuardDeny', { expected: 'deny SUBJECT_MISMATCH', observed: `${d?.decision} ${codesOf(d)}`, pass: d?.decision === 'deny' && codesOf(d).includes('SUBJECT_MISMATCH') });
}
for (const [g, host, code] of [[fx, 'spoofed-vendor.com', 'SUBJECT_MISMATCH'], [fx, 'revoked-key-vendor.com', 'KEY_NOT_TRUSTED'], [fxForged, 'forged-log-vendor.com', 'NOT_IN_LOG']]) {
  const o = await agentRun(g, host, { mwOpts: { interrupt, ToolMessage, onDeny: 'message' } });
  const tm = toolMsgs(o.r1).at(-1);
  step(PC, `fixture ${host}: deny ${code} with onDeny 'message' answers with an error ToolMessage`, { expected: 'executed 0, ToolMessage status error naming the code', observed: `executed ${o.executed.length}, status ${tm?.status}, error ${o.err1?.message ?? null}`, pass: o.executed.length === 0 && tm?.status === 'error' && String(tm?.content).includes(code) });
}
{
  const o = await agentRun(fx, 'acme-payments.com', { mwOpts: { interrupt, ToolMessage } });
  step(PC, 'fixture acme-payments.com: allow', { expected: 'executed 1', observed: `executed ${o.executed.length}, decision ${o.decisions[0]?.decision}`, pass: o.executed.length === 1 });
}
{
  const o = await agentRun(live, 'pilot-unknown-7f3a9c2e.com', { mwOpts: { ToolMessage } });
  const tm = toolMsgs(o.r1).at(-1);
  step(PC, 'no interrupt given: hold answers with an error ToolMessage, no checkpoint pause', { expected: 'executed 0, status error', observed: `executed ${o.executed.length}, interrupts ${o.ints.length}, status ${tm?.status}`, pass: o.executed.length === 0 && tm?.status === 'error' && o.ints.length === 0 });
}

void isGraphInterrupt;
process.exitCode = save('pilot2-js', { packages: { '@langchain/langgraph': pkgVersion('@langchain/langgraph'), '@langchain/core': pkgVersion('@langchain/core'), langchain: pkgVersion('langchain'), '@langchain/langgraph-checkpoint': pkgVersion('@langchain/langgraph-checkpoint') } }) ? 1 : 0;
