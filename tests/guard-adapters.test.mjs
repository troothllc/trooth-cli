// tests/guard-adapters.test.mjs - the framework adapters of the Trooth guard
// (docs/GUARD-ADAPTERS.md) against a fake guard that implements the Guard
// interface of trooth/guard and answers from a table, and against fake
// framework pieces (interrupt, ToolMessage, Command, RunContext) in the shapes
// the frameworks document. No framework package, no network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GuardHold, GuardDeny, GuardError, errorFor, describeDecision, failClosedDecision, isApproval, guardDecisionOf } from '../bin/lib/guard/errors.mjs';
import { troothToolInputGuardrail, troothNeedsApproval, guardTool, troothAgentInputGuardrail } from '../bin/lib/guard/openai-agents.mjs';
import { troothMiddleware } from '../bin/lib/guard/langchain.mjs';
import { createGuardNode } from '../bin/lib/guard/langgraph.mjs';
import { guardFetch, requestTarget, httpRules, coversRequest } from '../bin/lib/guard/http.mjs';

// ---- a fake guard -----------------------------------------------------------
const POLICY = {
  id: 'vendor-payments', version: 3, sha256: 'a'.repeat(64),
  applies_to: { tools: ['pay.*', 'send_email'], http: [{ method: 'POST', host: '*.example-bank.com' }, { host: 'files.example.org' }] },
};
const decisionFor = (tool, host, d) => ({
  decision: d,
  reasons: d === 'allow' ? [{ code: 'RULE_PASSED' }] : d === 'deny' ? [{ code: 'SIGNATURE_INVALID' }] : [{ code: 'EVIDENCE_MISSING', detail: 'legal-entity' }],
  subject: host ?? '',
  policy: { id: 'vendor-payments', version: 3, sha256: 'a'.repeat(64) },
  evidence: [],
  action: { tool, host },
  decided_at: '2026-10-07T00:00:00.000Z',
});
// host -> decision: good.example allow, unknown.example hold, bad.example deny, boom.example throws, junk.example garbage
function fakeGuard(table = { 'good.example': 'allow', 'unknown.example': 'hold', 'bad.example': 'deny' }) {
  const calls = [];
  const glob = (g, s) => new RegExp(`^${g.split('*').map((x) => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`).test(s);
  const g = {
    policy: POLICY,
    calls,
    applies: (name) => POLICY.applies_to.tools.some((p) => glob(p, name)),
    targetHost: (tc) => {
      const a = tc.arguments;
      if (!a || typeof a !== 'object') return null;
      const v = a.url ?? a.host ?? a.to;
      if (typeof v !== 'string') return null;
      return v.includes('@') ? v.split('@')[1] : v.replace(/^https?:\/\//, '').split('/')[0];
    },
    async decide({ tool, host, args }) {
      calls.push({ tool, host, args });
      if (host === 'boom.example') throw new Error('network down');
      if (host === 'junk.example') return { decision: 'maybe' };
      return decisionFor(tool, host, table[host] ?? 'hold');
    },
    async decideToolCall(tc) {
      if (!g.applies(tc.name)) return null;
      return g.decide({ tool: tc.name, host: g.targetHost(tc), args: tc.arguments });
    },
  };
  return g;
}

// ---- errors ---------------------------------------------------------------
test('errors: GuardHold and GuardDeny carry the Decision and its reason codes', () => {
  const h = errorFor(decisionFor('pay.out', 'unknown.example', 'hold'));
  assert.ok(h instanceof GuardHold && h instanceof GuardError && h instanceof Error);
  assert.equal(h.code, 'TROOTH_GUARD_HOLD');
  assert.deepEqual(h.reasons, ['EVIDENCE_MISSING']);
  assert.equal(h.decision.action.host, 'unknown.example');
  const d = errorFor(decisionFor('pay.out', 'bad.example', 'deny'));
  assert.ok(d instanceof GuardDeny);
  assert.equal(d.code, 'TROOTH_GUARD_DENY');
  assert.equal(errorFor(decisionFor('pay.out', 'good.example', 'allow')), null);
  assert.ok(errorFor({}) instanceof GuardHold, 'something that is not a Decision is a hold');
});

test('errors: messages are plain and never label a company', () => {
  for (const v of ['allow', 'hold', 'deny']) {
    const m = describeDecision(decisionFor('pay.out', 'x.example', v));
    assert.match(m, new RegExp(`^Trooth guard: ${v} the call to pay\\.out for x\\.example under policy vendor-payments version 3\\.`));
    assert.doesNotMatch(m, /safe|unsafe|verified|trusted|score|rating|!|n't|—/i);
  }
});

test('errors: a failure becomes a hold with SOURCE_UNREACHABLE; resume approval forms', () => {
  const f = failClosedDecision(fakeGuard(), { tool: 't', host: 'h.example' }, 'x');
  assert.equal(f.decision, 'hold');
  assert.equal(f.reasons[0].code, 'SOURCE_UNREACHABLE');
  assert.equal(f.policy.id, 'vendor-payments');
  assert.equal(f.subject, 'h.example');
  for (const k of ['decision', 'reasons', 'subject', 'policy', 'evidence', 'decided_at']) assert.ok(k in f, k);
  for (const yes of [true, 'approve', { type: 'approve' }, { approved: true }, { decisions: [{ type: 'approve' }, { type: 'approve' }] }]) assert.equal(isApproval(yes), true, JSON.stringify(yes));
  for (const no of [undefined, null, false, 'yes', 1, { type: 'reject' }, { decisions: [] }, { decisions: [{ type: 'approve' }, { type: 'reject' }] }]) assert.equal(isApproval(no), false, JSON.stringify(no));
});

// ---- OpenAI Agents SDK ----------------------------------------------------
const fnCall = (name, args, callId = 'call_1') => ({ type: 'function_call', name, arguments: JSON.stringify(args), callId });
const ctx = (approved) => ({ isToolApproved: ({ toolName, callId }) => approved?.[`${toolName}/${callId}`] });

test('openai-agents: the tool input guardrail has the shape defineToolInputGuardrail returns', () => {
  const gr = troothToolInputGuardrail(fakeGuard());
  assert.equal(gr.type, 'tool_input');
  assert.equal(gr.name, 'trooth_guard');
  assert.equal(typeof gr.run, 'function');
  assert.throws(() => troothToolInputGuardrail({}), TypeError);
  assert.throws(() => troothToolInputGuardrail(fakeGuard(), { onHold: 'allow' }), TypeError);
});

test('openai-agents: allow -> allow, deny -> throwException, hold -> rejectContent', async () => {
  const gr = troothToolInputGuardrail(fakeGuard());
  const a = await gr.run({ context: ctx(), toolCall: fnCall('pay.out', { url: 'https://good.example/pay' }) });
  assert.deepEqual(a.behavior, { type: 'allow' });
  assert.equal(a.outputInfo.decision.decision, 'allow');
  const d = await gr.run({ context: ctx(), toolCall: fnCall('pay.out', { url: 'https://bad.example/pay' }) });
  assert.deepEqual(d.behavior, { type: 'throwException' });
  assert.equal(d.outputInfo.decision.reasons[0].code, 'SIGNATURE_INVALID');
  const h = await gr.run({ context: ctx(), toolCall: fnCall('pay.out', { url: 'https://unknown.example/pay' }) });
  assert.equal(h.behavior.type, 'rejectContent');
  assert.match(h.behavior.message, /hold the call to pay\.out for unknown\.example .*A person must approve it/);
  const ht = await troothToolInputGuardrail(fakeGuard(), { onHold: 'throw' }).run({ context: ctx(), toolCall: fnCall('pay.out', { url: 'unknown.example' }) });
  assert.deepEqual(ht.behavior, { type: 'throwException' });
});

test('openai-agents: a held call a person approved runs; a denied call a person approved does not', async () => {
  const gr = troothToolInputGuardrail(fakeGuard());
  const approved = { 'pay.out/call_9': true };
  const h = await gr.run({ context: ctx(approved), toolCall: fnCall('pay.out', { url: 'unknown.example' }, 'call_9') });
  assert.deepEqual(h.behavior, { type: 'allow' });
  assert.equal(h.outputInfo.approved_by_person, true);
  const other = await gr.run({ context: ctx(approved), toolCall: fnCall('pay.out', { url: 'unknown.example' }, 'call_8') });
  assert.equal(other.behavior.type, 'rejectContent', 'approval is per call id');
  const d = await gr.run({ context: ctx({ 'pay.out/call_9': true }), toolCall: fnCall('pay.out', { url: 'bad.example' }, 'call_9') });
  assert.deepEqual(d.behavior, { type: 'throwException' });
  const rejected = await gr.run({ context: ctx({ 'pay.out/call_9': false }), toolCall: fnCall('pay.out', { url: 'unknown.example' }, 'call_9') });
  assert.equal(rejected.behavior.type, 'rejectContent');
});

test('openai-agents: an uncovered tool is allowed untouched; failures and garbage never allow', async () => {
  const g = fakeGuard();
  const gr = troothToolInputGuardrail(g);
  const u = await gr.run({ context: ctx(), toolCall: fnCall('search', { q: 'x' }) });
  assert.deepEqual(u, { behavior: { type: 'allow' }, outputInfo: { covered: false } });
  assert.equal(g.calls.length, 0, 'the guard is not asked about a tool its policy does not cover');
  for (const host of ['boom.example', 'junk.example']) {
    const r = await gr.run({ context: ctx(), toolCall: fnCall('pay.out', { url: host }) });
    assert.equal(r.behavior.type, 'rejectContent', host);
    assert.equal(r.outputInfo.decision.reasons[0].code, 'SOURCE_UNREACHABLE');
  }
  const bad = await gr.run({ context: ctx(), toolCall: { name: 'pay.out', arguments: '{not json', callId: 'c' } });
  assert.notDeepEqual(bad.behavior, { type: 'allow' }, 'unparsable arguments: no host, not allowed');
});

test('openai-agents: needsApproval is true only for a hold', async () => {
  const seen = [];
  const na = troothNeedsApproval(fakeGuard(), 'pay.out', { onDecision: (d) => seen.push(d.decision) });
  assert.equal(await na({}, { url: 'unknown.example' }, 'c1'), true);
  assert.equal(await na({}, { url: 'good.example' }, 'c2'), false);
  assert.equal(await na({}, { url: 'bad.example' }, 'c3'), false, 'a deny is stopped by the guardrail, not offered to a person');
  assert.equal(await na({}, { url: 'boom.example' }, 'c4'), true, 'a failure goes to a person');
  assert.deepEqual(seen, ['hold', 'allow', 'deny', 'hold']);
  assert.equal(await troothNeedsApproval(fakeGuard(), 'search')({}, { q: 1 }), false);
  assert.throws(() => troothNeedsApproval(fakeGuard()), TypeError);
});

test('openai-agents: guardTool adds needsApproval and puts the guardrail first', async () => {
  const mine = { type: 'tool_input', name: 'mine', run: async () => ({ behavior: { type: 'allow' } }) };
  const t = guardTool(fakeGuard(), { name: 'pay.out', description: 'd', parameters: {}, execute: () => 1, inputGuardrails: [mine] });
  assert.equal(t.description, 'd');
  assert.equal(t.inputGuardrails.length, 2);
  assert.equal(t.inputGuardrails[0].name, 'trooth_guard');
  assert.equal(t.inputGuardrails[1], mine);
  assert.equal(await t.needsApproval({}, { url: 'unknown.example' }), true);
  assert.equal(await t.needsApproval({}, { url: 'good.example' }), false);
  assert.equal(guardTool(fakeGuard(), { name: 'pay.out', needsApproval: true }).needsApproval, true, 'an always-approve tool stays that way');
  const theirs = guardTool(fakeGuard(), { name: 'pay.out', needsApproval: async (_c, i) => i.big === true });
  assert.equal(await theirs.needsApproval({}, { url: 'good.example', big: true }), true);
  assert.equal(await theirs.needsApproval({}, { url: 'good.example', big: false }), false);
});

test('openai-agents: the agent input guardrail trips on any hold or deny', async () => {
  const gr = troothAgentInputGuardrail(fakeGuard(), { extract: (input) => input.split(',').map((h) => ({ tool: 'pay.out', host: h })) });
  assert.equal(gr.runInParallel, false);
  assert.equal((await gr.execute({ input: 'good.example' })).tripwireTriggered, false);
  for (const i of ['good.example,unknown.example', 'bad.example', 'boom.example']) {
    const r = await gr.execute({ input: i });
    assert.equal(r.tripwireTriggered, true, i);
    assert.ok(r.outputInfo.decisions.length >= 1);
  }
  const broken = troothAgentInputGuardrail(fakeGuard(), { extract: () => { throw new Error('no'); } });
  assert.equal((await broken.execute({ input: 'x' })).tripwireTriggered, true);
  assert.equal((await gr.execute({ input: '' })).outputInfo.decisions.length, 1);
  assert.throws(() => troothAgentInputGuardrail(fakeGuard(), {}), TypeError);
});

// ---- LangChain JS ---------------------------------------------------------
class FakeToolMessage { constructor(f) { Object.assign(this, f); } }
const req = (name, args, id = 'tc1') => ({ toolCall: { name, args, id }, tool: {}, state: {}, runtime: {} });
const okHandler = () => { const h = async (r) => ({ ran: r.toolCall.name }); h.count = 0; const w = async (r) => { w.count++; return h(r); }; w.count = 0; return w; };

test('langchain: options for createMiddleware with a wrapToolCall hook', () => {
  const m = troothMiddleware(fakeGuard());
  assert.equal(m.name, 'TroothGuardMiddleware');
  assert.equal(typeof m.wrapToolCall, 'function');
  assert.throws(() => troothMiddleware(fakeGuard(), { onHold: 'interrupt' }), TypeError);
  assert.throws(() => troothMiddleware(fakeGuard(), { onDeny: 'message' }), TypeError);
  assert.throws(() => troothMiddleware(null), TypeError);
});

test('langchain: allow runs the tool; an uncovered tool runs without asking', async () => {
  const g = fakeGuard();
  const m = troothMiddleware(g);
  const h = okHandler();
  assert.deepEqual(await m.wrapToolCall(req('pay.out', { url: 'good.example' }), h), { ran: 'pay.out' });
  assert.deepEqual(await m.wrapToolCall(req('search', { q: 1 }), h), { ran: 'search' });
  assert.equal(h.count, 2);
  assert.equal(g.calls.length, 1);
});

test('langchain: deny throws GuardDeny or answers with an error ToolMessage; the tool never runs', async () => {
  const h = okHandler();
  await assert.rejects(troothMiddleware(fakeGuard()).wrapToolCall(req('pay.out', { url: 'bad.example' }), h), GuardDeny);
  const msg = await troothMiddleware(fakeGuard(), { ToolMessage: FakeToolMessage, onDeny: 'message' }).wrapToolCall(req('pay.out', { url: 'bad.example' }, 'id7'), h);
  assert.ok(msg instanceof FakeToolMessage);
  assert.equal(msg.status, 'error');
  assert.equal(msg.tool_call_id, 'id7');
  assert.match(msg.content, /deny .*SIGNATURE_INVALID/);
  assert.equal(h.count, 0);
});

test('langchain: hold interrupts for a person; approve runs the tool, anything else does not', async () => {
  const payloads = [];
  const h = okHandler();
  const mk = (resume, extra = {}) => troothMiddleware(fakeGuard(), { interrupt: (p) => { payloads.push(p); return resume; }, ...extra });
  assert.deepEqual(await mk({ type: 'approve' }).wrapToolCall(req('pay.out', { url: 'unknown.example' }), h), { ran: 'pay.out' });
  assert.equal(payloads[0].type, 'trooth_guard_hold');
  assert.equal(payloads[0].decision.decision, 'hold');
  assert.deepEqual(payloads[0].tool_call, { name: 'pay.out', id: 'tc1' });
  assert.equal(JSON.stringify(payloads[0]).includes('unknown.example/'), false);
  await assert.rejects(mk({ type: 'reject' }).wrapToolCall(req('pay.out', { url: 'unknown.example' }), h), GuardHold);
  const m = await mk(undefined, { ToolMessage: FakeToolMessage }).wrapToolCall(req('pay.out', { url: 'unknown.example' }), h);
  assert.match(m.content, /A person did not approve it/);
  assert.equal(h.count, 1);
  // interrupt pauses by throwing; the middleware must let that through
  const pause = new Error('GraphInterrupt');
  await assert.rejects(troothMiddleware(fakeGuard(), { interrupt: () => { throw pause; } }).wrapToolCall(req('pay.out', { url: 'unknown.example' }), h), (e) => e === pause);
  assert.equal(h.count, 1);
});

test('langchain: hold without interrupt answers with a ToolMessage or throws; failures hold', async () => {
  const h = okHandler();
  const m = await troothMiddleware(fakeGuard(), { ToolMessage: FakeToolMessage }).wrapToolCall(req('pay.out', { url: 'unknown.example' }), h);
  assert.match(m.content, /hold .*A person must approve it/);
  await assert.rejects(troothMiddleware(fakeGuard()).wrapToolCall(req('pay.out', { url: 'unknown.example' }), h), GuardHold);
  await assert.rejects(troothMiddleware(fakeGuard()).wrapToolCall(req('pay.out', { url: 'boom.example' }), h), (e) => e instanceof GuardHold && e.reasons[0] === 'SOURCE_UNREACHABLE');
  assert.equal(h.count, 0);
});

// ---- LangGraph JS ---------------------------------------------------------
class FakeCommand { constructor(a) { Object.assign(this, a); } }
const state = (...calls) => ({ messages: [{ type: 'human', content: 'pay' }, { type: 'ai', content: '', tool_calls: calls }] });

test('langgraph: all allowed -> empty update (or the decisions); uncovered calls are skipped', async () => {
  const node = createGuardNode(fakeGuard(), { interrupt: () => { throw new Error('should not interrupt'); } });
  assert.deepEqual(await node(state({ name: 'pay.out', args: { url: 'good.example' }, id: 'a' }, { name: 'search', args: {}, id: 'b' })), {});
  const withKey = createGuardNode(fakeGuard(), { interrupt: () => null, decisionsKey: 'trooth' });
  const u = await withKey(state({ name: 'pay.out', args: { url: 'good.example' }, id: 'a' }));
  assert.equal(u.trooth.length, 1);
  assert.equal(u.trooth[0].decision.decision, 'allow');
  assert.deepEqual(await node({ messages: [] }), {});
  assert.throws(() => createGuardNode(fakeGuard(), {}), TypeError);
  assert.throws(() => createGuardNode(fakeGuard(), { interrupt: () => 1, denyGoto: 'x' }), TypeError);
  // Routing without toolsGoto is refused: a static edge to the tool node would also run after a routed deny.
  assert.throws(() => createGuardNode(fakeGuard(), { interrupt: () => 1, Command: FakeCommand, denyGoto: 'x' }), /toolsGoto/);
  assert.throws(() => createGuardNode(fakeGuard(), { interrupt: () => 1, Command: FakeCommand, holdGoto: 'x' }), /toolsGoto/);
});

test('langgraph: with routing, allow and an approved hold route to toolsGoto by Command', async () => {
  const opts = { Command: FakeCommand, denyGoto: 'blocked', holdGoto: 'review', toolsGoto: 'tools' };
  const ok = await createGuardNode(fakeGuard(), { interrupt: () => { throw new Error('no interrupt'); }, ...opts })(state({ name: 'pay.out', args: { url: 'good.example' }, id: 'a' }));
  assert.ok(ok instanceof FakeCommand);
  assert.equal(ok.goto, 'tools');
  const approved = await createGuardNode(fakeGuard(), { interrupt: () => ({ type: 'approve' }), ...opts })(state({ name: 'pay.out', args: { url: 'unknown.example' }, id: 'a' }));
  assert.equal(approved.goto, 'tools');
  const rejected = await createGuardNode(fakeGuard(), { interrupt: () => ({ type: 'reject' }), ...opts })(state({ name: 'pay.out', args: { url: 'unknown.example' }, id: 'a' }));
  assert.equal(rejected.goto, 'review');
  const denied = await createGuardNode(fakeGuard(), { interrupt: () => true, ...opts })(state({ name: 'pay.out', args: { url: 'bad.example' }, id: 'a' }));
  assert.equal(denied.goto, 'blocked');
});

test('errors: guardDecisionOf finds the Decision inside framework wrappers', () => {
  const d = decisionFor('pay.out', 'bad.example', 'deny');
  // LangChain JS createAgent: MiddlewareError with the GuardDeny in .cause
  const mw = new Error('wrapped'); mw.cause = new GuardDeny(d);
  assert.equal(guardDecisionOf(mw), d);
  // @openai/agents: ToolCallError whose .error is the tripwire carrying the guardrail result
  const tc = new Error('Failed to run function tools'); tc.error = Object.assign(new Error('Tool input guardrail triggered'), { result: { output: { behavior: { type: 'throwException' }, outputInfo: { covered: true, decision: d } } } });
  assert.equal(guardDecisionOf(tc), d);
  // A second copy of the module: matched by code, not class
  const copy = Object.assign(new Error('x'), { code: 'TROOTH_GUARD_HOLD', decision: decisionFor('pay.out', 'u.example', 'hold') });
  assert.equal(guardDecisionOf(copy).decision, 'hold');
  assert.equal(guardDecisionOf(new Error('unrelated')), null);
  assert.equal(guardDecisionOf(null), null);
  assert.equal(guardDecisionOf(Object.assign(new Error('x'), { code: 'TROOTH_GUARD_DENY', decision: { decision: 'maybe' } })), null);
  const loop = new Error('loop'); loop.cause = loop;
  assert.equal(guardDecisionOf(loop), null);
});

test('langgraph: a hold calls interrupt once for every held call; approve continues, reject stops', async () => {
  const payloads = [];
  const node = (resume, extra) => createGuardNode(fakeGuard(), { interrupt: (p) => { payloads.push(p); return resume; }, ...extra });
  const s = state({ name: 'pay.out', args: { url: 'unknown.example' }, id: 'a' }, { name: 'send_email', args: { to: 'ap@unknown.example' }, id: 'b' }, { name: 'pay.out', args: { url: 'good.example' }, id: 'c' });
  assert.deepEqual(await node({ type: 'approve' })(s), {});
  assert.equal(payloads.length, 1);
  assert.deepEqual(payloads[0].held.map((x) => x.tool_call.id), ['a', 'b']);
  await assert.rejects(node({ type: 'reject' })(s), GuardHold);
  const routed = await node(false, { Command: FakeCommand, holdGoto: 'review', toolsGoto: 'tools' })(s);
  assert.ok(routed instanceof FakeCommand);
  assert.equal(routed.goto, 'review');
});

test('langgraph: a deny stops before any interrupt, by error or by Command', async () => {
  let asked = 0;
  const s = state({ name: 'pay.out', args: { url: 'unknown.example' }, id: 'a' }, { name: 'pay.out', args: { url: 'bad.example' }, id: 'b' });
  await assert.rejects(createGuardNode(fakeGuard(), { interrupt: () => { asked++; return true; } })(s), GuardDeny);
  const c = await createGuardNode(fakeGuard(), { interrupt: () => { asked++; return true; }, Command: FakeCommand, denyGoto: 'blocked', toolsGoto: 'tools', decisionsKey: 'd' })(s);
  assert.equal(c.goto, 'blocked');
  assert.equal(c.update.d.length, 2);
  assert.equal(asked, 0);
});

// ---- HTTP -----------------------------------------------------------------
function fakeFetch() {
  const sent = [];
  const f = async (input, init) => { sent.push({ input, init }); return { ok: true, status: 200 }; };
  f.sent = sent;
  return f;
}
const bankGuard = (d) => {
  const g = fakeGuard();
  g.decide = async (i) => { g.calls.push(i); return decisionFor(i.tool, i.host, d); };
  return g;
};

test('http: covered requests are decided on the host; allow passes through unchanged', async () => {
  const f = fakeFetch();
  const g = bankGuard('allow');
  const gf = guardFetch(f, g);
  const init = { method: 'post', body: 'secret=1', headers: { authorization: 'Bearer x' } };
  assert.equal((await gf('https://API.Example-Bank.com:8443/v1/payouts?acct=9', init)).status, 200);
  assert.equal(f.sent.length, 1);
  assert.equal(f.sent[0].init, init);
  assert.deepEqual(g.calls, [{ tool: 'http:POST', host: 'api.example-bank.com', args: { method: 'POST' } }]);
  assert.equal(JSON.stringify(g.calls).includes('secret'), false, 'the body is never given to the guard');
  assert.equal(JSON.stringify(g.calls).includes('acct'), false, 'nor the query');
  assert.equal(JSON.stringify(g.calls).includes('Bearer'), false, 'nor the headers');
});

test('http: hold throws GuardHold, deny throws GuardDeny, a failure holds; nothing is sent', async () => {
  for (const [d, E] of [['hold', GuardHold], ['deny', GuardDeny]]) {
    const f = fakeFetch();
    await assert.rejects(guardFetch(f, bankGuard(d))('https://pay.example-bank.com/x', { method: 'POST', body: 'b' }), (e) => e instanceof E && e.decision.decision === d);
    assert.equal(f.sent.length, 0);
  }
  const f = fakeFetch();
  const g = fakeGuard();
  g.decide = async () => { throw new Error('offline'); };
  await assert.rejects(guardFetch(f, g)('https://pay.example-bank.com/x', { method: 'POST' }), (e) => e instanceof GuardHold && e.reasons[0] === 'SOURCE_UNREACHABLE');
  assert.equal(f.sent.length, 0);
});

test('http: requests the policy does not cover pass through without a decision', async () => {
  const f = fakeFetch();
  const g = bankGuard('deny');
  const gf = guardFetch(f, g);
  await gf('https://pay.example-bank.com/x');
  await gf('https://pay.example-bank.com/x', { method: 'GET' });
  await gf('https://example-bank.com/x', { method: 'POST' });
  await gf('https://evil-example-bank.com/x', { method: 'POST' });
  await gf(new URL('https://other.example/x'), { method: 'POST' });
  assert.equal(f.sent.length, 5);
  assert.equal(g.calls.length, 0);
  await assert.rejects(gf('https://FILES.example.org./up', { method: 'PUT' }), GuardDeny, 'a rule with no method covers every method');
  await assert.rejects(gf({ url: 'https://a.b.example-bank.com/', method: 'POST' }), GuardDeny, 'a Request-like object; * spans labels');
});

test('http: a URL object from a polyfill or another realm, or anything fetch stringifies, is still decided', async () => {
  // fetch(input) turns an input that is not a string, URL or Request into a string;
  // the guard must read the same destination instead of letting it pass unchecked.
  class PolyURL { constructor(s) { this.s = s; } get href() { return this.s; } toString() { return this.s; } }
  for (const input of [new PolyURL('https://api.example-bank.com/v1/payouts'), { toString: () => 'https://api.example-bank.com/v1/payouts' }]) {
    const f = fakeFetch();
    const g = bankGuard('hold');
    await assert.rejects(guardFetch(f, g)(input, { method: 'POST' }), GuardHold);
    assert.equal(f.sent.length, 0, 'nothing is sent');
    assert.deepEqual(g.calls.map((c) => c.host), ['api.example-bank.com']);
  }
  assert.deepEqual(requestTarget(new PolyURL('https://A.example/')), { method: 'GET', host: 'a.example' });
});

test('python: trooth_guard covered() covers what the CLI covers (case, Unicode forms, non-ASCII, literal ? and [ ])', async (t) => {
  const { toolCovered } = await import('../bin/lib/guard-policy.mjs');
  const { execFileSync } = await import('node:child_process');
  const tools = ['stripe.create_payout', 'mcp__bank__*', 'a?b', 'c[d]'];
  const names = ['stripe.create_payout', 'Stripe.create_payout', 'STRIPE.CREATE_PAYOUT', 'ｓtripe.create_payout', 'stripe.create_payout ', 'mcp__BANK__pay', 'mcp__bank__', 'mcp__bank', 'search', 'axb', 'a?b', 'c[d]', 'cd', 'mcp__bank__x\n'];
  let out;
  try {
    out = execFileSync('python3', ['-I', '-c', 'import json,sys; sys.path.insert(0, sys.argv[1]); from trooth_guard.core import covered; a=json.loads(sys.stdin.read()); print(json.dumps([covered(n, a["tools"]) for n in a["names"]]))', new URL('../sdk/python', import.meta.url).pathname], { input: JSON.stringify({ tools, names }), encoding: 'utf8' });
  } catch (e) {
    if (e.code === 'ENOENT') { t.skip('python3 is not installed'); return; }
    throw e;
  }
  const policy = { applies_to: { tools } };
  assert.deepEqual(JSON.parse(out), names.map((n) => toolCovered(policy, n)));
});

test('http: target parsing and rules', () => {
  assert.deepEqual(requestTarget('https://X.Example.com.:9/p?q#f'), { method: 'GET', host: 'x.example.com' });
  assert.deepEqual(requestTarget({ url: 'https://a.example/', method: 'delete' }), { method: 'DELETE', host: 'a.example' });
  assert.deepEqual(requestTarget({ url: 'https://a.example/', method: 'delete' }, { method: 'PUT' }), { method: 'PUT', host: 'a.example' });
  assert.equal(requestTarget('/relative'), null);
  assert.equal(requestTarget(42), null);
  const rules = httpRules(fakeGuard());
  assert.equal(rules.length, 2);
  assert.equal(coversRequest(rules, null), false);
  assert.deepEqual(httpRules({ policy: {} }), []);
  assert.throws(() => guardFetch(null, fakeGuard()), TypeError);
  assert.throws(() => guardFetch(fakeFetch(), {}), TypeError);
});
