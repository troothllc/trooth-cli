// Pilot 1, "Payments agent" (Trooth-run, test harness): the OpenAI Agents SDK
// for JavaScript (@openai/agents, the real package) with a payout tool guarded
// by trooth/guard/openai-agents. No LLM key: the agent is driven by a scripted
// Model that implements the SDK's Model interface, so the SDK's own runner,
// needsApproval interruptions, tool input guardrails and RunState approval run.
import { z } from 'zod';
import { Agent, Runner, tool, Usage, setTracingDisabled, ToolInputGuardrailTripwireTriggered, InputGuardrailTripwireTriggered } from '@openai/agents';
import { guardTool, troothAgentInputGuardrail } from '../../bin/lib/guard/openai-agents.mjs';
import { guardDecisionOf } from '../../bin/lib/guard/errors.mjs';
import { liveGuard, fixtureGuard, step, codesOf, save, pkgVersion } from './common.mjs';

setTracingDisabled(true);
const P = 'payments-openai-agents';

/** A scripted model: first turn calls create_payout with `args`; after a tool result, it answers in text. */
class ScriptedModel {
  constructor(args) { this.args = args; this.calls = 0; this.sawToolOutput = []; }
  async getResponse(req) {
    this.calls++;
    const items = Array.isArray(req.input) ? req.input : [];
    const results = items.filter((i) => i.type === 'function_call_result');
    if (results.length) {
      this.sawToolOutput.push(results.at(-1).output);
      return { usage: new Usage(), output: [{ type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'Payout step finished.' }] }] };
    }
    return { usage: new Usage(), output: [{ type: 'function_call', callId: `call_${this.calls}_${Date.now()}`, name: 'create_payout', arguments: JSON.stringify(this.args), status: 'completed' }] };
  }
  async *getStreamedResponse() { throw new Error('streaming is not used in this pilot'); }
}

function payoutAgent(guard, args, executed, { inputGuardrails } = {}) {
  const payout = tool(guardTool(guard, {
    name: 'create_payout',
    description: 'Send a payout to a vendor.',
    parameters: z.object({ url: z.string(), amount: z.number() }),
    execute: async ({ url, amount }) => { executed.push({ url, amount }); return `payout of ${amount} sent to ${url}`; },
  }));
  const model = new ScriptedModel(args);
  return { agent: new Agent({ name: 'payments', instructions: 'Pay vendors.', model, tools: [payout], ...(inputGuardrails ? { inputGuardrails } : {}) }), model };
}

async function scenario(label, guard, args, expect, { approve, runConfig } = {}) {
  const executed = [];
  const { agent, model } = payoutAgent(guard, args, executed);
  const runner = new Runner(runConfig ?? {});
  let result, error;
  try {
    result = await runner.run(agent, 'Pay the invoice.');
    if (result.interruptions?.length) {
      const it = result.interruptions[0];
      if (approve === true) result.state.approve(it);
      else if (approve === false) result.state.reject(it);
      if (approve !== undefined) result = await runner.run(agent, result.state);
    }
  } catch (e) { error = e; }
  // @openai/agents (0.19.0 at least) wraps the tripwire: ToolCallError whose .error is ToolInputGuardrailTripwireTriggered.
  const inner = error instanceof ToolInputGuardrailTripwireTriggered ? error : error?.error;
  const gr = result?.state?._toolInputGuardrailResults ?? [];
  const lastGr = gr.at(-1)?.output;
  const obs = {
    interruptions_first_run: undefined,
    executed: executed.length,
    error: error ? error.constructor.name : null,
    inner: inner ? inner.constructor.name : null,
    guardrail_behavior: lastGr?.behavior?.type ?? (inner?.result?.output?.behavior?.type ?? null),
    approved_by_person: lastGr?.outputInfo?.approved_by_person ?? false,
    decision: (inner?.result?.output?.outputInfo?.decision ?? lastGr?.outputInfo?.decision)?.decision ?? null,
    codes: codesOf(inner?.result?.output?.outputInfo?.decision ?? lastGr?.outputInfo?.decision),
    model_saw: model.sawToolOutput.at(-1) ?? null,
    final: result?.finalOutput ?? null,
  };
  obs.helper = guardDecisionOf(error);
  return { obs, error };
}

const live = await liveGuard('payments-live.yaml');
const fx = await fixtureGuard('payments-fixture.yaml');
const fxForged = await fixtureGuard('payments-fixture.yaml', 'forged');

// 1. live allow: trooth.co under a policy requiring trooth_reading, min_witnesses 0
{
  const { obs, error } = await scenario('live allow', live, { url: 'https://trooth.co/pay', amount: 25 });
  step(P, 'live trooth.co: allow, the payout runs', { expected: 'allow, executed 1, no interruption', observed: `${obs.decision}, executed ${obs.executed}, error ${obs.error}`, pass: obs.decision === 'allow' && obs.executed === 1 && !error });
}
// 2. live hold, a person approves: needsApproval interrupts; after approve the guardrail sees isToolApproved
{
  const executed = [];
  const { agent } = payoutAgent(live, { url: 'https://pilot-unknown-7f3a9c2e.com/pay', amount: 40 }, executed);
  const runner = new Runner();
  let r = await runner.run(agent, 'Pay the invoice.');
  const n = r.interruptions?.length ?? 0;
  const item = r.interruptions?.[0];
  const executedBefore = executed.length;
  r.state.approve(item);
  r = await runner.run(agent, r.state);
  const gr = r.state._toolInputGuardrailResults.at(-1)?.output;
  step(P, 'live unknown domain: hold pauses the run with an interruption', { expected: '1 interruption, payout not run', observed: `${n} interruption(s) for ${item?.rawItem?.name ?? item?.name}, executed ${executedBefore}`, pass: n === 1 && executedBefore === 0 });
  step(P, 'live unknown domain: after state.approve, guardrail reads isToolApproved from its context and allows', { expected: 'guardrail allow with approved_by_person true, decision hold NO_RECORD, executed 1', observed: `behavior ${gr?.behavior?.type}, approved_by_person ${gr?.outputInfo?.approved_by_person}, decision ${gr?.outputInfo?.decision?.decision} ${codesOf(gr?.outputInfo?.decision)}, executed ${executed.length}`, pass: gr?.behavior?.type === 'allow' && gr?.outputInfo?.approved_by_person === true && executed.length === 1 && codesOf(gr?.outputInfo?.decision).includes('NO_RECORD') });
}
// 3. live hold, a person rejects
{
  const { obs } = await scenario('live hold reject', live, { url: 'https://pilot-unknown-7f3a9c2e.com/pay', amount: 40 }, null, { approve: false });
  step(P, 'live unknown domain: state.reject, the payout does not run', { expected: 'executed 0, the model is told it was rejected', observed: `executed ${obs.executed}, model saw ${JSON.stringify(obs.model_saw)}`, pass: obs.executed === 0 && obs.model_saw !== null });
}
// 4. live deny: a domain served for another host (www.trooth.co gets trooth.co's record)
{
  const { obs } = await scenario('live deny', live, { url: 'https://www.trooth.co/pay', amount: 40 });
  step(P, 'live www.trooth.co: deny SUBJECT_MISMATCH trips the tool input guardrail and stops the run', { expected: 'run throws, tripwire ToolInputGuardrailTripwireTriggered (top level or as .error), executed 0', observed: `${obs.error} wrapping ${obs.inner}, decision ${obs.decision} ${obs.codes}, executed ${obs.executed}`, pass: obs.inner === 'ToolInputGuardrailTripwireTriggered' && obs.executed === 0 && obs.codes.includes('SUBJECT_MISMATCH') });
  step(P, 'the error class the run rejects with (recorded; GUARD-ADAPTERS.md says the SDK may wrap the tripwire)', { expected: 'record what happens', observed: `${obs.error} wrapping ${obs.inner}`, pass: true, detail: 'informational' });
  step(P, 'guardDecisionOf(err) finds the Decision whether or not the SDK wraps the tripwire', { expected: 'deny SUBJECT_MISMATCH', observed: `${obs.helper?.decision} ${codesOf(obs.helper)}`, pass: obs.helper?.decision === 'deny' && codesOf(obs.helper).includes('SUBJECT_MISMATCH') });
}
// 5. fixture denies
for (const [g, host, code] of [[fx, 'spoofed-vendor.com', 'SUBJECT_MISMATCH'], [fx, 'revoked-key-vendor.com', 'KEY_NOT_TRUSTED'], [fxForged, 'forged-log-vendor.com', 'NOT_IN_LOG']]) {
  const { obs } = await scenario(`fixture deny ${host}`, g, { url: `https://${host}/pay`, amount: 10 });
  step(P, `fixture ${host}: deny ${code} stops the run`, { expected: 'tripwire (as .error of ToolCallError), executed 0', observed: `${obs.error} wrapping ${obs.inner}, decision ${obs.decision} ${obs.codes}, executed ${obs.executed}`, pass: obs.inner === 'ToolInputGuardrailTripwireTriggered' && obs.executed === 0 && obs.codes.includes(code) });
}
// 6. fixture allow and fixture hold (sanctions name match) with approval
{
  const { obs } = await scenario('fixture allow', fx, { url: 'https://acme-payments.com/pay', amount: 10 });
  step(P, 'fixture acme-payments.com: allow', { expected: 'allow, executed 1', observed: `${obs.decision}, executed ${obs.executed}`, pass: obs.decision === 'allow' && obs.executed === 1 });
  const h = await scenario('fixture hold approve', fx, { url: 'https://name-match-vendor.com/pay', amount: 10 }, null, { approve: true });
  step(P, 'fixture name-match-vendor.com: hold EVIDENCE_MISSING, approved, runs', { expected: 'executed 1 after approval, approved_by_person true', observed: `executed ${h.obs.executed}, approved_by_person ${h.obs.approved_by_person}, decision ${h.obs.decision} ${h.obs.codes}`, pass: h.obs.executed === 1 && h.obs.approved_by_person === true });
}
// 7. Runner option toolExecution.preApprovalInputGuardrails: true (exists in this SDK version)
{
  const { obs } = await scenario('preApproval', live, { url: 'https://pilot-unknown-7f3a9c2e.com/pay', amount: 40 }, null, { runConfig: { toolExecution: { preApprovalInputGuardrails: true } } });
  step(P, 'preApprovalInputGuardrails true: a hold is rejected by the guardrail before any person sees it', { expected: 'documented gap: no interruption, rejectContent, executed 0', observed: `guardrail ${obs.guardrail_behavior}, executed ${obs.executed}, model saw ${JSON.stringify(obs.model_saw)?.slice(0, 120)}`, pass: obs.executed === 0, detail: 'fails closed, but the person approval path is skipped' });
}
// 8. agent input guardrail with extract
{
  const extract = (input) => { const m = /https?:\/\/([^/\s]+)/.exec(typeof input === 'string' ? input : JSON.stringify(input)); return m ? [{ tool: 'create_payout', host: m[1] }] : []; };
  for (const [host, want] of [['trooth.co', false], ['pilot-unknown-7f3a9c2e.com', true]]) {
    const executed = [];
    const { agent } = payoutAgent(live, { url: `https://${host}/pay`, amount: 5 }, executed, { inputGuardrails: [troothAgentInputGuardrail(live, { extract })] });
    let err = null;
    try { await new Runner().run(agent, `Pay the invoice at https://${host}/pay`); } catch (e) { err = e; }
    const tripped = err instanceof InputGuardrailTripwireTriggered;
    step(P, `agent input guardrail, ${host}: tripwire ${want}`, { expected: `tripwire ${want}`, observed: `tripwire ${tripped}${err && !tripped ? ` (${err.constructor.name}: ${err.message})` : ''}, executed ${executed.length}`, pass: tripped === want && (want ? executed.length === 0 : executed.length === 1) });
  }
}

process.exitCode = save('pilot1-js', { packages: { '@openai/agents': pkgVersion('@openai/agents'), '@openai/agents-core': pkgVersion('@openai/agents-core'), zod: pkgVersion('zod') } }) ? 1 : 0;
void ToolInputGuardrailTripwireTriggered;
