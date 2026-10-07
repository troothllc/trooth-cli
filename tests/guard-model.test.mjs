// tests/guard-model.test.mjs - an exhaustive check of the guard's decision
// table (bin/lib/guard-decide.mjs decideFrom) over every combination of its
// abstract inputs, against an independent statement of the table (docs/GUARD.md
// section 5) and the invariants it must keep. spec/GuardDecision.tla states the
// same table and invariants for TLC.
//
// Inputs enumerated: source (network, cache, unreachable) x record x schema
// supported x signature (valid, invalid, absent) x key status (6) x subject
// match x log (included, not_logged, unavailable, proof_invalid) x witnesses
// below or at min_witnesses x log.required x unknown_counterparty (hold, deny)
// x source_unreachable (hold, deny) x every multiset of one to three rules,
// each rule one of {hold rule, absolute rule} x claim {present, missing,
// stale, disputed}. Rule order changes only the order of reasons; that is
// checked on its own below. Network-free.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decideFrom, validateDecision, TRUSTED } from '../bin/lib/guard-decide.mjs';
import { normalizePolicy, PolicyError } from '../bin/lib/guard-policy.mjs';

const NOW = Date.parse('2026-10-07T12:00:00.000Z');
const DAY = 86400000;
const iso = (ms) => new Date(ms).toISOString();
const SOURCES = ['network', 'cache', 'unreachable'];
const SIGS = ['valid', 'invalid', 'absent'];
const KEYS = ['active', 'retired_before_use', 'retired_after_use', 'revoked', 'compromised', 'unknown'];
const LOGS = ['included', 'not_logged', 'unavailable', 'proof_invalid'];
const STATES = ['present', 'missing', 'stale', 'disputed'];
const KINDS = ['hold', 'absolute'];
const CLAIMS = ['trooth_reading', 'domain_registration_record', 'security_txt_published'];

function claimFor(state, i) {
  if (state === 'missing') return undefined;
  const base = { fact_id: `trooth:statement:${'a'.repeat(64)}#${CLAIMS[i]}`, statement_sha256: 'a'.repeat(64), log_index: 7, disputed: state === 'disputed' };
  if (state === 'stale') return { ...base, observed_at: iso(NOW - 10 * DAY), stale_after: iso(NOW - DAY) };
  return { ...base, observed_at: iso(NOW - DAY), stale_after: iso(NOW + 30 * DAY) };
}

/** Every multiset of n rule configurations (kind, state), as index lists in non-decreasing order. */
function multisets(n, k) {
  const out = [];
  const rec = (start, acc) => { if (acc.length === n) { out.push([...acc]); return; } for (let i = start; i < k; i++) { acc.push(i); rec(i, acc); acc.pop(); } };
  rec(0, []);
  return out;
}
const RULE_CONFIGS = [1, 2, 3].flatMap((n) => multisets(n, KINDS.length * STATES.length)).map((idx) => idx.map((x) => ({ kind: KINDS[Math.floor(x / STATES.length)], state: STATES[x % STATES.length] })));

const policyCache = new Map();
function policyFor(rules, { required, uc, su }) {
  const key = `${rules.map((r) => r.kind[0]).join('')}|${required}|${uc}|${su}`;
  if (!policyCache.has(key)) {
    policyCache.set(key, normalizePolicy({
      policy: 'model', version: 1, applies_to: { tools: ['pay'] },
      log: { required, min_witnesses: 1 },
      rules: rules.map((r, i) => (r.kind === 'absolute' ? { id: `r${i}`, require: { claim: CLAIMS[i] }, on_fail: 'deny', absolute: true } : { id: `r${i}`, require: { claim: CLAIMS[i] }, on_fail: 'hold' })),
      unknown_counterparty: uc, source_unreachable: su,
    }));
  }
  return policyCache.get(key);
}

/** The decision table, stated again independently of the implementation. */
function oracle(f, rules, pol) {
  if (f.source === 'unreachable') return pol.su;
  if (!f.record) return pol.uc;
  if (!f.schema_supported) return 'hold';
  if (f.signature === 'invalid' || (f.signature !== 'absent' && !TRUSTED.includes(f.key_status)) || !f.subject_match) return 'deny';
  if (f.signature !== 'absent' && f.log === 'proof_invalid') return 'deny';
  let hold = f.signature !== 'absent' && pol.required && (f.log !== 'included' || f.witnesses < 1);
  let deny = false;
  for (const r of rules) {
    const ok = f.signature === 'valid' && r.state === 'present';
    if (ok) continue;
    if (r.kind === 'absolute') deny = true; else hold = true;
  }
  return deny ? 'deny' : hold ? 'hold' : 'allow';
}

test('exhaustive: the decision equals the table, and the invariants hold, for every combination', () => {
  let n = 0, allows = 0, holds = 0, denies = 0;
  const failProof = (f) => f.signature === 'invalid' || (f.signature !== 'absent' && !TRUSTED.includes(f.key_status)) || !f.subject_match || (f.signature !== 'absent' && f.log === 'proof_invalid');
  for (const required of [true, false]) for (const uc of ['hold', 'deny']) for (const su of ['hold', 'deny']) for (const rules of RULE_CONFIGS) {
    const policy = policyFor(rules, { required, uc, su });
    const claims = {};
    rules.forEach((r, i) => { const c = claimFor(r.state, i); if (c) claims[CLAIMS[i]] = c; });
    for (const source of SOURCES) for (const record of [true, false]) for (const schema of [true, false]) for (const signature of SIGS) for (const key of KEYS) for (const subject of [true, false]) for (const log of LOGS) for (const witnesses of [0, 1]) {
      const f = { now: NOW, host: 'pay.acme.com', target: 'ok', source, record, subject: record ? 'trooth:domain:acme.com' : '', schema_supported: schema, signature, key_status: key, subject_match: subject, log, witnesses, claims };
      const d = decideFrom(f, policy);
      n++;
      const want = oracle(f, rules, { required, uc, su });
      if (d.decision !== want) assert.fail(`table: ${JSON.stringify({ source, record, schema, signature, key, subject, log, witnesses, required, uc, su, rules })} gave ${d.decision}, want ${want}`);
      if (d.decision === 'allow') {
        allows++;
        // Invariant 1: allow implies every required check held.
        const held = source !== 'unreachable' && record && schema && signature === 'valid' && TRUSTED.includes(key) && subject && log !== 'proof_invalid' && (!required || (log === 'included' && witnesses >= 1)) && rules.every((r) => r.state === 'present');
        if (!held) assert.fail(`allow without every required check: ${JSON.stringify(f)}`);
        if (d.reasons.some((r) => r.code !== 'RULE_PASSED') || d.reasons.length !== rules.length) assert.fail('allow carries a reason other than RULE_PASSED per rule');
      } else if (d.decision === 'hold') holds++;
      else {
        denies++;
        // Invariant 3: deny only for a failed proof or an absolute rule (or the customer's own deny choice for no record or no source).
        const absoluteFailed = d.reasons.some((r) => r.code === 'ABSOLUTE_RULE_FAILED');
        const chosen = (source === 'unreachable' && su === 'deny') || (source !== 'unreachable' && !record && uc === 'deny');
        if (!(failProof(f) || absoluteFailed || chosen)) assert.fail(`deny without a failed proof or an absolute rule: ${JSON.stringify(f)}`);
      }
      // Invariant 2: source unreachable never yields allow.
      if (source === 'unreachable' && d.decision === 'allow') assert.fail('allow while unreachable');
      // Invariant 4: the same inputs always give the same decision (checked on one combination in 61).
      if (n % 61 === 0) assert.deepEqual(decideFrom(structuredClone(f), policy), d);
      if (n % 997 === 0) assert.deepEqual(validateDecision(d), []);
    }
  }
  const per = SOURCES.length * 2 * 2 * SIGS.length * KEYS.length * 2 * LOGS.length * 2;
  assert.equal(n, per * RULE_CONFIGS.length * 8);
  assert.equal(RULE_CONFIGS.length, 8 + 36 + 120);
  assert.ok(allows > 0 && holds > 0 && denies > 0);
  console.log(`# model: ${n} combinations checked (${allows} allow, ${holds} hold, ${denies} deny); ${RULE_CONFIGS.length} rule multisets`);
});

test('rule order changes only the order of reasons, never the decision', () => {
  const perms = (a) => (a.length <= 1 ? [a] : a.flatMap((x, i) => perms([...a.slice(0, i), ...a.slice(i + 1)]).map((p) => [x, ...p])));
  let n = 0;
  for (const rules of RULE_CONFIGS.filter((r) => r.length === 3)) {
    const claims = {};
    const decisions = new Set();
    for (const order of perms([0, 1, 2])) {
      const ordered = order.map((i) => rules[i]);
      ordered.forEach((r, i) => { const c = claimFor(r.state, i); if (c) claims[CLAIMS[i]] = c; else delete claims[CLAIMS[i]]; });
      const f = { now: NOW, host: 'acme.com', target: 'ok', source: 'network', record: true, subject: 'trooth:domain:acme.com', schema_supported: true, signature: 'valid', key_status: 'active', subject_match: true, log: 'included', witnesses: 1, claims: { ...claims } };
      decisions.add(decideFrom(f, policyFor(ordered, { required: true, uc: 'hold', su: 'hold' })).decision);
      n++;
    }
    assert.equal(decisions.size, 1);
  }
  assert.equal(n, 120 * 6);
});

test('exhaustive: a signature rule over every signature and key status, hold or absolute', () => {
  let n = 0;
  for (const statuses of [['active'], ['retired_before_use'], ['active', 'retired_before_use']]) for (const absolute of [true, false]) {
    const policy = normalizePolicy({ policy: 'sig', version: 1, applies_to: { tools: ['pay'] }, rules: [absolute ? { id: 'k', require: { signature: 'valid', key_status: statuses }, on_fail: 'deny', absolute: true } : { id: 'k', require: { signature: 'valid', key_status: statuses } }] });
    for (const signature of SIGS) for (const key of KEYS) for (const log of LOGS) {
      const d = decideFrom({ now: NOW, host: 'acme.com', target: 'ok', source: 'network', record: true, subject: 'trooth:domain:acme.com', schema_supported: true, signature, key_status: key, subject_match: true, log, witnesses: 1, claims: {} }, policy);
      n++;
      const proofFails = signature === 'invalid' || (signature !== 'absent' && !TRUSTED.includes(key)) || (signature !== 'absent' && log === 'proof_invalid');
      const ruleOk = signature === 'valid' && statuses.includes(key);
      const logHold = signature !== 'absent' && log !== 'included';
      const want = proofFails ? 'deny' : !ruleOk ? (absolute ? 'deny' : 'hold') : logHold ? 'hold' : 'allow';
      assert.equal(d.decision, want, JSON.stringify({ statuses, absolute, signature, key, log }));
      if (d.decision === 'allow') assert.ok(signature === 'valid' && statuses.includes(key));
    }
  }
  assert.equal(n, 3 * 2 * 3 * 6 * 4);
});

test('exhaustive: with no single host in the typed arguments, or an IP or localhost, nothing is allowed', () => {
  const policy = policyFor([{ kind: 'hold', state: 'present' }], { required: true, uc: 'hold', su: 'hold' });
  const denyNoRecord = policyFor([{ kind: 'hold', state: 'present' }], { required: true, uc: 'deny', su: 'hold' });
  for (const target of ['none', 'ambiguous', 'non_record']) for (const source of SOURCES) for (const signature of SIGS) {
    const f = { now: NOW, host: target === 'non_record' ? '10.0.0.1' : null, target, source, record: true, subject: '', schema_supported: true, signature, key_status: 'active', subject_match: true, log: 'included', witnesses: 2, claims: { trooth_reading: claimFor('present', 0) } };
    const d = decideFrom(f, policy);
    assert.equal(d.decision, 'hold', `${target} ${source}`);
    assert.deepEqual(d.reasons.map((r) => r.code), [target === 'non_record' ? 'NO_RECORD' : 'EVIDENCE_MISSING']);
    if (target === 'non_record') assert.equal(decideFrom(f, denyNoRecord).decision, 'deny');
  }
});

test('the policies the model leaves out are the ones parsePolicy refuses: deny without absolute, absolute that holds', () => {
  const base = { policy: 'x', version: 1, applies_to: { tools: ['pay'] } };
  assert.throws(() => normalizePolicy({ ...base, rules: [{ id: 'a', require: { claim: 'trooth_reading' }, on_fail: 'deny' }] }), PolicyError);
  assert.throws(() => normalizePolicy({ ...base, rules: [{ id: 'a', require: { claim: 'trooth_reading' }, on_fail: 'hold', absolute: true }] }), PolicyError);
  assert.throws(() => normalizePolicy({ ...base, rules: [{ id: 'a', require: { claim: 'trooth_reading' } }], source_unreachable: 'allow' }), PolicyError);
  assert.throws(() => normalizePolicy({ ...base, rules: [{ id: 'a', require: { claim: 'trooth_reading' } }], unknown_counterparty: 'allow' }), PolicyError);
});
