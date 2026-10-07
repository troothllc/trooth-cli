// tests/guard.test.mjs - trooth/guard end to end as a library: evidence read
// from a world of signed fixtures (tests/lib/guard-fixtures.mjs) through an
// injected fetch, every check done locally, and the decision validated
// against schemas/guard-decision.v1.schema.json. Network-free.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createGuard, parsePolicy, GUARD_DECISION_SCHEMA, decideFrom, validateDecision } from '../bin/lib/guard.mjs';
import { loadSchemas, makeValidator } from './lib/mini-schema.mjs';
import { makeWorld, POLICY_YAML, NOW, keyEntry, K, DEFAULT_KEYS } from './lib/guard-fixtures.mjs';

const schemas = loadSchemas(new URL('../schemas/', import.meta.url));
const validate = makeValidator(schemas);
const P = parsePolicy(POLICY_YAML);
const policyWith = (edit) => parsePolicy(edit(POLICY_YAML));
const ACME = { 'acme.com': { witness: {}, public: {} } };
const DAY = 86400000;
const iso = (ms) => new Date(ms).toISOString();

function guardFor(world, policy = P, extra = {}) {
  return createGuard({ policy, fetch: world.fetch, now: world.now, vkeys: world.vkeys, witnesses: world.witnesses, api: world.api, web: world.web, ...extra });
}
const codes = (d) => d.reasons.map((r) => r.code);
const notPassed = (d) => d.reasons.filter((r) => r.code !== 'RULE_PASSED');
function valid(d) {
  assert.deepEqual(validate('guard-decision.v1.schema.json', d), [], 'the decision validates against the schema');
  assert.deepEqual(validateDecision(d), []);
  return d;
}
const call = (args, name = 'stripe.create_payout') => ({ name, arguments: args });

test('the schema is the published contract: its $id is GUARD_DECISION_SCHEMA and the required fields are kept', () => {
  const s = schemas['guard-decision.v1.schema.json'];
  assert.equal(s.$id, GUARD_DECISION_SCHEMA);
  assert.deepEqual(s.required, ['decision', 'reasons', 'subject', 'policy', 'evidence', 'decided_at']);
  assert.equal(s.$defs.reason.properties.code.enum.length, 12);
  assert.ok(s.$defs.reason.properties.detail);
});

test('allow: every claim signed, logged and fresh; cosigned by the pinned witnesses; the walk reaches the parent', async () => {
  const w = makeWorld({ domains: ACME, growAfter: 2 });
  const d = valid(await guardFor(w).decideToolCall(call({ url: 'https://pay.acme.com/v1', memo: 'thanks' })));
  assert.equal(d.decision, 'allow');
  assert.deepEqual(codes(d), ['RULE_PASSED', 'RULE_PASSED', 'RULE_PASSED']);
  assert.equal(d.subject, 'trooth:domain:acme.com');
  assert.deepEqual(d.policy, { id: 'vendor-payments', version: 3, sha256: P.sha256 });
  assert.equal(d.evidence.length, 2);
  for (const e of d.evidence) { assert.match(e.statement_sha256, /^[0-9a-f]{64}$/); assert.equal(typeof e.log_index, 'number'); }
  assert.equal(d.evidence[1].stale_after, iso(Date.parse(d.evidence[1].observed_at) + 7 * DAY), 'the rule max_age_days sets stale_after');
  assert.equal(d.action.host, 'pay.acme.com');
  assert.deepEqual(d.action.argument_names, ['url', 'memo']);
  assert.equal(d.decided_at, iso(NOW));
  assert.ok(w.requests.some((r) => r.url.endsWith('/proof/consistency?first=' + w.receiptSize + '&second=' + w.size)), 'a newer cosigned checkpoint is tied to the receipt by a consistency proof');
});

test('what is sent: only the domain or a statement id, only to Trooth, the public record with cached=only, never the action', async () => {
  const w = makeWorld({ domains: ACME });
  await guardFor(w).decideToolCall(call({ url: 'https://pay.acme.com/v1/payouts/secret-path', amount: 987654, memo: 'invoice-77731' }));
  assert.ok(w.requests.length > 0);
  for (const r of w.requests) {
    const u = new URL(r.url);
    assert.ok(['trooth.test', 'api.trooth.test'].includes(u.host), r.url);
    assert.equal(r.method, 'GET');
    for (const secret of ['secret-path', '987654', 'invoice-77731', 'stripe', 'payout', 'memo']) assert.ok(!r.url.toLowerCase().includes(secret), `${secret} not in ${r.url}`);
    assert.match(String(r.headers['user-agent']), /^trooth-guard\//);
    if (u.pathname.startsWith('/scan/public-record/')) assert.equal(u.search, '?cached=only');
  }
});

test('witnesses: fewer cosigners than min_witnesses holds NOT_IN_LOG; enough allows; log.required false skips it', async () => {
  let d = valid(await guardFor(makeWorld({ domains: ACME, cosigners: 0 })).decideToolCall(call({ domain: 'acme.com' })));
  assert.equal(d.decision, 'hold');
  assert.equal(notPassed(d)[0].code, 'NOT_IN_LOG');
  assert.match(notPassed(d)[0].detail, /0 pinned witnesses cosigned/);
  const two = policyWith((t) => t.replace('min_witnesses: 1', 'min_witnesses: 2'));
  d = await guardFor(makeWorld({ domains: ACME, cosigners: 1 }), two).decideToolCall(call({ domain: 'acme.com' }));
  assert.equal(d.decision, 'hold');
  d = await guardFor(makeWorld({ domains: ACME, cosigners: 2, growAfter: 3 }), two).decideToolCall(call({ domain: 'acme.com' }));
  assert.equal(d.decision, 'allow');
  const notRequired = policyWith((t) => t.replace('log: { required: true, min_witnesses: 1 }', 'log: { required: false, min_witnesses: 0 }'));
  d = await guardFor(makeWorld({ domains: { 'acme.com': { witness: {}, public: {}, logWitness: false, logPublic: false } } }), notRequired).decideToolCall(call({ domain: 'acme.com' }));
  assert.equal(d.decision, 'allow');
  d = await guardFor(makeWorld({ domains: { 'acme.com': { witness: {}, public: {}, logWitness: false, logPublic: false } } })).decideToolCall(call({ domain: 'acme.com' }));
  assert.equal(d.decision, 'hold');
  assert.ok(notPassed(d).some((r) => r.code === 'NOT_IN_LOG' && /no entry for this statement|not in the log/.test(r.detail)));
});

test('no record: hold NO_RECORD (or deny when the policy says so); an IP or localhost is never looked up', async () => {
  const w = makeWorld({ domains: {} });
  let d = valid(await guardFor(w).decideToolCall(call({ url: 'https://unknown-vendor.example.org/pay' })));
  assert.equal(d.decision, 'hold'); assert.deepEqual(codes(d), ['NO_RECORD']);
  assert.deepEqual(w.requests.map((r) => new URL(r.url).searchParams.get('q')), ['unknown-vendor.example.org', 'example.org'], 'the exact host, then its parent');
  const deny = policyWith((t) => t.replace('unknown_counterparty: hold', 'unknown_counterparty: deny'));
  d = await guardFor(makeWorld({ domains: {} }), deny).decideToolCall(call({ domain: 'nobody.example.org' }));
  assert.equal(d.decision, 'deny'); assert.deepEqual(codes(d), ['NO_RECORD']);
  for (const host of ['http://127.0.0.1:8080/x', 'https://[::1]/', 'http://localhost:3000']) {
    const w2 = makeWorld({ domains: ACME });
    d = valid(await guardFor(w2).decideToolCall(call({ url: host })));
    assert.equal(d.decision, 'hold'); assert.deepEqual(codes(d), ['NO_RECORD']);
    assert.equal(w2.requests.length, 0, `${host}: nothing is sent`);
  }
});

test('no host in the typed arguments: hold EVIDENCE_MISSING needed target_host; a tool not covered is null', async () => {
  const w = makeWorld({ domains: ACME });
  const g = guardFor(w);
  let d = valid(await g.decideToolCall(call({ amount: 5, description: 'pay https://acme.com' })));
  assert.equal(d.decision, 'hold');
  assert.deepEqual(d.reasons, [{ code: 'EVIDENCE_MISSING', needed: 'target_host', detail: 'no typed argument names the host this action is about' }]);
  d = valid(await g.decide({ tool: 'stripe.create_payout', host: null }));
  assert.equal(d.reasons[0].needed, 'target_host');
  assert.equal(await g.decideToolCall(call({ url: 'https://acme.com' }, 'stripe.list_payouts')), null);
  assert.equal(w.requests.length, 0);
});

test('source unreachable: hold, never allow; deny when the policy or failMode says so; offline with no bundle is unreachable', async () => {
  let d = valid(await guardFor(makeWorld({ domains: ACME, down: true })).decideToolCall(call({ domain: 'acme.com' })));
  assert.equal(d.decision, 'hold'); assert.deepEqual(codes(d), ['SOURCE_UNREACHABLE']);
  const deny = policyWith((t) => t.replace('source_unreachable: hold', 'source_unreachable: deny'));
  d = await guardFor(makeWorld({ domains: ACME, down: true }), deny).decideToolCall(call({ domain: 'acme.com' }));
  assert.equal(d.decision, 'deny');
  d = await guardFor(makeWorld({ domains: ACME, down: true }), P, { failMode: 'deny' }).decideToolCall(call({ domain: 'acme.com' }));
  assert.equal(d.decision, 'deny');
  d = await guardFor(makeWorld({ domains: { 'acme.com': { projection: 'error' } } })).decideToolCall(call({ domain: 'acme.com' }));
  assert.equal(d.decision, 'hold'); assert.deepEqual(codes(d), ['SOURCE_UNREACHABLE']);
  const dir = mkdtempSync(join(tmpdir(), 'trooth-guard-'));
  const w = makeWorld({ domains: ACME });
  d = await guardFor(w, P, { offline: true, cache: { dir } }).decideToolCall(call({ domain: 'acme.com' }));
  assert.equal(d.decision, 'hold'); assert.deepEqual(codes(d), ['SOURCE_UNREACHABLE']); assert.equal(w.requests.length, 0);
});

test('bounded: a body over the size limit and a source slower than the deadline are unreachable, so hold', async () => {
  let d = await guardFor(makeWorld({ domains: ACME, hugeProjection: true })).decideToolCall(call({ domain: 'acme.com' }));
  assert.equal(d.decision, 'hold'); assert.match(d.reasons[0].detail, /byte limit/);
  const t0 = Date.now();
  d = await guardFor(makeWorld({ domains: ACME, slow: true }), P, { timeoutMs: 150 }).decideToolCall(call({ domain: 'acme.com' }));
  assert.equal(d.decision, 'hold'); assert.equal(d.reasons[0].code, 'SOURCE_UNREACHABLE'); assert.match(d.reasons[0].detail, /no answer within 150 ms/);
  assert.ok(Date.now() - t0 < 3000);
});

test('cache: a network read is saved; a fresh bundle is read with no request; offline reads it; a stale one is read again', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'trooth-guard-'));
  const w = makeWorld({ domains: ACME });
  let d = await guardFor(w, P, { cache: { dir } }).decideToolCall(call({ domain: 'acme.com' }));
  assert.equal(d.decision, 'allow');
  assert.deepEqual(readdirSync(dir), ['acme.com.trooth-guard.json']);
  const saved = JSON.parse(readFileSync(join(dir, 'acme.com.trooth-guard.json'), 'utf8'));
  assert.equal(saved.bundle, 'trooth.guard-bundle.v1');
  assert.equal(saved.witness.bundle, 'trooth.verification-bundle.v1', 'the witness part is the existing bundle format');
  assert.equal(saved.public_record.signed.statement.alg, 'Ed25519');
  const w2 = makeWorld({ domains: ACME, down: true });
  d = await guardFor(w2, P, { cache: { dir } }).decideToolCall(call({ url: 'https://acme.com/pay' }));
  assert.equal(d.decision, 'allow'); assert.equal(w2.requests.length, 0);
  d = await guardFor(w2, P, { cache: { dir } }).decideToolCall(call({ url: 'https://pay.acme.com' }));
  assert.equal(d.decision, 'hold', 'online, the exact host is asked first; when it cannot be asked, a cached parent does not stand in for it');
  assert.deepEqual(codes(d), ['SOURCE_UNREACHABLE']);
  const w3 = makeWorld({ domains: ACME, down: true });
  d = await guardFor(w3, P, { cache: { dir }, offline: true, now: () => NOW + 3 * DAY }).decideToolCall(call({ domain: 'acme.com' }));
  assert.equal(d.decision, 'allow', 'offline accepts an older bundle; the facts are still held to their own freshness');
  assert.equal(w3.requests.length, 0);
  d = await guardFor(w3, P, { cache: { dir }, offline: true, now: () => NOW + 9 * DAY }).decideToolCall(call({ domain: 'acme.com' }));
  assert.equal(d.decision, 'hold'); assert.ok(notPassed(d).some((r) => r.code === 'EVIDENCE_STALE' && r.rule_id === 'no-sanctions-match'));
  const w4 = makeWorld({ domains: ACME, down: true });
  d = await guardFor(w4, P, { cache: { dir, maxAgeSeconds: 60 }, now: () => NOW + 3600e3 }).decideToolCall(call({ domain: 'acme.com' }));
  assert.equal(d.decision, 'hold'); assert.deepEqual(codes(d), ['SOURCE_UNREACHABLE'], 'a cached bundle past maxAgeSeconds is not used online');
  assert.ok(w4.requests.length > 0);
});

test('claims: missing, stale by max_age_days, stale by the evidence class default, each claim from its section', async () => {
  const policy = parsePolicy(`policy: claims
version: 1
applies_to: { tools: ["pay"] }
rules:
  - id: reading
    require: { claim: trooth_reading }
  - id: s1
    require: { claim: "check:S1" }
  - id: s2
    require: { claim: "check:S2" }
  - id: sam
    require: { claim: no_sam_exclusion_name_match }
  - id: rdap
    require: { claim: domain_registration_record }
  - id: txt
    require: { claim: security_txt_published }
  - id: control
    require: { claim: domain_control_confirmed, max_age_days: 30 }
`);
  const w = makeWorld({ domains: ACME });
  let d = valid(await guardFor(w, policy).decideToolCall({ name: 'pay', arguments: { domain: 'acme.com' } }));
  const by = Object.fromEntries(d.reasons.map((r) => [r.rule_id, r]));
  for (const id of ['reading', 's1', 'sam', 'rdap', 'txt']) assert.equal(by[id].code, 'RULE_PASSED', id);
  assert.equal(by.s2.code, 'EVIDENCE_MISSING'); assert.equal(by.s2.needed, 'check:S2'); assert.match(by.s2.detail, /not as expected/);
  assert.equal(by.control.code, 'EVIDENCE_MISSING'); assert.match(by.control.detail, /holds no proof binding the domain to the company record or to its declaration key/);
  assert.equal(d.decision, 'hold');
  // Ten days later: the SAM.gov answer (procurement_exclusion, 7 days) is stale; the RDAP one (30) is not.
  d = await guardFor(makeWorld({ domains: ACME }), policy, { now: () => NOW + 10 * DAY }).decideToolCall({ name: 'pay', arguments: { domain: 'acme.com' } });
  const later = Object.fromEntries(d.reasons.map((r) => [r.rule_id, r]));
  assert.equal(later.sam.code, 'EVIDENCE_STALE');
  assert.equal(later.rdap.code, 'RULE_PASSED');
  // A sanctions name match, an expired security.txt and no entity.
  const w2 = makeWorld({ domains: { 'acme.com': { witness: {}, public: { sanctionsMatches: [{ name: 'Acme Test Inc.', programs: 'X' }], securityTxt: false, entity: false } } } });
  d = await guardFor(w2).decideToolCall(call({ domain: 'acme.com' }));
  const m = Object.fromEntries(d.reasons.map((r) => [r.rule_id, r]));
  assert.equal(m['legal-entity'].code, 'EVIDENCE_MISSING');
  assert.equal(m['no-sanctions-match'].code, 'EVIDENCE_MISSING');
  assert.match(m['no-sanctions-match'].detail, /a name match is not an identification/);
});

test('a record with no public record reading, or with no signed artifact, holds; withheld holds', async () => {
  let d = await guardFor(makeWorld({ domains: { 'acme.com': { witness: {} } } })).decideToolCall(call({ domain: 'acme.com' }));
  assert.equal(d.decision, 'hold');
  assert.ok(notPassed(d).every((r) => r.code === 'EVIDENCE_MISSING'));
  assert.match(notPassed(d)[0].detail, /no cached public record reading/);
  d = valid(await guardFor(makeWorld({ domains: { 'acme.com': {} } })).decideToolCall(call({ domain: 'acme.com' })));
  assert.equal(d.decision, 'deny', 'the absolute signature rule fails with no signed artifact');
  assert.deepEqual(notPassed(d).map((r) => r.code), ['EVIDENCE_MISSING', 'EVIDENCE_MISSING', 'ABSOLUTE_RULE_FAILED']);
  d = await guardFor(makeWorld({ domains: { 'acme.com': { projection: 'withheld' } } }), policyWith((t) => t.replace(/  - id: no-compromised-keys[\s\S]*?absolute: true\n/, ''))).decideToolCall(call({ domain: 'acme.com' }));
  assert.equal(d.decision, 'hold');
  d = await guardFor(makeWorld({ domains: { 'acme.com': { witness: {}, public: 'unsigned' } } })).decideToolCall(call({ domain: 'acme.com' }));
  assert.equal(d.decision, 'hold'); assert.match(notPassed(d)[0].detail, /not signed/);
});

test('versions this guard does not read hold SCHEMA_UNSUPPORTED', async () => {
  let d = valid(await guardFor(makeWorld({ domains: { 'acme.com': { projection: 'contract3', witness: {}, public: {} } } })).decideToolCall(call({ domain: 'acme.com' })));
  assert.equal(d.decision, 'hold'); assert.deepEqual(codes(d), ['SCHEMA_UNSUPPORTED']);
  d = await guardFor(makeWorld({ domains: { 'acme.com': { witness: { version: 'trooth.witness-statement.v4' }, public: {} } } })).decideToolCall(call({ domain: 'acme.com' }));
  assert.equal(d.decision, 'hold'); assert.deepEqual(codes(d), ['SCHEMA_UNSUPPORTED']); assert.match(d.reasons[0].detail, /v4/);
});

test('key status: retired before use is trusted; a rule accepting only active keys holds or, when absolute, denies', async () => {
  const retired = [keyEntry('test-guard-a', K.a, { status: 'retired', retired_at: iso(NOW - 3600e3) }), DEFAULT_KEYS()[1]];
  let d = await guardFor(makeWorld({ domains: ACME, keys: retired })).decideToolCall(call({ domain: 'acme.com' }));
  assert.equal(d.decision, 'allow');
  const activeOnly = policyWith((t) => t.replace('key_status: [active, retired_before_use]', 'key_status: [active]'));
  d = await guardFor(makeWorld({ domains: ACME, keys: retired }), activeOnly).decideToolCall(call({ domain: 'acme.com' }));
  assert.equal(d.decision, 'deny');
  assert.equal(notPassed(d)[0].code, 'ABSOLUTE_RULE_FAILED'); assert.match(notPassed(d)[0].detail, /^KEY_NOT_TRUSTED: the signing key is retired_before_use/);
  const holdOnly = parsePolicy(`policy: k\nversion: 1\napplies_to: { tools: ["pay"] }\nrules:\n  - id: keys\n    require: { signature: valid, key_status: [active] }\n`);
  d = await guardFor(makeWorld({ domains: ACME, keys: retired }), holdOnly).decideToolCall({ name: 'pay', arguments: { domain: 'acme.com' } });
  assert.equal(d.decision, 'hold'); assert.equal(notPassed(d)[0].code, 'KEY_NOT_TRUSTED'); assert.equal(notPassed(d)[0].rule_id, 'keys');
});

test('the same inputs always give the same decision', async () => {
  const a = await guardFor(makeWorld({ domains: ACME })).decideToolCall(call({ domain: 'acme.com' }));
  const b = await guardFor(makeWorld({ domains: ACME })).decideToolCall(call({ domain: 'acme.com' }));
  // The worlds use fresh keys, so statement hashes differ; the decision and the reasons do not.
  assert.equal(a.decision, b.decision);
  assert.deepEqual(a.reasons.map((r) => [r.code, r.rule_id]), b.reasons.map((r) => [r.code, r.rule_id]));
  const facts = { now: NOW, host: 'acme.com', target: 'ok', source: 'network', record: true, subject: 'trooth:domain:acme.com', schema_supported: true, signature: 'valid', key_status: 'active', subject_match: true, log: 'included', witnesses: 1, claims: {} };
  assert.deepEqual(decideFrom(facts, P), decideFrom(structuredClone(facts), P));
});

test('decide() takes a host, a URL or an email address; anything else has no record and is never looked up', async () => {
  const w = makeWorld({ domains: ACME });
  const g = guardFor(w);
  for (const h of ['ACME.com', 'https://pay.acme.com/x', 'billing@acme.com']) assert.equal((await g.decide({ tool: 'stripe.create_payout', host: h })).decision, 'allow', h);
  const before = w.requests.length;
  for (const h of ['10.0.0.1', 'not a host', 'ftp://acme.com/']) {
    const d = valid(await g.decide({ tool: 'stripe.create_payout', host: h }));
    assert.equal(d.decision, 'hold', h); assert.deepEqual(codes(d), ['NO_RECORD']);
  }
  assert.equal(w.requests.length, before);
});

test('one deadline for the whole decision: many requests each under timeoutMs still end in hold by deadlineMs', async () => {
  // Each answer comes just inside the per-request timeout, but the walk asks for every
  // parent domain in turn; before the fix nothing bounded the total, and a Claude Code
  // hook that times out lets the tool run.
  const slowAbsent = async (url, init = {}) => {
    await new Promise((resolve, reject) => { const t = setTimeout(resolve, 120); init.signal?.addEventListener('abort', () => { clearTimeout(t); reject(init.signal.reason); }); });
    return new Response(JSON.stringify({ found: false }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  const w = makeWorld({ domains: {} });
  const started = Date.now();
  let d = valid(await guardFor({ ...w, fetch: slowAbsent }, P, { timeoutMs: 1000, deadlineMs: 300 }).decideToolCall(call({ url: 'https://a.b.c.d.e.f.g.acme.com/' })));
  assert.equal(d.decision, 'hold');
  assert.equal(notPassed(d)[0].code, 'SOURCE_UNREACHABLE');
  assert.match(notPassed(d)[0].detail, /deadline/);
  assert.ok(Date.now() - started < 900, 'the decision came by the deadline');
  // A fetch that never answers and ignores its signal is cut off by the deadline too.
  d = valid(await guardFor({ ...w, fetch: () => new Promise(() => {}) }, P, { deadlineMs: 200 }).decideToolCall(call({ domain: 'acme.com' })));
  assert.equal(d.decision, 'hold');
  assert.equal(notPassed(d)[0].code, 'SOURCE_UNREACHABLE');
});

test('a host field the guard cannot read does not let another field decide the target', async () => {
  const w = makeWorld({ domains: ACME });
  for (const args of [{ domain: 'acme.com', url: 'evil.example/v1/payouts' }, { domain: 'acme.com', to: 'pay@evil.example, ap@acme.com' }, { domain: 'acme.com', url: 'ftp://evil.example/drop' }, { url: 'https://acme.com\\@evil.example/pay' }]) {
    const d = valid(await guardFor(w).decideToolCall(call(args)));
    assert.equal(d.decision, 'hold', JSON.stringify(args));
    assert.equal(notPassed(d)[0].needed, 'target_host');
  }
});

test('the walk does not reach a platform owner for a name a customer chose (cloudapp.azure.com)', async () => {
  const d = valid(await guardFor(makeWorld({ domains: { 'azure.com': { witness: {}, public: {} } } })).decideToolCall(call({ url: 'https://attacker.eastus.cloudapp.azure.com/pay' })));
  assert.equal(d.decision, 'hold');
  assert.equal(notPassed(d)[0].code, 'NO_RECORD');
});

test('log.required false: corrections that cannot be read leave no claim to stand on (hold), never allow', async () => {
  const relaxed = policyWith((t) => t.replace('log: { required: true, min_witnesses: 1 }', 'log: { required: false, min_witnesses: 0 }'));
  const dom = { 'acme.com': { witness: {}, public: {}, correctPublic: true, correctWitness: true } };
  let d = valid(await guardFor(makeWorld({ domains: dom, logDown: true }), relaxed).decideToolCall(call({ domain: 'acme.com' })));
  assert.equal(d.decision, 'hold', 'both statements are withdrawn and the log cannot say so');
  assert.ok(notPassed(d).every((r) => r.code === 'EVIDENCE_MISSING' && /correction/.test(r.detail)));
  d = valid(await guardFor(makeWorld({ domains: ACME }), relaxed).decideToolCall(call({ domain: 'acme.com' })));
  assert.equal(d.decision, 'allow', 'with the log readable and nothing corrected, the relaxed policy allows');
});

test('a withheld record with a signed public record still holds: every claim is disputed while the review is open', async () => {
  const d = valid(await guardFor(makeWorld({ cosignAt: NOW - 600000, domains: { 'acme.com': { projection: 'withheld', public: {} } } })).decideToolCall(call({ domain: 'acme.com' })));
  assert.equal(d.decision, 'hold');
  const disputed = d.reasons.filter((r) => r.code === 'EVIDENCE_DISPUTED');
  assert.ok(disputed.length >= 1, JSON.stringify(d.reasons));
  assert.ok(disputed.every((r) => /withheld while a report about it is reviewed/.test(r.detail)));
  assert.ok(!d.reasons.some((r) => r.code === 'RULE_PASSED' && /legal-entity|no-sanctions/.test(r.rule_id)));
});

/* ---- domain_control_confirmed, from the proofs in the signed public record (docs/GUARD.md section 4) ---- */

const CONTROL = parsePolicy(`policy: control
version: 1
applies_to: { tools: ["pay"] }
rules:
  - id: control
    require: { claim: domain_control_confirmed }
`);
const TP = 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k';
const proof = (method, status = 'confirmed', other = 'trooth:company:acme', extra = {}) => ({ id: `${method}:1`, binds: ['trooth:domain:acme.com', other], proof_method: method, status, detail: 'test', source: 'trooth record', observed_at: '2026-10-06T12:00:00.000Z', ...extra });
async function control(proofs, now) {
  const w = makeWorld({ domains: { 'acme.com': { witness: {}, public: { proofs } } } });
  const d = valid(await guardFor(w, CONTROL, now ? { now: () => now } : {}).decideToolCall({ name: 'pay', arguments: { domain: 'acme.com' } }));
  return { d, r: d.reasons.find((x) => x.rule_id === 'control') };
}

test('domain_control_confirmed: present with each qualifying method, to the company record or to the declaration key', async () => {
  for (const m of ['dns_txt', 'domain_email_code', 'identity_provider_sign_in', 'domain_signed_declaration']) {
    for (const other of ['trooth:company:acme', `trooth:key:acme.com#${TP}`]) {
      const { d, r } = await control([proof(m, 'confirmed', other)]);
      assert.equal(r.code, 'RULE_PASSED', `${m} ${other}`);
      assert.equal(d.decision, 'allow');
      const e = d.evidence.find((x) => x.fact_id.endsWith('#domain_control_confirmed'));
      assert.ok(e, 'the evidence names the claim');
      assert.match(e.statement_sha256, /^[0-9a-f]{64}$/);
      assert.equal(typeof e.log_index, 'number');
      assert.equal(e.observed_at, '2026-10-06T12:00:00.000Z');
      const days = other.startsWith('trooth:key:') ? 30 : 365;
      assert.equal(e.stale_after, iso(Date.parse(e.observed_at) + days * DAY), `${m} ${other}: the stale-after of its evidence class`);
    }
  }
});

test('domain_control_confirmed: absent when the proof is claimed, not_found or not_read', async () => {
  for (const st of ['claimed', 'not_found', 'not_read']) {
    const { d, r } = await control([proof('dns_txt', st)]);
    assert.equal(r.code, 'EVIDENCE_MISSING', st);
    assert.equal(r.needed, 'domain_control_confirmed');
    assert.match(r.detail, new RegExp(`dns_txt ${st}`));
    assert.equal(d.decision, 'hold');
  }
});

test('domain_control_confirmed: absent with a method that does not show domain control, or a binding to anything else', async () => {
  for (const m of ['repository_control', 'registry_record', 'regulator_filing', 'site_statement', 'registry_name_match', 'asked', 'none']) {
    const { r } = await control([proof(m)]);
    assert.equal(r.code, 'EVIDENCE_MISSING', m);
    assert.match(r.detail, /does not show domain control/);
  }
  for (const proofs of [
    [proof('dns_txt', 'confirmed', 'trooth:repo:github.com/acme')],
    [proof('domain_signed_declaration', 'confirmed', `trooth:key:other.com#${TP}`)],
    [proof('dns_txt', 'confirmed', 'trooth:key:trooth-master-2026-09')],
    [{ ...proof('dns_txt'), binds: ['trooth:domain:other.com', 'trooth:company:acme'] }],
    [{ ...proof('dns_txt'), binds: ['trooth:domain:acme.com'] }],
    [{ ...proof('dns_txt'), binds: ['trooth:domain:acme.com', 'trooth:company:acme', 'trooth:company:x'] }],
    [],
  ]) {
    const { r } = await control(proofs);
    assert.equal(r.code, 'EVIDENCE_MISSING', JSON.stringify(proofs));
  }
});

test('domain_control_confirmed: stale per evidence class (domain_declaration 30 days, trooth_claim_record 365)', async () => {
  const key = proof('domain_signed_declaration', 'confirmed', `trooth:key:acme.com#${TP}`);
  const claim = proof('identity_provider_sign_in', 'confirmed', 'trooth:company:acme');
  assert.equal((await control([key], NOW + 29 * DAY)).r.code, 'RULE_PASSED');
  assert.equal((await control([key], NOW + 31 * DAY)).r.code, 'EVIDENCE_STALE', 'a declaration read 31 days ago');
  assert.equal((await control([claim], NOW + 31 * DAY)).r.code, 'RULE_PASSED', 'the claim record keeps for a year');
  assert.equal((await control([claim, key], NOW + 31 * DAY)).r.code, 'RULE_PASSED', 'with both, the fresher one counts');
  const old = { ...claim, observed_at: iso(NOW - 366 * DAY) };
  assert.equal((await control([old])).r.code, 'EVIDENCE_STALE', 'a claim confirmed 366 days ago');
  const future = { ...key, observed_at: iso(NOW + 300 * DAY) };
  const { d } = await control([future], NOW + 31 * DAY);
  assert.equal(d.reasons[0].code, 'EVIDENCE_STALE', 'an observed_at after the reading counts from the reading, never later');
});

test('domain_control_confirmed: a rule max_age_days overrides the class; an unsigned record carries none', async () => {
  const strict = parsePolicy(`policy: control
version: 1
applies_to: { tools: ["pay"] }
rules:
  - id: control
    require: { claim: domain_control_confirmed, max_age_days: 7 }
`);
  const w = makeWorld({ domains: { 'acme.com': { witness: {}, public: { proofs: [proof('dns_txt')] } } } });
  const d = await guardFor(w, strict, { now: () => NOW + 10 * DAY }).decideToolCall({ name: 'pay', arguments: { domain: 'acme.com' } });
  assert.equal(d.reasons[0].code, 'EVIDENCE_STALE');
  const u = makeWorld({ domains: { 'acme.com': { witness: {}, public: 'unsigned' } } });
  const d2 = await guardFor(u, CONTROL).decideToolCall({ name: 'pay', arguments: { domain: 'acme.com' } });
  assert.equal(d2.reasons[0].code, 'EVIDENCE_MISSING');
  assert.match(d2.reasons[0].detail, /not signed/);
});
