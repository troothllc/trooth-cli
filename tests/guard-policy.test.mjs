// tests/guard-policy.test.mjs - the guard's policy (bin/lib/guard-policy.mjs,
// bin/lib/yaml-lite.mjs) and its interception rules: which tool calls are
// covered and which host a call is about. Network-free.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { parsePolicy, PolicyError, createGuard } from '../bin/lib/guard.mjs';
import { parseYaml, YamlError } from '../bin/lib/yaml-lite.mjs';
import { canonicalize } from '../bin/lib/jcs.mjs';
import { hostOfValue, targetHosts, toolCovered, hostCandidates, isNonRecordHost, checkHostPattern, hostMatches } from '../bin/lib/guard-policy.mjs';
import { loadSchemas, makeValidator } from './lib/mini-schema.mjs';
import { POLICY_YAML, VKEY, WITNESSES } from './lib/guard-fixtures.mjs';

const validate = makeValidator(loadSchemas(new URL('../schemas/', import.meta.url)));
const bad = (text, re, format) => assert.throws(() => parsePolicy(text, format), (e) => e instanceof PolicyError && re.test(e.message), `expected ${re}`);
const minimal = (extra = '') => `policy: p\nversion: 1\napplies_to: { tools: ["pay"] }\nrules:\n  - id: r1\n    require: { claim: trooth_reading }\n${extra}`;

test('the spec policy parses from YAML, with its defaults, and validates against the policy schema', () => {
  const p = parsePolicy(POLICY_YAML);
  assert.equal(p.id, 'vendor-payments');
  assert.equal(p.version, 3);
  assert.deepEqual(p.applies_to.tools, ['stripe.create_payout', 'mcp__bank__*']);
  assert.deepEqual(p.applies_to.http, [{ method: 'POST', host: '*.example-bank.com' }]);
  assert.deepEqual(p.log, { required: true, min_witnesses: 1 });
  assert.equal(p.rules.length, 3);
  assert.deepEqual(p.rules[2], { id: 'no-compromised-keys', require: { signature: 'valid', key_status: ['active', 'retired_before_use'] }, on_fail: 'deny', absolute: true });
  assert.equal(p.rules[0].on_fail, 'hold');
  assert.deepEqual(p.destinations.allowed, ['api.stripe.com']);
  assert.equal(p.unknown_counterparty, 'hold');
  assert.equal(p.source_unreachable, 'hold');
  assert.deepEqual(validate('guard-policy.v1.schema.json', p.document), []);
});

test('policy sha256 is the SHA-256 of the RFC 8785 JSON of the document; YAML and JSON forms agree', () => {
  const y = parsePolicy(POLICY_YAML);
  const j = parsePolicy(JSON.stringify(y.document, null, 2));
  assert.equal(j.sha256, y.sha256);
  assert.equal(y.sha256, createHash('sha256').update(canonicalize(y.document)).digest('hex'));
  const changed = parsePolicy(POLICY_YAML.replace('version: 3', 'version: 4'));
  assert.notEqual(changed.sha256, y.sha256);
  const reordered = parsePolicy(JSON.stringify({ version: 3, ...y.document }), 'json');
  assert.equal(reordered.sha256, y.sha256, 'key order does not change the hash');
});

test('defaults: log required with one witness, hold for no record and no source, the default host fields', () => {
  const p = parsePolicy(minimal());
  assert.deepEqual(p.log, { required: true, min_witnesses: 1 });
  assert.equal(p.unknown_counterparty, 'hold');
  assert.equal(p.source_unreachable, 'hold');
  assert.deepEqual(p.host_from, ['url', 'endpoint', 'host', 'domain', 'base_url', 'webhook_url', 'email', 'to']);
  assert.equal(p.rules[0].absolute, false);
});

test('refused: unknown keys, wrong types, duplicate rule ids, failMode or source_unreachable allow', () => {
  bad(minimal('extra: 1\n'), /unknown key "extra"/);
  bad(minimal().replace('version: 1', 'version: "1"'), /version must be a whole number/);
  bad(minimal().replace('version: 1', 'version: 0'), /version must be between 1/);
  bad(minimal('  - id: r1\n    require: { claim: trooth_reading }\n'), /rule ids must be unique/);
  bad(minimal('failMode: allow\n'), /failMode: allow is refused/);
  bad(minimal('fail_mode: hold\n'), /not a policy key/);
  bad(minimal('source_unreachable: allow\n'), /source_unreachable: allow is refused/);
  bad(minimal('unknown_counterparty: allow\n'), /unknown_counterparty: allow is refused/);
  bad(minimal('unknown_counterparty: maybe\n'), /must be one of hold, deny/);
  bad(minimal().replace('claim: trooth_reading', 'claim: legal_entty'), /not a claim the guard can read/);
  bad(minimal().replace('{ claim: trooth_reading }', '{ claim: trooth_reading, max_age: 3 }'), /unknown key "max_age"/);
  bad(minimal().replace('{ claim: trooth_reading }', '{ claim: trooth_reading, max_age_days: 0 }'), /max_age_days must be between 1/);
  bad(minimal().replace('{ claim: trooth_reading }', '{ signature: valid, key_status: [active, compromised] }'), /key_status "compromised" is not accepted/);
  bad(minimal().replace('{ claim: trooth_reading }', '{ signature: invalid }'), /signature must be "valid"/);
  bad(minimal('    on_fail: deny\n'), /on_fail: deny needs absolute: true/);
  bad(minimal('    absolute: true\n    on_fail: hold\n'), /contradicts itself/);
  bad(minimal('    absolute: "yes"\n'), /absolute must be true or false/);
  bad(minimal('log: { required: true, min_witnesses: 9 }\n'), /log.min_witnesses must be between 0 and 3/);
  bad(minimal('log: { required: "true" }\n'), /log.required must be true or false/);
  bad('policy: p\nversion: 1\napplies_to: { tools: [] }\nrules:\n  - id: r\n    require: { claim: trooth_reading }\n', /would cover nothing/);
  bad('policy: p\nversion: 1\napplies_to: { tools: ["x"] }\nrules: []\n', /at least one rule/);
  bad('policy: p\nversion: 1\napplies_to: { tools: ["x"] }\n', /at least one rule/);
  bad('- a\n- b\n', /mapping at the top level/);
  bad(minimal().replace('id: r1', 'id: "bad id"'), /rules\[0\]\.id/);
});

test('refused: wildcard abuse in host patterns and tool patterns', () => {
  bad(minimal('destinations: { allowed: ["*"] }\n'), /accepted only as the first label|at least two labels/);
  bad(minimal('destinations: { allowed: ["*.com"] }\n'), /at least two labels/);
  bad(minimal('destinations: { allowed: ["api.*.com"] }\n'), /only as the first label/);
  bad(minimal('destinations: { allowed: ["*.*.stripe.com"] }\n'), /only as the first label/);
  bad(minimal().replace('tools: ["pay"]', 'tools: ["pay"], http: [{ method: POST, host: "*" }]'), /applies_to.http\[0\].host/);
  bad(minimal().replace('tools: ["pay"]', 'tools: ["mcp__**"]'), /write one "\*"/);
  assert.equal(checkHostPattern('*.stripe.com', 'x'), '*.stripe.com');
  assert.equal(hostMatches('*.stripe.com', 'api.stripe.com'), true);
  assert.equal(hostMatches('*.stripe.com', 'stripe.com'), false);
  assert.equal(hostMatches('*.stripe.com', 'evilstripe.com'), false);
  assert.equal(hostMatches('api.stripe.com', 'API.Stripe.com.'), true);
});

test('JSON policies: duplicate keys, fractions and invalid JSON are refused', () => {
  bad('{"policy":"p","policy":"q","version":1}', /names the key "policy" twice/, 'json');
  bad('{"policy":"p","version":1.5,"applies_to":{"tools":["x"]},"rules":[{"id":"r","require":{"claim":"trooth_reading"}}]}', /not a whole number/, 'json');
  bad('{"policy":', /not valid JSON/, 'json');
  bad('x', /unknown policy format/, 'toml');
});

test('the YAML subset: comments, flow lists and maps, quoting, integers, booleans; and its refusals', () => {
  assert.deepEqual(parseYaml('a: 1 # one\nb: [x, "y z", \'it\'\'s\']\nc: { d: true, e: null }\nf:\n  - g: -3\n    h: "#not a comment"\n  - plain value\n'), { a: 1, b: ['x', 'y z', "it's"], c: { d: true, e: null }, f: [{ g: -3, h: '#not a comment' }, 'plain value'] });
  assert.deepEqual(parseYaml('---\nlist:\n- a\n- b\n'), { list: ['a', 'b'] });
  assert.deepEqual(parseYaml('url: https://x.example/a#frag'), { url: 'https://x.example/a#frag' });
  const refuse = (t, re) => assert.throws(() => parseYaml(t), (e) => e instanceof YamlError && re.test(e.message), `${JSON.stringify(t)} -> ${re}`);
  refuse('a: 1\na: 2', /appears twice/);
  refuse('a:\n\tb: 1', /tab/);
  refuse('a: &x 1', /anchors/);
  refuse('a: *x', /anchors/);
  refuse('a: !!str 1', /anchors|tags/);
  refuse('a: |\n  text', /block scalars/);
  refuse('a: 1.5', /only decimal integers/);
  refuse('a: 0x10', /only decimal integers/);
  refuse('a: yes', /means different things/);
  refuse('a: [1, 2', /not closed/);
  refuse('a: [1,]', /trailing comma/);
  refuse('a: {b: 1, b: 2}', /appears twice/);
  refuse('a: "open', /not closed/);
  refuse('a: 1\n---\nb: 2', /more than one document/);
  refuse('a:\n  b: 1\n c: 2', /indentation|cannot place/);
  refuse('__proto__: 1', /not accepted/);
  refuse('', /empty/);
  refuse('a: b: c', /quote it/);
});

/* ---------------------------------------------------------- interception ---- */

const P = parsePolicy(POLICY_YAML);

test('applies(): exact names and "*" globs; reads pass straight through', () => {
  const g = createGuard({ policy: P, fetch: async () => { throw new Error('no network in this test'); }, vkeys: [VKEY], witnesses: WITNESSES });
  assert.equal(g.applies('stripe.create_payout'), true);
  assert.equal(g.applies('mcp__bank__transfer'), true);
  assert.equal(g.applies('mcp__bank__'), true);
  assert.equal(g.applies('stripe.list_payouts'), false);
  assert.equal(g.applies('mcp__bankx__transfer'), false);
  assert.equal(g.applies('stripeXcreate_payout'), false, 'a dot in a pattern is a dot, not any character');
  assert.equal(g.applies('Read'), false);
  const all = parsePolicy(minimal().replace('tools: ["pay"]', 'tools: ["*"]'));
  assert.equal(toolCovered(all, 'anything at all'), true);
});

test('applies(): case and Unicode look-alikes of a covered name fail toward checking', () => {
  assert.equal(toolCovered(P, 'STRIPE.create_payout'), true, 'case-folded match is covered');
  assert.equal(toolCovered(P, 'ｓｔｒｉｐｅ.create_payout'), true, 'fullwidth letters fold to the covered name');
  assert.equal(toolCovered(P, 'strіpe.create_payout'), true, 'a Cyrillic i is not plain ASCII, so it is covered');
  assert.equal(toolCovered(P, 'mcp__bank__transfer\u200b'), true, 'a zero-width space does not escape coverage');
  assert.equal(toolCovered(P, 'stripe.list_payouts'), false);
});

test('hostOfValue: URLs, emails, bare hosts; never other schemes', () => {
  assert.equal(hostOfValue('https://API.Stripe.com:443/v1/payouts?x=1'), 'api.stripe.com');
  assert.equal(hostOfValue('http://pay.acme.com.'), 'pay.acme.com');
  assert.equal(hostOfValue('https://stripe.com@evil.example/'), 'evil.example', 'userinfo is not the host');
  assert.equal(hostOfValue('billing@Acme.com'), 'acme.com');
  assert.equal(hostOfValue('Acme Billing <billing@acme.com>'), 'acme.com');
  assert.equal(hostOfValue('mailto:ap@acme.com?subject=x'), 'acme.com');
  assert.equal(hostOfValue('pay.acme.com'), 'pay.acme.com');
  assert.equal(hostOfValue('pay.acme.com:8443'), 'pay.acme.com');
  assert.equal(hostOfValue('127.0.0.1'), '127.0.0.1');
  assert.equal(hostOfValue('localhost:3000'), 'localhost');
  assert.equal(hostOfValue('ftp://files.acme.com/'), null);
  assert.equal(hostOfValue('javascript:alert(1)'), null);
  assert.equal(hostOfValue('please pay acme.com today'), null, 'prose is not a host');
  assert.equal(hostOfValue('acme'), null);
  assert.equal(hostOfValue(42), null);
});

test('targetHosts: typed fields only (host_from), never prose fields; several hosts are ambiguous', () => {
  const t = (args) => targetHosts(P, { name: 'stripe.create_payout', arguments: args });
  assert.deepEqual(t({ url: 'https://pay.acme.com/x' }).hosts, ['pay.acme.com']);
  assert.deepEqual(t(JSON.stringify({ email: 'ap@acme.com' })).hosts, ['acme.com'], 'arguments given as a JSON string');
  assert.deepEqual(t({ description: 'send it to https://evil.example/', memo: 'evil.example' }).hosts, [], 'prose fields are never read');
  assert.deepEqual(t({ url: 'https://pay.acme.com', note: 'https://evil.example' }).hosts, ['pay.acme.com']);
  const amb = t({ url: 'https://pay.acme.com', email: 'x@evil.example' });
  assert.equal(amb.ambiguous, true);
  assert.deepEqual(t({ to: ['a@acme.com', 'b@acme.com'] }).hosts, ['acme.com']);
  assert.equal(t({ to: ['a@acme.com', 'b@other.com'] }).ambiguous, true);
  assert.deepEqual(t({ nested: { url: 'https://x.com' } }).hosts, [], 'nested fields only when host_from names the path');
  const dotted = parsePolicy(minimal('host_from: ["payee.website"]\n'));
  assert.deepEqual(targetHosts(dotted, { name: 'pay', arguments: { payee: { website: 'https://acme.com' } } }).hosts, ['acme.com']);
  const g = createGuard({ policy: P, fetch: async () => { throw new Error('none'); }, vkeys: [VKEY], witnesses: WITNESSES });
  assert.equal(g.targetHost({ name: 'x', arguments: { url: 'https://pay.acme.com', email: 'a@evil.example' } }), null);
  assert.equal(g.targetHost({ name: 'x', arguments: { domain: 'Acme.com' } }), 'acme.com');
});

test('YAML: a flow map key __proto__ is refused, so a hidden prototype cannot change the policy outside its hash', () => {
  // Before the fix, log: { __proto__: { required: false } } parsed: log.required read false
  // through the prototype while the policy hash equalled that of log: {} (which requires the log).
  const evil = POLICY_YAML.replace('log: { required: true, min_witnesses: 1 }', 'log: { __proto__: { required: false } }');
  assert.throws(() => parsePolicy(evil), (e) => e instanceof PolicyError && /__proto__ is not accepted/.test(e.message));
  for (const k of ['__proto__', 'constructor', 'prototype']) assert.throws(() => parseYaml(`a: { ${k}: { b: 1 } }`), /not accepted/);
  assert.throws(() => parseYaml('a: [{ "__proto__": { b: 1 } }]'), /not accepted/);
});

test('targetHosts: a host field whose value names a destination the guard cannot read makes the call ambiguous', () => {
  const t = (args) => targetHosts(P, { name: 'stripe.create_payout', arguments: args });
  // Each of these sent the action to evil.example while the guard checked (and allowed) acme.com.
  for (const args of [
    { domain: 'acme.com', url: 'evil.example/v1/payouts' },
    { domain: 'acme.com', webhook_url: 'evil.example:8443/hook' },
    { domain: 'acme.com', to: 'pay@evil.example, ap@acme.com' },
    { domain: 'acme.com', to: 'pay@evil.example,ap@acme.com' },
    { domain: 'acme.com', url: 'ftp://evil.example/drop' },
    { domain: 'acme.com', endpoint: 'wss://evil.example/socket' },
    { url: 'https://acme.com\\@evil.example/pay' },
    { domain: 'acme.com', url: 'https://acme.com\\@evil.example/pay' },
  ]) {
    const r = t(args);
    assert.ok(r.ambiguous || r.hosts.length === 0, JSON.stringify(args));
  }
  assert.equal(hostOfValue('https://acme.com\\@evil.example/pay'), null, 'Python urllib reads this as evil.example; WHATWG as acme.com');
  assert.deepEqual(t({ domain: 'acme.com', to: 'acct_123' }), { hosts: ['acme.com'], fields: ['domain'], ambiguous: false }, 'a value that cannot name a host (an account id) is not a destination');
  const g = createGuard({ policy: P, fetch: async () => { throw new Error('none'); }, vkeys: [VKEY], witnesses: WITNESSES });
  assert.equal(g.targetHost({ name: 'x', arguments: { domain: 'acme.com', url: 'evil.example/pay' } }), null);
});

test('host candidates walk to two labels and stop before shared domains; IPs and localhost have no record', () => {
  // A VM label under cloudapp.azure.com stood on azure.com's record before these were listed.
  assert.deepEqual(hostCandidates('attacker.eastus.cloudapp.azure.com'), ['attacker.eastus.cloudapp.azure.com', 'eastus.cloudapp.azure.com']);
  assert.deepEqual(hostCandidates('acct.z13.web.core.windows.net'), ['acct.z13.web.core.windows.net', 'z13.web.core.windows.net', 'web.core.windows.net']);
  assert.deepEqual(hostCandidates('tenant.sharepoint.com'), ['tenant.sharepoint.com']);
  assert.deepEqual(hostCandidates('a.b.acme.com'), ['a.b.acme.com', 'b.acme.com', 'acme.com']);
  assert.deepEqual(hostCandidates('acme.com'), ['acme.com']);
  assert.deepEqual(hostCandidates('evil.github.io'), ['evil.github.io']);
  assert.deepEqual(hostCandidates('shop.acme.co.uk'), ['shop.acme.co.uk', 'acme.co.uk']);
  assert.equal(isNonRecordHost('10.0.0.1'), true);
  assert.equal(isNonRecordHost('::1'), true);
  assert.equal(isNonRecordHost('localhost'), true);
  assert.equal(isNonRecordHost('api.localhost'), true);
  assert.equal(isNonRecordHost('acme.com'), false);
});

test('createGuard refuses failMode allow, a missing policy and a malformed key', () => {
  assert.throws(() => createGuard({ policy: P, failMode: 'allow', vkeys: [VKEY], witnesses: WITNESSES }), /failMode 'allow' is refused/);
  assert.throws(() => createGuard({ policy: P, failMode: 'open', vkeys: [VKEY], witnesses: WITNESSES }), /failMode must be/);
  assert.throws(() => createGuard({ policy: { rules: [] } }), PolicyError);
  assert.throws(() => createGuard({ policy: P, vkeys: ['not-a-key'] }), /verifier key/);
  assert.throws(() => createGuard({ policy: P, vkeys: [VKEY], witnesses: ['bad'] }), /verifier key|cosigner/);
  assert.throws(() => createGuard({ policy: P, vkeys: [VKEY], witnesses: WITNESSES, offline: true }), /needs|cache/);
  assert.ok(createGuard({ policy: P, failMode: 'deny', vkeys: [VKEY], witnesses: WITNESSES, fetch: async () => {} }));
});
