// tests/schemas.test.mjs - schemas/ describes what Trooth actually publishes.
// Every vector, every bundle, a real bundle saved from trooth.co and the CLI's
// own --json output validate; every property carries a description; the
// generated types (scripts/gen-types.mjs) are current; ids follow docs/IDS.md.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { loadSchemas, makeValidator } from './lib/mini-schema.mjs';
import { formatId, parseId, statementId } from '../bin/lib/ids.mjs';
import { canonicalize, isCanonical, CanonicalizationError } from '../bin/lib/jcs.mjs';

const schemaDir = new URL('../schemas/', import.meta.url);
const schemas = loadSchemas(schemaDir);
const validate = makeValidator(schemas);
const vec = JSON.parse(readFileSync(new URL('./vectors/vectors.json', import.meta.url), 'utf8'));
const bundles = JSON.parse(readFileSync(new URL('./vectors/bundles.json', import.meta.url), 'utf8')).bundles;
const liveUrl = new URL('./fixtures/bundles/trooth.co-2026-10-06.bundle.json', import.meta.url);
const live = JSON.parse(readFileSync(liveUrl, 'utf8'));
const ok = (file, v, label) => assert.deepEqual(validate(file, v), [], `${label} against ${file}`);

test('each schema names itself under https://trooth.co/schemas/ and states its dialect', () => {
  assert.equal(Object.keys(schemas).length, 10);
  for (const [f, s] of Object.entries(schemas)) {
    assert.equal(s.$id, `https://trooth.co/schemas/${f}`);
    assert.equal(s.$schema, 'https://json-schema.org/draft/2020-12/schema');
    assert.ok(s.title && s.description, `${f} has a title and a description`);
  }
});

test('every property in every schema carries a description', () => {
  const missing = [];
  const walk = (n, where) => {
    if (!n || typeof n !== 'object') return;
    if (n.properties) for (const [k, v] of Object.entries(n.properties)) { if (!v.description) missing.push(`${where}.${k}`); walk(v, `${where}.${k}`); }
    for (const [k, v] of Object.entries(n)) if (k !== 'properties' && typeof v === 'object') walk(v, `${where}/${k}`);
  };
  for (const [f, s] of Object.entries(schemas)) walk(s, f);
  assert.deepEqual(missing, []);
});

test('the v2 schema lists members in the exact order v2 signs them', () => {
  const live2 = JSON.parse(live.statement.payload);
  assert.deepEqual(Object.keys(live2), schemas['witness-payload.v2.schema.json'].required);
  assert.deepEqual(Object.keys(schemas['witness-payload.v2.schema.json'].properties), schemas['witness-payload.v2.schema.json'].required);
});

test('every well-formed vector validates: envelope, payload, key list, manifest', () => {
  let n = 0;
  for (const v of vec.vectors) {
    let p; try { p = JSON.parse(v.statement.payload); } catch { continue; }
    if (['malformed-signature', 'wrong-alg'].includes(v.name)) continue;
    ok('witness-statement.schema.json', v.statement, v.name);
    ok(`witness-payload.${p.statement.slice(-2)}.schema.json`, p, v.name);
    ok('key-list.schema.json', { keys: v.keys }, v.name);
    if (v.manifest) ok('evidence-manifest.schema.json', v.manifest, v.name);
    n++;
  }
  assert.ok(n >= 25, `${n} vectors validated`);
});

test('a reason-less v2 check, a v3 payload without subject_id and a manifest entry with both fields are refused', () => {
  const p2 = JSON.parse(vec.vectors.find((v) => v.name === 'valid-v2').statement.payload);
  p2.checks[1].reason = null; p2.checks[1].outcome = 'bogus';
  assert.notDeepEqual(validate('witness-payload.v2.schema.json', p2), []);
  const p3 = JSON.parse(vec.vectors.find((v) => v.name === 'valid-v3').statement.payload);
  delete p3.subject_id;
  assert.notDeepEqual(validate('witness-payload.v3.schema.json', p3), []);
  assert.notDeepEqual(validate('evidence-manifest.schema.json', [{ check_id: 'S1', source: 'https://a.example/', commitment: `sha256:${'0'.repeat(64)}` }]), []);
});

test('log receipts, correction payloads and logged bundles validate (docs/LOG.md)', () => {
  const log = JSON.parse(readFileSync(new URL('./vectors/log.json', import.meta.url), 'utf8'));
  let receipts = 0, corrections = 0;
  for (const c of log.cases) {
    if (['proof-tampered', 'checkpoint-forged', 'checkpoint-other-origin'].includes(c.name)) continue;
    if (c.log.receipt) { ok('log-receipt.schema.json', c.log.receipt, c.name); receipts++; }
    for (const x of c.log.corrections) { ok('witness-statement.schema.json', x.statement, c.name); if (!['correction-bad-signature'].includes(c.name)) ok('correction-payload.v1.schema.json', JSON.parse(x.statement.payload), c.name); corrections++; }
  }
  assert.ok(receipts >= 8 && corrections >= 4, `${receipts} receipts, ${corrections} corrections`);
  assert.notDeepEqual(validate('correction-payload.v1.schema.json', { ...JSON.parse(log.entries[3].statement.payload), effect: 'deleted' }), []);
  assert.notDeepEqual(validate('log-receipt.schema.json', { ...log.cases[0].log.receipt, root_hash: 'short' }), []);
});

test('bundles validate, including a real one saved from trooth.co', () => {
  for (const b of bundles) if (!b.expect.error) ok('verification-bundle.v1.schema.json', b.bundle, b.name);
  ok('verification-bundle.v1.schema.json', live, 'trooth.co bundle');
  ok('witness-payload.v2.schema.json', JSON.parse(live.statement.payload), 'trooth.co payload');
});

test('trooth verify --json output validates against verify-result', () => {
  const cli = new URL('../bin/trooth.mjs', import.meta.url).pathname;
  const r = spawnSync(process.execPath, [cli, 'verify', '--bundle', liveUrl.pathname, '--json'], { encoding: 'utf8', env: { ...process.env, TROOTH_WEB: 'http://127.0.0.1:9', TROOTH_API: 'http://127.0.0.1:9' } });
  assert.equal(r.status, 0, r.stderr);
  const doc = JSON.parse(r.stdout);
  ok('verify-result.schema.json', doc, 'cli output');
  assert.equal(doc.verdict, 'checked');
  assert.equal(doc.statement_id, statementId(live.statement.payload));
});

test('trooth verify --json with a log answer validates against verify-result', async () => {
  const { mkdtempSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const cli = new URL('../bin/trooth.mjs', import.meta.url).pathname;
  for (const name of ['bundle-superseded', 'bundle-v3-logged', 'bundle-forged-checkpoint']) {
    const b = bundles.find((x) => x.name === name);
    const f = join(mkdtempSync(join(tmpdir(), 'trooth-schema-')), 'b.json');
    writeFileSync(f, JSON.stringify(b.bundle));
    const logVkey = JSON.parse(readFileSync(new URL('./vectors/log.json', import.meta.url), 'utf8')).vkey;
    const r = spawnSync(process.execPath, [cli, 'verify', '--bundle', f, '--json', '--log-vkey', logVkey], { encoding: 'utf8', env: { ...process.env, TROOTH_WEB: 'http://127.0.0.1:9', TROOTH_API: 'http://127.0.0.1:9' } });
    const doc = JSON.parse(r.stdout);
    ok('verify-result.schema.json', doc, name);
    assert.equal(doc.verdict, b.expect.verdict, name);
    assert.ok(doc.log, `${name} carries the log part`);
  }
});

test('stable ids: format, parse and refuse', () => {
  assert.equal(formatId('domain', 'Trooth.CO.'), 'trooth:domain:trooth.co');
  assert.deepEqual(parseId('trooth:mapping:1.0.1'), { type: 'mapping', value: '1.0.1' });
  assert.equal(parseId('trooth:domain:not a domain'), null);
  assert.equal(parseId('trooth:planet:earth'), null);
  assert.throws(() => formatId('statement', 'abc'));
  assert.match(statementId('{}'), /^trooth:statement:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a$/);
});

test('RFC 8785 profile: sorting by UTF-16 code units, ECMAScript escaping, integers only', () => {
  assert.equal(canonicalize({ '\u{1F600}': 1, 'דּ': 2, b: [true, null, 'a\u0000\u001f"\\/'] }), '{"b":[true,null,"a\\u0000\\u001f\\"\\\\/"],"\u{1F600}":1,"דּ":2}');
  assert.equal(canonicalize(-0), '0');
  assert.throws(() => canonicalize(0.5), CanonicalizationError);
  assert.throws(() => canonicalize(2 ** 53), CanonicalizationError);
  assert.throws(() => canonicalize('\uD800'), CanonicalizationError);
  assert.equal(isCanonical('{"a":1,"b":2}'), true);
  assert.equal(isCanonical('{"b":2,"a":1}'), false);
  assert.equal(isCanonical('{"a":1e0}'), false);
});

test('generated types are current', () => {
  execFileSync(process.execPath, [new URL('../scripts/gen-types.mjs', import.meta.url).pathname, '--check'], { stdio: 'pipe' });
});
